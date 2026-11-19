"""Normalised schema descriptions for parity checks (stdlib only).

Three representations of the schema exist: the SQLAlchemy models (canonical),
the Alembic migrations (0001, 0002), and ``schema_reference.sql``. This module
reduces each to the same comparable shape:

    {table: {"columns": {name: (affinity, notnull, default)},
             "indexes": {name: (columns, unique)},
             "foreign_keys": {(column, ref_table, ref_column, on_delete)},
             "checks": {name: expression},
             "triggers": {name: normalised CREATE TRIGGER text}}}

Declared type names are compared by SQLite type affinity, because SQLite stores
by affinity: VARCHAR(320) and TEXT behave identically, DATETIME does not.

Migrations are read statically. Triggers are recognised either as
``op.execute("CREATE TRIGGER ...")`` with a literal, or as a loop
``for statement in _TRIGGERS: op.execute(statement)`` over a module-level
tuple of literals.
"""

from __future__ import annotations

import ast
import re
import sqlite3
from pathlib import Path
from typing import Any

Column = tuple[str, bool, str | None]
Schema = dict[str, dict[str, Any]]

IGNORED_TABLES = {"alembic_version", "sqlite_sequence"}


# --- normalisation helpers ---------------------------------------------------


def affinity(declared_type: str) -> str:
    """SQLite type affinity, per https://sqlite.org/datatype3.html section 3.1."""
    t = declared_type.upper()
    if "INT" in t:
        return "INTEGER"
    if any(k in t for k in ("CHAR", "CLOB", "TEXT")):
        return "TEXT"
    if "BLOB" in t or not t:
        return "BLOB"
    if any(k in t for k in ("REAL", "FLOA", "DOUB")):
        return "REAL"
    return "NUMERIC"


def normalise_default(raw: str | None) -> str | None:
    """'viewer' / viewer / (CURRENT_TIMESTAMP) / '1' -> comparable text."""
    if raw is None:
        return None
    value = raw.strip()
    while value.startswith("(") and value.endswith(")"):
        value = value[1:-1].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    if value.upper() == "CURRENT_TIMESTAMP":
        return "CURRENT_TIMESTAMP"
    return value


def normalise_expression(expr: str) -> str:
    return re.sub(r"\s+", " ", expr).strip()


_TRIGGER_HEAD = re.compile(
    r"^CREATE\s+TRIGGER\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\b", re.IGNORECASE
)
_TRIGGER_TABLE = re.compile(r"\bON\s+(\w+)\b", re.IGNORECASE)


def normalise_trigger(sql: str) -> tuple[str, str, str]:
    """(name, table, text) with IF NOT EXISTS, whitespace and ';' removed.

    SQLite stores a trigger without ``IF NOT EXISTS``, so the reference copy
    and the migration copy compare equal only after this normalisation.
    """
    text = normalise_expression(sql).rstrip(";").strip()
    head = _TRIGGER_HEAD.match(text)
    table = _TRIGGER_TABLE.search(text)
    if head is None or table is None:
        raise ValueError(f"not a CREATE TRIGGER statement: {sql[:60]!r}")
    name = head.group(1)
    text = _TRIGGER_HEAD.sub(f"CREATE TRIGGER {name}", text, count=1)
    return name, table.group(1), text


def _balanced(text: str, start: int) -> str:
    """Contents of the parenthesised group opening at ``text[start]``."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i]
    raise ValueError("unbalanced parentheses in CHECK constraint")


def checks_from_ddl(ddl: str) -> dict[str, str]:
    """Named CHECK constraints from a CREATE TABLE statement."""
    found: dict[str, str] = {}
    for match in re.finditer(r"CONSTRAINT\s+(\w+)\s+CHECK\s*\(", ddl, re.IGNORECASE):
        found[match.group(1)] = normalise_expression(_balanced(ddl, match.end() - 1))
    return found


# --- describe a live SQLite database ----------------------------------------


def describe_sqlite(conn: sqlite3.Connection) -> Schema:
    schema: Schema = {}
    tables = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        if row[0] not in IGNORED_TABLES and not row[0].startswith("sqlite_")
    ]
    for table in tables:
        columns: dict[str, Column] = {}
        for _cid, name, decl, notnull, default, pk in conn.execute(
            f"PRAGMA table_info({table})"
        ):
            # A single-column INTEGER PRIMARY KEY is a rowid alias and can
            # never hold NULL, whether or not NOT NULL was written.
            columns[name] = (
                affinity(decl),
                bool(notnull) or bool(pk),
                normalise_default(default),
            )

        indexes: dict[str, tuple[tuple[str, ...], bool]] = {}
        for _seq, name, unique, origin, _partial in conn.execute(
            f"PRAGMA index_list({table})"
        ):
            if origin == "pk":
                continue
            cols = tuple(r[2] for r in conn.execute(f"PRAGMA index_info({name})"))
            # Indexes created by a UNIQUE constraint have generated names, so
            # they are keyed by their columns to keep the comparison stable.
            key = name if origin == "c" else f"<unique constraint {','.join(cols)}>"
            indexes[key] = (cols, bool(unique))

        foreign_keys = {
            (row[3], row[2], row[4], row[6].upper())
            for row in conn.execute(f"PRAGMA foreign_key_list({table})")
        }

        ddl = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()[0]

        triggers: dict[str, str] = {}
        for (trigger_sql,) in conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?",
            (table,),
        ):
            name, _table, text = normalise_trigger(trigger_sql)
            triggers[name] = text

        schema[table] = {
            "columns": columns,
            "indexes": indexes,
            "foreign_keys": foreign_keys,
            "checks": checks_from_ddl(ddl),
            "triggers": triggers,
        }
    return schema


# --- describe an Alembic migration file statically ---------------------------

_SA_AFFINITY = {
    "Integer": "INTEGER",
    "String": "TEXT",
    "Text": "TEXT",
    "DateTime": "NUMERIC",
    "Float": "REAL",
}


def _name(node: ast.AST) -> str:
    """Accept "x" or op.f("x")."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "f"
        and node.args
    ):
        return _name(node.args[0])
    raise ValueError(f"unsupported name expression: {ast.dump(node)}")


def _kw(call: ast.Call, key: str) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == key:
            return keyword.value
    return None


def _attr(call: ast.Call) -> str:
    return call.func.attr if isinstance(call.func, ast.Attribute) else ""


def _str_list(node: ast.AST) -> list[str]:
    assert isinstance(node, ast.List)
    return [_name(elt) for elt in node.elts]


def _default(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return normalise_default(str(node.value))
    if isinstance(node, ast.Call) and _attr(node) == "current_timestamp":
        return "CURRENT_TIMESTAMP"
    raise ValueError(f"unsupported server_default: {ast.dump(node)}")


def _module_constant(tree: ast.Module, name: str) -> Any:
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ):
            return ast.literal_eval(node.value)
    raise ValueError(f"module constant {name} not found")


def _trigger_sources(tree: ast.Module, upgrade: ast.FunctionDef) -> list[str]:
    """Literal CREATE TRIGGER statements executed by ``upgrade()``."""
    found: list[str] = []
    for node in ast.walk(upgrade):
        if (
            isinstance(node, ast.Call)
            and _attr(node) == "execute"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            found.append(node.args[0].value)
        elif (
            isinstance(node, ast.For)
            and isinstance(node.iter, ast.Name)
            and node.iter.id == "_TRIGGERS"
        ):
            found.extend(_module_constant(tree, "_TRIGGERS"))
    return [s for s in found if s.lstrip().upper().startswith("CREATE TRIGGER")]


def describe_migration(path: Path) -> Schema:
    """Statically reduce the ``upgrade()`` of a migration to the shared shape."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    upgrade = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "upgrade"
    )
    schema: Schema = {}
    for node in ast.walk(upgrade):
        if not isinstance(node, ast.Call):
            continue
        op_name = _attr(node)
        if op_name == "create_table":
            table = _name(node.args[0])
            entry: dict[str, Any] = {
                "columns": {},
                "indexes": {},
                "foreign_keys": set(),
                "checks": {},
                "triggers": {},
            }
            primary_keys: set[str] = set()
            for item in node.args[1:]:
                if not isinstance(item, ast.Call):
                    continue
                kind = _attr(item)
                if kind == "Column":
                    col = _name(item.args[0])
                    type_call = item.args[1]
                    assert isinstance(type_call, ast.Call)
                    nullable = _kw(item, "nullable")
                    notnull = isinstance(nullable, ast.Constant) and (
                        nullable.value is False
                    )
                    entry["columns"][col] = (
                        _SA_AFFINITY[_attr(type_call)],
                        notnull,
                        _default(_kw(item, "server_default")),
                    )
                elif kind == "CheckConstraint":
                    expr = item.args[0]
                    assert isinstance(expr, ast.Constant)
                    name_node = _kw(item, "name")
                    if name_node is None:
                        raise ValueError(f"unnamed CHECK constraint on {table}")
                    entry["checks"][_name(name_node)] = normalise_expression(
                        str(expr.value)
                    )
                elif kind == "ForeignKeyConstraint":
                    (local,) = _str_list(item.args[0])
                    (remote,) = _str_list(item.args[1])
                    ref_table, ref_col = remote.split(".")
                    on_delete = _kw(item, "ondelete")
                    entry["foreign_keys"].add(
                        (
                            local,
                            ref_table,
                            ref_col,
                            _name(on_delete).upper() if on_delete else "NO ACTION",
                        )
                    )
                elif kind == "PrimaryKeyConstraint":
                    primary_keys.update(_name(a) for a in item.args)
                elif kind == "UniqueConstraint":
                    cols = tuple(_name(a) for a in item.args)
                    entry["indexes"][f"<unique constraint {','.join(cols)}>"] = (
                        cols,
                        True,
                    )
            for col in primary_keys:
                aff, _notnull, default = entry["columns"][col]
                entry["columns"][col] = (aff, True, default)
            schema[table] = entry
        elif op_name == "create_index":
            name = _name(node.args[0])
            table = _name(node.args[1])
            cols = tuple(_str_list(node.args[2]))
            unique_node = _kw(node, "unique")
            unique = isinstance(unique_node, ast.Constant) and bool(unique_node.value)
            schema[table]["indexes"][name] = (cols, unique)
        elif op_name == "add_column":
            # ALTER TABLE ... ADD COLUMN on a table from an earlier migration.
            table = _name(node.args[0])
            column = node.args[1]
            assert isinstance(column, ast.Call) and _attr(column) == "Column"
            type_call = column.args[1]
            assert isinstance(type_call, ast.Call)
            nullable = _kw(column, "nullable")
            notnull = isinstance(nullable, ast.Constant) and nullable.value is False
            if _kw(column, "server_default") is None and notnull:
                raise ValueError(f"{table}: NOT NULL ADD COLUMN needs a default")
            if len(column.args) > 2:
                raise ValueError(f"{table}: add_column with inline constraints")
            schema.setdefault(LATER_COLUMNS, {}).setdefault(table, {})[
                _name(column.args[0])
            ] = (
                _SA_AFFINITY[_attr(type_call)],
                notnull,
                _default(_kw(column, "server_default")),
            )
    for statement in _trigger_sources(tree, upgrade):
        name, table, text = normalise_trigger(statement)
        if table in schema:
            schema[table]["triggers"][name] = text
        else:
            # A trigger on a table created by an earlier migration.
            schema.setdefault(LATER_TRIGGERS, {}).setdefault(table, {})[name] = text
    return schema


# --- describe SQLAlchemy model modules statically -----------------------------
#
# The models are canonical but cannot be imported without SQLAlchemy. This
# reads the declarative classes with ``ast`` and applies the naming convention
# from app/database/base.py, so model drift is caught today. It understands
# only the constructs the project uses; anything else raises.

_MODEL_AFFINITY = {**_SA_AFFINITY, "UtcDateTime": "NUMERIC"}


def _type_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id
    return None


def _module_strings(tree: ast.Module) -> dict[str, str]:
    """Module-level ``NAME = "literal"`` constants (used as server defaults)."""
    found: dict[str, str] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            found[node.targets[0].id] = node.value.value
    return found


def _model_column(
    table: str,
    attr: str,
    call: ast.Call,
    entry: dict[str, Any],
    constants: dict[str, str],
) -> None:
    args = list(call.args)
    column = attr
    first = args[0] if args else None
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        column = first.value
        args.pop(0)
    if not args:
        raise ValueError(f"{table}.{column}: mapped_column without a type")
    type_node = args[0]
    kind = _type_name(type_node)
    if kind == "ForeignKey":
        assert isinstance(type_node, ast.Call)
        ref_table, ref_col = _name(type_node.args[0]).split(".")
        on_delete = _kw(type_node, "ondelete")
        entry["foreign_keys"].add(
            (
                column,
                ref_table,
                ref_col,
                _name(on_delete).upper() if on_delete else "NO ACTION",
            )
        )
        affinity_name = "INTEGER"
    elif kind in _MODEL_AFFINITY:
        affinity_name = _MODEL_AFFINITY[kind]
    else:
        raise ValueError(f"{table}.{column}: unsupported column type {kind!r}")

    def flag(key: str) -> bool:
        node = _kw(call, key)
        return isinstance(node, ast.Constant) and node.value is True

    nullable = _kw(call, "nullable")
    notnull = flag("primary_key") or (
        isinstance(nullable, ast.Constant) and nullable.value is False
    )
    server_default = _kw(call, "server_default")
    if isinstance(server_default, ast.Name):
        if server_default.id not in constants:
            raise ValueError(f"{table}.{column}: unknown constant {server_default.id}")
        server_default = ast.Constant(constants[server_default.id])
    entry["columns"][column] = (
        affinity_name,
        notnull,
        _default(server_default),
    )
    if flag("index"):
        entry["indexes"][f"ix_{table}_{column}"] = ((column,), flag("unique"))
    elif flag("unique"):
        entry["indexes"][f"<unique constraint {column}>"] = ((column,), True)


def _model_table_args(table: str, node: ast.AST, entry: dict[str, Any]) -> None:
    assert isinstance(node, ast.Tuple), f"{table}: __table_args__ must be a tuple"
    for item in node.elts:
        assert isinstance(item, ast.Call)
        kind = _type_name(item)
        if kind == "CheckConstraint":
            expr = item.args[0]
            assert isinstance(expr, ast.Constant)
            name_node = _kw(item, "name")
            if name_node is None:
                raise ValueError(f"unnamed CHECK constraint on {table}")
            entry["checks"][f"ck_{table}_{_name(name_node)}"] = normalise_expression(
                str(expr.value)
            )
        elif kind == "Index":
            name = _name(item.args[0])
            cols = tuple(_name(a) for a in item.args[1:])
            unique_node = _kw(item, "unique")
            unique = isinstance(unique_node, ast.Constant) and bool(unique_node.value)
            entry["indexes"][name] = (cols, unique)
        else:
            raise ValueError(f"{table}: unsupported __table_args__ item {kind!r}")


def describe_models(paths: list[Path]) -> Schema:
    """Statically reduce SQLAlchemy model modules to the shared shape."""
    from app.database.append_only import trigger_statements

    schema: Schema = {}
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        constants = _module_strings(tree)
        tables_by_class: dict[str, str] = {}
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            table: str | None = None
            for stmt in cls.body:
                if (
                    isinstance(stmt, ast.Assign)
                    and isinstance(stmt.targets[0], ast.Name)
                    and stmt.targets[0].id == "__tablename__"
                ):
                    table = _name(stmt.value)
            if table is None:
                continue
            tables_by_class[cls.name] = table
            entry: dict[str, Any] = {
                "columns": {},
                "indexes": {},
                "foreign_keys": set(),
                "checks": {},
                "triggers": {},
            }
            for stmt in cls.body:
                if (
                    isinstance(stmt, ast.Assign)
                    and isinstance(stmt.targets[0], ast.Name)
                    and stmt.targets[0].id == "__table_args__"
                ):
                    _model_table_args(table, stmt.value, entry)
                elif (
                    isinstance(stmt, ast.AnnAssign)
                    and isinstance(stmt.target, ast.Name)
                    and isinstance(stmt.value, ast.Call)
                    and _type_name(stmt.value) == "mapped_column"
                ):
                    _model_column(table, stmt.target.id, stmt.value, entry, constants)
            schema[table] = entry
        # attach_append_only_guards(SomeModel.__table__) at module level
        for stmt in tree.body:
            call = stmt.value if isinstance(stmt, ast.Expr) else None
            if (
                isinstance(call, ast.Call)
                and _type_name(call) == "attach_append_only_guards"
                and isinstance(call.args[0], ast.Attribute)
                and isinstance(call.args[0].value, ast.Name)
            ):
                table = tables_by_class[call.args[0].value.id]
                for statement in trigger_statements(table):
                    name, _t, text = normalise_trigger(statement)
                    schema[table]["triggers"][name] = text
    return schema


#: Key under which describe_migration reports triggers it adds to tables that
#: an earlier migration created.
LATER_TRIGGERS = "<triggers on existing tables>"
#: Key under which describe_migration reports ``op.add_column`` calls.
LATER_COLUMNS = "<columns added to existing tables>"


def describe_migrations(paths: list[Path]) -> Schema:
    """The schema produced by applying the migrations in order.

    Supports create_table, create_index, add_column and CREATE TRIGGER.
    """
    combined: Schema = {}
    for path in paths:
        described = describe_migration(path)
        later = described.pop(LATER_TRIGGERS, {})
        added = described.pop(LATER_COLUMNS, {})
        for table, columns in added.items():
            if table not in combined:
                raise ValueError(f"{path.name} adds a column to unknown {table}")
            for name, column in columns.items():
                if name in combined[table]["columns"]:
                    raise ValueError(f"{path.name} re-adds {table}.{name}")
                combined[table]["columns"][name] = column
        for table, entry in described.items():
            if table in combined:
                raise ValueError(f"{path.name} re-creates table {table}")
            combined[table] = entry
        for table, triggers in later.items():
            if table not in combined:
                raise ValueError(f"{path.name} adds a trigger to unknown {table}")
            combined[table]["triggers"].update(triggers)
    return combined


# --- comparison ---------------------------------------------------------------


def diff_schemas(left: Schema, right: Schema, labels: tuple[str, str]) -> list[str]:
    """Human-readable differences. Empty list means equivalent."""
    a_label, b_label = labels
    problems: list[str] = []
    for table in sorted(set(left) | set(right)):
        if table not in left:
            problems.append(f"{table}: only in {b_label}")
            continue
        if table not in right:
            problems.append(f"{table}: only in {a_label}")
            continue
        for part in ("columns", "indexes", "checks", "triggers"):
            a, b = left[table][part], right[table][part]
            for key in sorted(set(a) | set(b)):
                if key not in a:
                    problems.append(f"{table}.{part}: {key!r} only in {b_label}")
                elif key not in b:
                    problems.append(f"{table}.{part}: {key!r} only in {a_label}")
                elif a[key] != b[key]:
                    problems.append(
                        f"{table}.{part}: {key!r} {a_label}={a[key]!r} "
                        f"{b_label}={b[key]!r}"
                    )
        fa, fb = left[table]["foreign_keys"], right[table]["foreign_keys"]
        for fk in sorted(fa - fb):
            problems.append(f"{table}.foreign_keys: {fk} only in {a_label}")
        for fk in sorted(fb - fa):
            problems.append(f"{table}.foreign_keys: {fk} only in {b_label}")
    return problems
