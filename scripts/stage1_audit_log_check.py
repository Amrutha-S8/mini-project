"""Stage 1 check: is audit_log append-only in a database built by Alembic?

Usage (from the backend folder, after ``python -m alembic upgrade head``):

    python ..\\scripts\\stage1_audit_log_check.py data\\stage1_test.db

Safe by design:

* The database you name is never written. It is copied to a temporary
  folder, and every test write happens on the copy, which is then deleted.
* No secrets are read or printed.
* Standard library only, so it works before or without the project's
  packages.

Prints one PASS or FAIL line per check and exits with 1 if anything failed.
"""

from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

HEAD_REVISION = "0004_audit_log_append_only"
EXPECTED_TRIGGERS = {"trg_audit_log_guard_update", "trg_audit_log_no_delete"}

Check = tuple[str, bool, str]


def _refused(conn: sqlite3.Connection, sql: str) -> tuple[bool, str]:
    try:
        conn.execute(sql)
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        return True, str(exc)
    return False, "the statement succeeded"


def run_checks(db_copy: Path) -> list[Check]:
    """All checks, run against a disposable copy of the database."""
    results: list[Check] = []
    conn = sqlite3.connect(db_copy)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        version = None
        if "alembic_version" in tables:
            row = conn.execute("SELECT version_num FROM alembic_version").fetchone()
            version = row[0] if row else None
        results.append(
            (
                "migrated to head (0004)",
                version == HEAD_REVISION,
                f"alembic_version = {version!r}",
            )
        )
        results.append(("audit_log table exists", "audit_log" in tables, ""))
        if "audit_log" not in tables or "users" not in tables:
            return results

        triggers = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master"
                " WHERE type='trigger' AND tbl_name='audit_log'"
            )
        }
        missing = EXPECTED_TRIGGERS - triggers
        results.append(
            (
                "audit_log triggers installed",
                not missing,
                "missing: " + ", ".join(sorted(missing)) if missing else "",
            )
        )

        uid = conn.execute(
            "INSERT INTO users (email, password_hash, full_name, role)"
            " VALUES ('stage1-check@example.invalid', 'not-a-real-hash',"
            " 'Stage 1 check', 'admin')"
        ).lastrowid
        entry = conn.execute(
            "INSERT INTO audit_log (actor_user_id, actor_label, action, entity_type)"
            " VALUES (?, 'stage1-check', 'stage1.check', 'test')",
            (uid,),
        ).lastrowid
        conn.commit()
        results.append(("new audit entries can be written", entry is not None, ""))

        ok, why = _refused(
            conn,
            f"UPDATE audit_log SET action = 'edited' WHERE id = {int(entry or 0)}",  # noqa: S608
        )
        results.append(("UPDATE of an audit entry is refused", ok, why))
        ok, why = _refused(conn, f"DELETE FROM audit_log WHERE id = {int(entry or 0)}")  # noqa: S608
        results.append(("DELETE of an audit entry is refused", ok, why))

        action = conn.execute(
            "SELECT action FROM audit_log WHERE id = ?", (entry,)
        ).fetchone()
        results.append(
            ("entry unchanged after refused writes", action == ("stage1.check",), "")
        )

        conn.execute("DELETE FROM users WHERE id = ?", (uid,))
        conn.commit()
        row = conn.execute(
            "SELECT actor_user_id, actor_label FROM audit_log WHERE id = ?", (entry,)
        ).fetchone()
        results.append(
            (
                "deleting a user keeps the entry (actor set to NULL)",
                row == (None, "stage1-check"),
                f"row = {row!r}",
            )
        )
    finally:
        conn.close()
    return results


def check_database(path: Path, report: Callable[[str], None] = print) -> bool:
    if not path.is_file():
        report(f"FAIL  database file not found: {path}")
        return False
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "copy.db"
        shutil.copyfile(path, copy)
        for suffix in ("-wal", "-shm"):
            side = path.with_name(path.name + suffix)
            if side.exists():
                shutil.copyfile(side, copy.with_name(copy.name + suffix))
        results = run_checks(copy)
    for name, ok, detail in results:
        report(
            f"{'PASS' if ok else 'FAIL'}  {name}"
            + (f"  ({detail})" if detail and not ok else "")
        )
    report("The original database was not modified.")
    return all(ok for _, ok, _ in results)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    return 0 if check_database(Path(argv[1])) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
