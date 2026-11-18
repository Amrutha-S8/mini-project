"""Attach the append-only triggers to model tables.

``Base.metadata.create_all`` then produces the same triggers as migration
0002 and the reference DDL. The statements come from
``app/database/append_only.py``, the canonical source.
"""

from __future__ import annotations

from sqlalchemy import DDL, Table, event

from app.database.append_only import trigger_statements


def attach_append_only_guards(table: Table) -> None:
    for statement in trigger_statements(table.name):
        event.listen(table, "after_create", DDL(statement))
