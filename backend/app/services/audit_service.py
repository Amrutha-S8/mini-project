"""Audit-log writer.

Every security-relevant action records actor, IP, action, entity, outcome and
before/after values (SR-AUDIT-03, SR-AUDIT-04). The table is append-only: this
module offers no update or delete operation, and none may be added
(SR-AUDIT-06, SR-AUDIT-07).
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.models.audit_log import (
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    AuditLog,
)

SYSTEM_ACTOR = "system"


def _dump(value: dict[str, Any] | None) -> str | None:
    """Serialise a before/after payload, never raising on odd types."""
    if value is None:
        return None
    return json.dumps(value, default=str, sort_keys=True)


def record(
    db: Session,
    *,
    action: str,
    entity_type: str,
    entity_id: str | int | None = None,
    actor_user_id: int | None = None,
    actor_label: str | None = None,
    actor_ip: str | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    outcome: str = OUTCOME_SUCCESS,
    correlation_id: str | None = None,
) -> AuditLog:
    """Append one audit entry.

    The caller owns the transaction; this only adds and flushes so the entry
    shares the fate of the action it describes.
    """
    if outcome not in (OUTCOME_SUCCESS, OUTCOME_FAILURE):
        raise ValueError(f"invalid audit outcome: {outcome!r}")

    entry = AuditLog(
        action=action,
        entity_type=entity_type,
        entity_id=None if entity_id is None else str(entity_id),
        actor_user_id=actor_user_id,
        actor_label=actor_label or (SYSTEM_ACTOR if actor_user_id is None else "user"),
        actor_ip=actor_ip,
        before_value=_dump(before),
        after_value=_dump(after),
        outcome=outcome,
        correlation_id=correlation_id,
    )
    db.add(entry)
    db.flush()
    return entry
