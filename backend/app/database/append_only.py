"""Database-level append-only guards for event and evidence tables (stdlib only).

SR-AUDIT-06/07 require that security history cannot be edited or deleted,
including by an admin. The application exposes no update or delete path; these
SQLite triggers enforce the same rule inside the database, so a bug, a raw SQL
console or a future module cannot quietly rewrite history either.

Every column of a guarded table is classified once here:

* ``immutable``  never changes after insert.
* ``clearable``  may only be set to NULL (privacy purge). Never to a new value.
* ``set_once``   may go from NULL to a value once (purge stamp, incident link).
* ``mutable``    may change (operator review, workflow progress).

``frozen_when_finished`` makes a workflow row read-only once it leaves the
``running`` state. Tables listed in ``NO_DELETE`` reject DELETE outright.

The SQL produced here is the canonical text. The reference DDL and Alembic
migration 0002 carry copies, and ``tests/test_schema_events.py`` checks that
all three match and that every column of every guarded table is classified.

Note for future migrations: an Alembic batch rebuild recreates the table and
drops its triggers, so any migration that rebuilds a guarded table must
re-create them.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class UpdateRule:
    immutable: tuple[str, ...]
    clearable: tuple[str, ...] = ()
    set_once: tuple[str, ...] = ()
    mutable: tuple[str, ...] = ()
    frozen_when_finished: bool = False
    #: True means no UPDATE is allowed at all.
    forbid_all: bool = False

    @property
    def columns(self) -> frozenset[str]:
        return frozenset(self.immutable + self.clearable + self.set_once + self.mutable)


UPDATE_RULES: dict[str, UpdateRule] = {
    "access_events": UpdateRule(
        forbid_all=True,
        immutable=(
            "id",
            "decision_id",
            "request_id",
            "occurred_at",
            "recorded_at",
            "door_id",
            "source",
            "decision",
            "rule_number",
            "rule_name",
            "reason_code",
            "engine_version",
            "family_member_id",
            "permission_id",
            "matched_embedding_id",
            "match_confidence",
            "threshold_used",
            "review_of_decision_id",
            "approver_user_id",
            "camera_id",
            "correlation_id",
            "decision_latency_ms",
        ),
    ),
    "visitor_events": UpdateRule(
        immutable=(
            "id",
            "occurred_at",
            "recorded_at",
            "camera_id",
            "access_event_id",
            "sighting_count",
            "dwell_seconds",
            "face_count",
            "retention_expires_at",
        ),
        clearable=("visitor_cluster_key", "snapshot_ref", "snapshot_sha256"),
        set_once=("purged_at",),
        mutable=("disposition",),
    ),
    "security_events": UpdateRule(
        immutable=(
            "id",
            "event_uid",
            "event_type",
            "modality",
            "severity",
            "outcome",
            "suspicious",
            "occurred_at",
            "received_at",
            "timestamp_assumed_utc",
            "recorded_at",
            "source_module",
            "detector_rule",
            "confidence",
            "family_member_id",
            "user_id",
            "session_id",
            "request_id",
            "correlation_id",
            "ip_address",
            "door_id",
            "camera_id",
            "decision_id",
            "evidence_ref",
            "contributing_event_ids",
            "details",
        ),
        clearable=("visitor_key",),
        set_once=("incident_id",),
    ),
    "incident_evidence": UpdateRule(
        immutable=(
            "id",
            "incident_id",
            "evidence_type",
            "sha256",
            "byte_size",
            "captured_at",
            "source_module",
            "retention_expires_at",
            "created_at",
        ),
        clearable=("evidence_ref", "content"),
        set_once=("purged_at",),
    ),
    "workflow_executions": UpdateRule(
        immutable=(
            "id",
            "run_uid",
            "execution_kind",
            "workflow_name",
            "workflow_version",
            "automation_task_id",
            "incident_id",
            "requested_by_user_id",
            "trigger_source",
            "started_at",
        ),
        mutable=(
            "status",
            "finished_at",
            "duration_ms",
            "current_node",
            "steps",
            "result_summary",
            "error_message",
            "tokens_used",
        ),
        frozen_when_finished=True,
    ),
}

#: Migration 0003: approved retention extensions are never edited.
UPDATE_RULES["retention_extensions"] = UpdateRule(
    forbid_all=True,
    immutable=(
        "id",
        "evidence_id",
        "incident_id",
        "requested_by_user_id",
        "approved_by_user_id",
        "reason",
        "original_deadline",
        "previous_deadline",
        "extended_deadline",
        "requested_at",
        "approved_at",
        "recorded_at",
    ),
)

#: Migration 0004 (finding S4): audit entries are never edited. The actor may
#: only become NULL, which is what ``ON DELETE SET NULL`` from ``users`` does.
UPDATE_RULES["audit_log"] = UpdateRule(
    immutable=(
        "id",
        "occurred_at",
        "actor_label",
        "actor_ip",
        "action",
        "entity_type",
        "entity_id",
        "before_value",
        "after_value",
        "outcome",
        "correlation_id",
    ),
    clearable=("actor_user_id",),
)

#: Migration 0005: a detection finding is evidence and never changes.
UPDATE_RULES["incident_detections"] = UpdateRule(
    forbid_all=True,
    immutable=(
        "id",
        "incident_id",
        "security_event_id",
        "detector_rule",
        "dedupe_key",
        "severity",
        "reason",
        "event_uids",
        "detected_at",
        "recorded_at",
    ),
)

#: Migration 0005: a notification attempt keeps who/what/where fixed; only the
#: provider-reported progress changes, and identifiers and timestamps that
#: record a provider fact can be set once and never rewritten.
UPDATE_RULES["notifications"] = UpdateRule(
    immutable=(
        "id",
        "incident_id",
        "channel",
        "provider",
        "recipient_masked",
        "trigger_reason",
        "created_at",
    ),
    set_once=("provider_message_id", "sent_at", "delivered_at", "failed_at"),
    mutable=(
        "status",
        "provider_status",
        "http_status",
        "error_code",
        "error_message",
        "status_checked_at",
        "updated_at",
    ),
)

#: Tables whose rows can never be deleted. ``incidents`` is included because
#: security history must not be purged (SR-AUDIT-08); it has no UPDATE guard
#: because cases are mutable by design.
NO_DELETE: tuple[str, ...] = (
    "access_events",
    "visitor_events",
    "security_events",
    "incidents",
    "incident_evidence",
    "workflow_executions",
    "retention_extensions",
    "audit_log",
    "incident_detections",
    "notifications",
)

#: Integrity triggers added by migration 0003 (retention policy). They run
#: after the append-only guards of the same table.
EXTRA_TRIGGERS: dict[str, tuple[str, ...]] = {
    # An extension must match the evidence's original deadline, an open
    # incident, an active admin approver, and the current effective deadline.
    "retention_extensions": (
        "CREATE TRIGGER trg_retention_extensions_validate_insert BEFORE INSERT "
        "ON retention_extensions FOR EACH ROW WHEN NOT EXISTS (SELECT 1 FROM "
        "incident_evidence e JOIN incidents i ON i.id = e.incident_id WHERE "
        "e.id = NEW.evidence_id AND e.incident_id = NEW.incident_id AND "
        "e.purged_at IS NULL AND e.retention_expires_at = NEW.original_deadline "
        "AND i.status IN ('open', 'investigating')) OR NOT EXISTS (SELECT 1 FROM "
        "users u WHERE u.id = NEW.approved_by_user_id AND u.role = 'admin' AND "
        "u.is_active = 1) OR NEW.previous_deadline IS NOT COALESCE((SELECT "
        "MAX(x.extended_deadline) FROM retention_extensions x WHERE "
        "x.evidence_id = NEW.evidence_id), NEW.original_deadline) BEGIN SELECT "
        "RAISE(ABORT, 'retention_extensions: extension not valid for this "
        "evidence'); END",
    ),
    # Evidence under an approved extension cannot be purged before it ends.
    "incident_evidence": (
        "CREATE TRIGGER trg_incident_evidence_respect_extensions BEFORE UPDATE OF "
        "purged_at ON incident_evidence FOR EACH ROW WHEN NEW.purged_at IS NOT "
        "NULL AND EXISTS (SELECT 1 FROM retention_extensions r WHERE "
        "r.evidence_id = NEW.id AND r.extended_deadline > NEW.purged_at) BEGIN "
        "SELECT RAISE(ABORT, 'incident_evidence: retention extended; purge not "
        "permitted'); END",
    ),
}


def _update_trigger(table: str, rule: UpdateRule) -> str:
    head = f"CREATE TRIGGER trg_{table}_guard_update BEFORE UPDATE ON {table}"
    body = f"BEGIN SELECT RAISE(ABORT, '{table}: update not permitted'); END"
    if rule.forbid_all:
        return f"{head} FOR EACH ROW {body}"
    conditions = [f"NEW.{c} IS NOT OLD.{c}" for c in rule.immutable]
    conditions += [
        f"(NEW.{c} IS NOT OLD.{c} AND NEW.{c} IS NOT NULL)" for c in rule.clearable
    ]
    conditions += [
        f"(OLD.{c} IS NOT NULL AND NEW.{c} IS NOT OLD.{c})" for c in rule.set_once
    ]
    if rule.frozen_when_finished:
        conditions.append("OLD.status <> 'running'")
    return f"{head} FOR EACH ROW WHEN {' OR '.join(conditions)} {body}"


def _delete_trigger(table: str) -> str:
    return (
        f"CREATE TRIGGER trg_{table}_no_delete BEFORE DELETE ON {table} "
        f"FOR EACH ROW BEGIN SELECT RAISE(ABORT, '{table}: delete not permitted'); "
        "END"
    )


def trigger_statements(table: str) -> tuple[str, ...]:
    """Canonical CREATE TRIGGER statements for one table, in a fixed order."""
    statements: list[str] = []
    if table in UPDATE_RULES:
        statements.append(_update_trigger(table, UPDATE_RULES[table]))
    if table in NO_DELETE:
        statements.append(_delete_trigger(table))
    statements.extend(EXTRA_TRIGGERS.get(table, ()))
    return tuple(statements)


def all_trigger_statements() -> dict[str, tuple[str, ...]]:
    tables = sorted(set(UPDATE_RULES) | set(NO_DELETE) | set(EXTRA_TRIGGERS))
    return {t: trigger_statements(t) for t in tables}
