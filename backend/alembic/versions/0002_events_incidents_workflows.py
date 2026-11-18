"""Events, incidents, evidence and workflow executions (DD-09).

Adds the six tables the event pipeline, incident handling and the AI workflow
recorder need: access_events, visitor_events, incidents, security_events,
incident_evidence and workflow_executions, plus the append-only triggers
from ``app/database/append_only.py`` (copied here as literals so this
revision never changes when application code does).

Foreign keys that would point at tables not built yet (permissions,
face_embeddings, automation_tasks) are plain integer columns for now. Adding
those keys later needs a batch rebuild, which drops triggers: that migration
must re-create them.

``downgrade()`` refuses to run if any of these tables holds rows, because it
would destroy security history (DATABASE_DESIGN.md 9.4).

Status: written and checked statically against the reference DDL. Never
applied: Alembic and SQLAlchemy cannot be installed in this environment.

Revision ID: 0002_events_incidents_workflows
Revises: 0001_initial_identity
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_events_incidents_workflows"
down_revision: str | None = "0001_initial_identity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLES = (
    "access_events",
    "visitor_events",
    "incidents",
    "security_events",
    "incident_evidence",
    "workflow_executions",
)

_TRIGGERS = (
    (
        "CREATE TRIGGER trg_access_events_guard_update BEFORE UPDATE ON "
        "access_events FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'access_events: "
        "update not permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_access_events_no_delete BEFORE DELETE ON access_events "
        "FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'access_events: delete not "
        "permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_incident_evidence_guard_update BEFORE UPDATE ON "
        "incident_evidence FOR EACH ROW WHEN NEW.id IS NOT OLD.id OR "
        "NEW.incident_id IS NOT OLD.incident_id OR NEW.evidence_type IS NOT "
        "OLD.evidence_type OR NEW.sha256 IS NOT OLD.sha256 OR NEW.byte_size IS NOT "
        "OLD.byte_size OR NEW.captured_at IS NOT OLD.captured_at OR "
        "NEW.source_module IS NOT OLD.source_module OR NEW.retention_expires_at IS "
        "NOT OLD.retention_expires_at OR NEW.created_at IS NOT OLD.created_at OR "
        "(NEW.evidence_ref IS NOT OLD.evidence_ref AND NEW.evidence_ref IS NOT "
        "NULL) OR (NEW.content IS NOT OLD.content AND NEW.content IS NOT NULL) OR "
        "(OLD.purged_at IS NOT NULL AND NEW.purged_at IS NOT OLD.purged_at) BEGIN "
        "SELECT RAISE(ABORT, 'incident_evidence: update not permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_incident_evidence_no_delete BEFORE DELETE ON "
        "incident_evidence FOR EACH ROW BEGIN SELECT RAISE(ABORT, "
        "'incident_evidence: delete not permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_incidents_no_delete BEFORE DELETE ON incidents FOR EACH"
        " ROW BEGIN SELECT RAISE(ABORT, 'incidents: delete not permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_security_events_guard_update BEFORE UPDATE ON "
        "security_events FOR EACH ROW WHEN NEW.id IS NOT OLD.id OR NEW.event_uid IS"
        " NOT OLD.event_uid OR NEW.event_type IS NOT OLD.event_type OR NEW.modality"
        " IS NOT OLD.modality OR NEW.severity IS NOT OLD.severity OR NEW.outcome IS"
        " NOT OLD.outcome OR NEW.suspicious IS NOT OLD.suspicious OR "
        "NEW.occurred_at IS NOT OLD.occurred_at OR NEW.received_at IS NOT "
        "OLD.received_at OR NEW.timestamp_assumed_utc IS NOT "
        "OLD.timestamp_assumed_utc OR NEW.recorded_at IS NOT OLD.recorded_at OR "
        "NEW.source_module IS NOT OLD.source_module OR NEW.detector_rule IS NOT "
        "OLD.detector_rule OR NEW.confidence IS NOT OLD.confidence OR "
        "NEW.family_member_id IS NOT OLD.family_member_id OR NEW.user_id IS NOT "
        "OLD.user_id OR NEW.session_id IS NOT OLD.session_id OR NEW.request_id IS "
        "NOT OLD.request_id OR NEW.correlation_id IS NOT OLD.correlation_id OR "
        "NEW.ip_address IS NOT OLD.ip_address OR NEW.door_id IS NOT OLD.door_id OR "
        "NEW.camera_id IS NOT OLD.camera_id OR NEW.decision_id IS NOT "
        "OLD.decision_id OR NEW.evidence_ref IS NOT OLD.evidence_ref OR "
        "NEW.contributing_event_ids IS NOT OLD.contributing_event_ids OR "
        "NEW.details IS NOT OLD.details OR (NEW.visitor_key IS NOT OLD.visitor_key "
        "AND NEW.visitor_key IS NOT NULL) OR (OLD.incident_id IS NOT NULL AND "
        "NEW.incident_id IS NOT OLD.incident_id) BEGIN SELECT RAISE(ABORT, "
        "'security_events: update not permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_security_events_no_delete BEFORE DELETE ON "
        "security_events FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'security_events: "
        "delete not permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_visitor_events_guard_update BEFORE UPDATE ON "
        "visitor_events FOR EACH ROW WHEN NEW.id IS NOT OLD.id OR NEW.occurred_at "
        "IS NOT OLD.occurred_at OR NEW.recorded_at IS NOT OLD.recorded_at OR "
        "NEW.camera_id IS NOT OLD.camera_id OR NEW.access_event_id IS NOT "
        "OLD.access_event_id OR NEW.sighting_count IS NOT OLD.sighting_count OR "
        "NEW.dwell_seconds IS NOT OLD.dwell_seconds OR NEW.face_count IS NOT "
        "OLD.face_count OR NEW.retention_expires_at IS NOT OLD.retention_expires_at"
        " OR (NEW.visitor_cluster_key IS NOT OLD.visitor_cluster_key AND "
        "NEW.visitor_cluster_key IS NOT NULL) OR (NEW.snapshot_ref IS NOT "
        "OLD.snapshot_ref AND NEW.snapshot_ref IS NOT NULL) OR (NEW.snapshot_sha256"
        " IS NOT OLD.snapshot_sha256 AND NEW.snapshot_sha256 IS NOT NULL) OR "
        "(OLD.purged_at IS NOT NULL AND NEW.purged_at IS NOT OLD.purged_at) BEGIN "
        "SELECT RAISE(ABORT, 'visitor_events: update not permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_visitor_events_no_delete BEFORE DELETE ON "
        "visitor_events FOR EACH ROW BEGIN SELECT RAISE(ABORT, 'visitor_events: "
        "delete not permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_workflow_executions_guard_update BEFORE UPDATE ON "
        "workflow_executions FOR EACH ROW WHEN NEW.id IS NOT OLD.id OR NEW.run_uid "
        "IS NOT OLD.run_uid OR NEW.execution_kind IS NOT OLD.execution_kind OR "
        "NEW.workflow_name IS NOT OLD.workflow_name OR NEW.workflow_version IS NOT "
        "OLD.workflow_version OR NEW.automation_task_id IS NOT "
        "OLD.automation_task_id OR NEW.incident_id IS NOT OLD.incident_id OR "
        "NEW.requested_by_user_id IS NOT OLD.requested_by_user_id OR "
        "NEW.trigger_source IS NOT OLD.trigger_source OR NEW.started_at IS NOT "
        "OLD.started_at OR OLD.status <> 'running' BEGIN SELECT RAISE(ABORT, "
        "'workflow_executions: update not permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_workflow_executions_no_delete BEFORE DELETE ON "
        "workflow_executions FOR EACH ROW BEGIN SELECT RAISE(ABORT, "
        "'workflow_executions: delete not permitted'); END"
    ),
)


def upgrade() -> None:
    op.create_table(
        "access_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("decision_id", sa.String(length=64), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column("door_id", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=20), nullable=False),
        sa.Column("decision", sa.String(length=10), nullable=False),
        sa.Column("rule_number", sa.Integer(), nullable=False),
        sa.Column("rule_name", sa.String(length=50), nullable=False),
        sa.Column("reason_code", sa.String(length=100), nullable=False),
        sa.Column("engine_version", sa.String(length=50), nullable=False),
        sa.Column("family_member_id", sa.Integer(), nullable=True),
        sa.Column("permission_id", sa.Integer(), nullable=True),
        sa.Column("matched_embedding_id", sa.Integer(), nullable=True),
        sa.Column("match_confidence", sa.Float(), nullable=True),
        sa.Column("threshold_used", sa.Float(), nullable=True),
        sa.Column("review_of_decision_id", sa.String(length=64), nullable=True),
        sa.Column("approver_user_id", sa.Integer(), nullable=True),
        sa.Column("camera_id", sa.String(length=64), nullable=True),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("decision_latency_ms", sa.Integer(), nullable=True),
        sa.CheckConstraint(
            "decision IN ('allow', 'deny', 'hold')",
            name=op.f("ck_access_events_decision_valid"),
        ),
        sa.CheckConstraint(
            "source IN ('camera', 'admin_review', 'manual_override')",
            name=op.f("ck_access_events_source_valid"),
        ),
        sa.CheckConstraint(
            "rule_number >= 0", name=op.f("ck_access_events_rule_number_valid")
        ),
        sa.CheckConstraint(
            "source = 'admin_review' OR review_of_decision_id IS NULL",
            name=op.f("ck_access_events_review_link_only_for_reviews"),
        ),
        sa.CheckConstraint(
            "source <> 'admin_review' OR decision IN ('allow', 'deny')",
            name=op.f("ck_access_events_review_never_holds"),
        ),
        sa.CheckConstraint(
            "match_confidence IS NULL OR "
            "(match_confidence >= -1 AND match_confidence <= 1)",
            name=op.f("ck_access_events_match_confidence_range"),
        ),
        sa.CheckConstraint(
            "threshold_used IS NULL OR (threshold_used > 0 AND threshold_used <= 1)",
            name=op.f("ck_access_events_threshold_range"),
        ),
        sa.CheckConstraint(
            "decision_latency_ms IS NULL OR decision_latency_ms >= 0",
            name=op.f("ck_access_events_latency_nonnegative"),
        ),
        sa.ForeignKeyConstraint(
            ["family_member_id"],
            ["family_members.id"],
            name=op.f("fk_access_events_family_member_id_family_members"),
        ),
        sa.ForeignKeyConstraint(
            ["approver_user_id"],
            ["users.id"],
            name=op.f("fk_access_events_approver_user_id_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_access_events")),
    )
    op.create_index(
        op.f("ix_access_events_decision_id"),
        "access_events",
        ["decision_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_access_events_occurred_at"), "access_events", ["occurred_at"]
    )
    op.create_index(
        op.f("ix_access_events_member_time"),
        "access_events",
        ["family_member_id", "occurred_at"],
    )
    op.create_index(op.f("ix_access_events_decision"), "access_events", ["decision"])
    op.create_index(
        op.f("ix_access_events_correlation_id"), "access_events", ["correlation_id"]
    )

    op.create_table(
        "visitor_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column("camera_id", sa.String(length=64), nullable=True),
        sa.Column("access_event_id", sa.Integer(), nullable=True),
        sa.Column("visitor_cluster_key", sa.String(length=128), nullable=True),
        sa.Column("sighting_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("dwell_seconds", sa.Integer(), nullable=True),
        sa.Column("face_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("snapshot_ref", sa.String(length=255), nullable=True),
        sa.Column("snapshot_sha256", sa.String(length=64), nullable=True),
        sa.Column(
            "disposition",
            sa.String(length=30),
            nullable=False,
            server_default="unreviewed",
        ),
        sa.Column("retention_expires_at", sa.DateTime(), nullable=False),
        sa.Column("purged_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "disposition IN ('unreviewed', 'benign', 'suspicious', "
            "'promoted_to_member')",
            name=op.f("ck_visitor_events_disposition_valid"),
        ),
        sa.CheckConstraint(
            "sighting_count >= 1",
            name=op.f("ck_visitor_events_sighting_count_positive"),
        ),
        sa.CheckConstraint(
            "face_count >= 1", name=op.f("ck_visitor_events_face_count_positive")
        ),
        sa.CheckConstraint(
            "dwell_seconds IS NULL OR dwell_seconds >= 0",
            name=op.f("ck_visitor_events_dwell_nonnegative"),
        ),
        sa.CheckConstraint(
            "snapshot_ref IS NULL OR (length(snapshot_ref) BETWEEN 1 AND 255 AND "
            "length(CAST(snapshot_ref AS BLOB)) = length(snapshot_ref) AND "
            "snapshot_ref NOT GLOB '*[^A-Za-z0-9._/-]*' AND "
            "substr(snapshot_ref, 1, 1) <> '/' AND "
            "substr(snapshot_ref, -1, 1) <> '/' AND "
            "instr(snapshot_ref, '//') = 0 AND snapshot_ref <> '..' AND "
            "substr(snapshot_ref, 1, 3) <> '../' AND "
            "substr(snapshot_ref, -3, 3) <> '/..' AND "
            "instr(snapshot_ref, '/../') = 0)",
            name=op.f("ck_visitor_events_snapshot_ref_safe"),
        ),
        sa.CheckConstraint(
            "snapshot_sha256 IS NULL OR (length(snapshot_sha256) = 64 AND "
            "snapshot_sha256 NOT GLOB '*[^0-9a-f]*')",
            name=op.f("ck_visitor_events_snapshot_sha256_hex"),
        ),
        sa.CheckConstraint(
            "(snapshot_ref IS NULL) = (snapshot_sha256 IS NULL)",
            name=op.f("ck_visitor_events_snapshot_hashed"),
        ),
        sa.CheckConstraint(
            "purged_at IS NULL OR (snapshot_ref IS NULL AND "
            "snapshot_sha256 IS NULL AND visitor_cluster_key IS NULL)",
            name=op.f("ck_visitor_events_purge_complete"),
        ),
        sa.CheckConstraint(
            "retention_expires_at > occurred_at",
            name=op.f("ck_visitor_events_retention_after_occurrence"),
        ),
        sa.ForeignKeyConstraint(
            ["access_event_id"],
            ["access_events.id"],
            name=op.f("fk_visitor_events_access_event_id_access_events"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_visitor_events")),
    )
    op.create_index(
        op.f("ix_visitor_events_occurred_at"), "visitor_events", ["occurred_at"]
    )
    op.create_index(
        op.f("ix_visitor_events_visitor_cluster_key"),
        "visitor_events",
        ["visitor_cluster_key"],
    )
    op.create_index(
        op.f("ix_visitor_events_retention_expires_at"),
        "visitor_events",
        ["retention_expires_at"],
    )

    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_uid", sa.String(length=64), nullable=False),
        sa.Column("opened_at", sa.DateTime(), nullable=False),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("category", sa.String(length=50), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="open"
        ),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_event_at", sa.DateTime(), nullable=True),
        sa.Column("last_event_at", sa.DateTime(), nullable=True),
        sa.Column(
            "notify_recommended", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column("assigned_to_user_id", sa.Integer(), nullable=True),
        sa.Column("resolved_by_user_id", sa.Integer(), nullable=True),
        sa.Column("resolution_notes", sa.Text(), nullable=True),
        sa.Column("attack_chain", sa.Text(), nullable=True),
        sa.Column("attack_chain_generated_at", sa.DateTime(), nullable=True),
        sa.Column("ai_summary", sa.Text(), nullable=True),
        sa.Column("ai_recommendations", sa.Text(), nullable=True),
        sa.Column("ai_model_version", sa.String(length=100), nullable=True),
        sa.Column("ai_generated_at", sa.DateTime(), nullable=True),
        sa.Column("is_ai_enriched", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name=op.f("ck_incidents_severity_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('open', 'investigating', 'resolved', 'false_positive')",
            name=op.f("ck_incidents_status_valid"),
        ),
        sa.CheckConstraint(
            "event_count >= 0", name=op.f("ck_incidents_event_count_nonnegative")
        ),
        sa.CheckConstraint(
            "notify_recommended IN (0, 1)",
            name=op.f("ck_incidents_notify_recommended_bool"),
        ),
        sa.CheckConstraint(
            "is_ai_enriched IN (0, 1)", name=op.f("ck_incidents_is_ai_enriched_bool")
        ),
        sa.CheckConstraint(
            "(status IN ('resolved', 'false_positive')) = (closed_at IS NOT NULL)",
            name=op.f("ck_incidents_closed_consistent"),
        ),
        sa.CheckConstraint(
            "first_event_at IS NULL OR last_event_at IS NULL OR "
            "first_event_at <= last_event_at",
            name=op.f("ck_incidents_window_ordered"),
        ),
        sa.CheckConstraint(
            "attack_chain IS NULL OR json_valid(attack_chain)",
            name=op.f("ck_incidents_attack_chain_json"),
        ),
        sa.CheckConstraint(
            "(attack_chain IS NULL) = (attack_chain_generated_at IS NULL)",
            name=op.f("ck_incidents_attack_chain_dated"),
        ),
        sa.CheckConstraint(
            "ai_recommendations IS NULL OR json_valid(ai_recommendations)",
            name=op.f("ck_incidents_ai_recommendations_json"),
        ),
        sa.CheckConstraint(
            "is_ai_enriched = 1 OR (ai_summary IS NULL AND "
            "ai_recommendations IS NULL AND ai_model_version IS NULL AND "
            "ai_generated_at IS NULL)",
            name=op.f("ck_incidents_ai_content_labelled"),
        ),
        sa.CheckConstraint(
            "is_ai_enriched = 0 OR (ai_summary IS NOT NULL AND "
            "ai_model_version IS NOT NULL AND ai_generated_at IS NOT NULL)",
            name=op.f("ck_incidents_ai_provenance"),
        ),
        sa.ForeignKeyConstraint(
            ["assigned_to_user_id"],
            ["users.id"],
            name=op.f("fk_incidents_assigned_to_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["resolved_by_user_id"],
            ["users.id"],
            name=op.f("fk_incidents_resolved_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incidents")),
    )
    op.create_index(
        op.f("ix_incidents_incident_uid"), "incidents", ["incident_uid"], unique=True
    )
    op.create_index(op.f("ix_incidents_status"), "incidents", ["status"])
    op.create_index(op.f("ix_incidents_severity"), "incidents", ["severity"])
    op.create_index(op.f("ix_incidents_opened_at"), "incidents", ["opened_at"])

    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_uid", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("modality", sa.String(length=20), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("outcome", sa.String(length=10), nullable=False),
        sa.Column("suspicious", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column(
            "timestamp_assumed_utc", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column(
            "recorded_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column("source_module", sa.String(length=64), nullable=False),
        sa.Column("detector_rule", sa.String(length=100), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("family_member_id", sa.Integer(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("visitor_key", sa.String(length=128), nullable=True),
        sa.Column("session_id", sa.String(length=128), nullable=True),
        sa.Column("request_id", sa.String(length=128), nullable=True),
        sa.Column("correlation_id", sa.String(length=128), nullable=True),
        sa.Column("ip_address", sa.String(length=128), nullable=True),
        sa.Column("door_id", sa.String(length=128), nullable=True),
        sa.Column("camera_id", sa.String(length=128), nullable=True),
        sa.Column("decision_id", sa.String(length=128), nullable=True),
        sa.Column("evidence_ref", sa.String(length=255), nullable=True),
        sa.Column("incident_id", sa.Integer(), nullable=True),
        sa.Column("contributing_event_ids", sa.Text(), nullable=True),
        sa.Column("details", sa.Text(), nullable=False, server_default="{}"),
        sa.CheckConstraint(
            "length(event_uid) BETWEEN 1 AND 128",
            name=op.f("ck_security_events_event_uid_length"),
        ),
        sa.CheckConstraint(
            "modality IN ('biometric', 'access', 'door', 'auth', 'api', 'admin', "
            "'ai_agent', 'system', 'notification')",
            name=op.f("ck_security_events_modality_valid"),
        ),
        sa.CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name=op.f("ck_security_events_severity_valid"),
        ),
        sa.CheckConstraint(
            "outcome IN ('succeeded', 'blocked', 'failed', 'observed')",
            name=op.f("ck_security_events_outcome_valid"),
        ),
        sa.CheckConstraint(
            "suspicious IN (0, 1)", name=op.f("ck_security_events_suspicious_bool")
        ),
        sa.CheckConstraint(
            "timestamp_assumed_utc IN (0, 1)",
            name=op.f("ck_security_events_timestamp_assumed_utc_bool"),
        ),
        sa.CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name=op.f("ck_security_events_confidence_range"),
        ),
        sa.CheckConstraint(
            "evidence_ref IS NULL OR (length(evidence_ref) BETWEEN 1 AND 255 AND "
            "length(CAST(evidence_ref AS BLOB)) = length(evidence_ref) AND "
            "evidence_ref NOT GLOB '*[^A-Za-z0-9._/-]*' AND "
            "substr(evidence_ref, 1, 1) <> '/' AND "
            "substr(evidence_ref, -1, 1) <> '/' AND "
            "instr(evidence_ref, '//') = 0 AND evidence_ref <> '..' AND "
            "substr(evidence_ref, 1, 3) <> '../' AND "
            "substr(evidence_ref, -3, 3) <> '/..' AND "
            "instr(evidence_ref, '/../') = 0)",
            name=op.f("ck_security_events_evidence_ref_safe"),
        ),
        sa.CheckConstraint(
            "json_valid(details)", name=op.f("ck_security_events_details_json")
        ),
        sa.CheckConstraint(
            "contributing_event_ids IS NULL OR json_valid(contributing_event_ids)",
            name=op.f("ck_security_events_contributing_json"),
        ),
        sa.ForeignKeyConstraint(
            ["family_member_id"],
            ["family_members.id"],
            name=op.f("fk_security_events_family_member_id_family_members"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_security_events_user_id_users")
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_security_events_incident_id_incidents"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_events")),
    )
    op.create_index(
        op.f("ix_security_events_event_uid"),
        "security_events",
        ["event_uid"],
        unique=True,
    )
    op.create_index(
        op.f("ix_security_events_occurred_at"), "security_events", ["occurred_at"]
    )
    op.create_index(
        op.f("ix_security_events_severity"), "security_events", ["severity"]
    )
    op.create_index(
        op.f("ix_security_events_incident_id"), "security_events", ["incident_id"]
    )
    op.create_index(
        op.f("ix_security_events_event_type"), "security_events", ["event_type"]
    )

    op.create_table(
        "incident_evidence",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("evidence_type", sa.String(length=20), nullable=False),
        sa.Column("evidence_ref", sa.String(length=255), nullable=True),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("byte_size", sa.Integer(), nullable=True),
        sa.Column("captured_at", sa.DateTime(), nullable=False),
        sa.Column("source_module", sa.String(length=64), nullable=False),
        sa.Column("retention_expires_at", sa.DateTime(), nullable=True),
        sa.Column("purged_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.CheckConstraint(
            "evidence_type IN ('snapshot', 'clip', 'log_extract', 'event_export', "
            "'note')",
            name=op.f("ck_incident_evidence_evidence_type_valid"),
        ),
        sa.CheckConstraint(
            "evidence_ref IS NULL OR (length(evidence_ref) BETWEEN 1 AND 255 AND "
            "length(CAST(evidence_ref AS BLOB)) = length(evidence_ref) AND "
            "evidence_ref NOT GLOB '*[^A-Za-z0-9._/-]*' AND "
            "substr(evidence_ref, 1, 1) <> '/' AND "
            "substr(evidence_ref, -1, 1) <> '/' AND "
            "instr(evidence_ref, '//') = 0 AND evidence_ref <> '..' AND "
            "substr(evidence_ref, 1, 3) <> '../' AND "
            "substr(evidence_ref, -3, 3) <> '/..' AND "
            "instr(evidence_ref, '/../') = 0)",
            name=op.f("ck_incident_evidence_evidence_ref_safe"),
        ),
        sa.CheckConstraint(
            "sha256 IS NULL OR (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*')",
            name=op.f("ck_incident_evidence_sha256_hex"),
        ),
        sa.CheckConstraint(
            "byte_size IS NULL OR byte_size >= 0",
            name=op.f("ck_incident_evidence_byte_size_nonnegative"),
        ),
        sa.CheckConstraint(
            "evidence_ref IS NULL OR sha256 IS NOT NULL",
            name=op.f("ck_incident_evidence_file_hashed"),
        ),
        sa.CheckConstraint(
            "purged_at IS NOT NULL OR evidence_ref IS NOT NULL OR content IS NOT NULL",
            name=op.f("ck_incident_evidence_has_payload"),
        ),
        sa.CheckConstraint(
            "purged_at IS NULL OR (evidence_ref IS NULL AND content IS NULL)",
            name=op.f("ck_incident_evidence_purge_complete"),
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_incident_evidence_incident_id_incidents"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_evidence")),
    )
    op.create_index(
        op.f("ix_incident_evidence_incident_id"), "incident_evidence", ["incident_id"]
    )
    op.create_index(
        op.f("ix_incident_evidence_retention_expires_at"),
        "incident_evidence",
        ["retention_expires_at"],
    )

    op.create_table(
        "workflow_executions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_uid", sa.String(length=64), nullable=False),
        sa.Column("execution_kind", sa.String(length=30), nullable=False),
        sa.Column("workflow_name", sa.String(length=100), nullable=True),
        sa.Column("workflow_version", sa.String(length=50), nullable=True),
        sa.Column("automation_task_id", sa.Integer(), nullable=True),
        sa.Column("incident_id", sa.Integer(), nullable=True),
        sa.Column("requested_by_user_id", sa.Integer(), nullable=True),
        sa.Column("trigger_source", sa.String(length=20), nullable=False),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="running"
        ),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("current_node", sa.String(length=100), nullable=True),
        sa.Column("steps", sa.Text(), nullable=True),
        sa.Column("result_summary", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("tokens_used", sa.Integer(), nullable=True),
        sa.CheckConstraint(
            "execution_kind IN ('scheduled_job', 'langgraph_workflow')",
            name=op.f("ck_workflow_executions_execution_kind_valid"),
        ),
        sa.CheckConstraint(
            "trigger_source IN ('schedule', 'manual', 'event')",
            name=op.f("ck_workflow_executions_trigger_source_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('running', 'succeeded', 'failed', 'cancelled', 'timeout')",
            name=op.f("ck_workflow_executions_status_valid"),
        ),
        sa.CheckConstraint(
            "(execution_kind = 'langgraph_workflow') = (workflow_name IS NOT NULL)",
            name=op.f("ck_workflow_executions_name_matches_kind"),
        ),
        sa.CheckConstraint(
            "execution_kind = 'scheduled_job' OR automation_task_id IS NULL",
            name=op.f("ck_workflow_executions_task_only_for_jobs"),
        ),
        sa.CheckConstraint(
            "(status = 'running') = (finished_at IS NULL)",
            name=op.f("ck_workflow_executions_finished_consistent"),
        ),
        sa.CheckConstraint(
            "duration_ms IS NULL OR duration_ms >= 0",
            name=op.f("ck_workflow_executions_duration_nonnegative"),
        ),
        sa.CheckConstraint(
            "tokens_used IS NULL OR tokens_used >= 0",
            name=op.f("ck_workflow_executions_tokens_nonnegative"),
        ),
        sa.CheckConstraint(
            "steps IS NULL OR json_valid(steps)",
            name=op.f("ck_workflow_executions_steps_json"),
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_workflow_executions_incident_id_incidents"),
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"],
            ["users.id"],
            name=op.f("fk_workflow_executions_requested_by_user_id_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_workflow_executions")),
    )
    op.create_index(
        op.f("ix_workflow_executions_run_uid"),
        "workflow_executions",
        ["run_uid"],
        unique=True,
    )
    op.create_index(
        op.f("ix_workflow_executions_kind_started"),
        "workflow_executions",
        ["execution_kind", "started_at"],
    )
    op.create_index(
        op.f("ix_workflow_executions_automation_task_id"),
        "workflow_executions",
        ["automation_task_id"],
    )
    op.create_index(
        op.f("ix_workflow_executions_incident_id"),
        "workflow_executions",
        ["incident_id"],
    )
    op.create_index(
        op.f("ix_workflow_executions_status"), "workflow_executions", ["status"]
    )
    op.create_index(
        op.f("ix_workflow_executions_requested_by_user_id"),
        "workflow_executions",
        ["requested_by_user_id"],
    )

    for statement in _TRIGGERS:
        op.execute(statement)


def downgrade() -> None:
    """Drop the 0002 tables, but only if they are empty."""
    bind = op.get_bind()
    populated = [
        table
        for table in _TABLES
        # Table names come from the _TABLES constant above, never from input.
        if bind.execute(sa.text(f"SELECT COUNT(*) FROM {table}")).scalar_one()  # noqa: S608
    ]
    if populated:
        raise RuntimeError(
            "refusing to downgrade: these tables hold security history: "
            + ", ".join(populated)
        )
    for table in reversed(_TABLES):
        op.drop_table(table)
