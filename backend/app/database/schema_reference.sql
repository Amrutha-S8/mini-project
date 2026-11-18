-- =====================================================================
-- Reference schema — identity (0001) + events, incidents, workflows (0002)
-- =====================================================================
--
-- PURPOSE AND STATUS — read before using.
--
-- The SQLAlchemy models in app/models/ are the CANONICAL schema, and Alembic
-- migration 0001 is the canonical way to apply it. This file is a *reference
-- DDL* that mirrors those models so the schema design can be executed and
-- tested with stdlib sqlite3 while SQLAlchemy and Alembic are uninstallable
-- (PROJECT_AUDIT.md blocker E1).
--
-- It is therefore a SECOND representation of the schema, which is a known
-- duplication risk. Day 2b task: once Alembic is installed, run
-- `alembic upgrade head` on an empty database and diff its sqlite_master
-- against the schema produced by this file. They must match; if they diverge,
-- the models win and this file is corrected or deleted.
--
-- Migration 0001 creates the four identity tables. Migration 0002 adds the
-- six tables the event pipeline, incidents and AI workflow records need
-- (DD-09). The remaining five tables arrive with their owning module (see
-- app/models/__init__.py).
--
-- Source of truth for column semantics: docs/DATABASE_DESIGN.md, amended by
-- docs/DESIGN_DECISIONS.md DD-09 for the 0002 tables.
-- =====================================================================

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------
-- users — operator accounts (DATABASE_DESIGN.md 3.1)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER NOT NULL PRIMARY KEY,
    email               TEXT    NOT NULL,
    password_hash       TEXT    NOT NULL,              -- Argon2id encoded hash
    full_name           TEXT    NOT NULL,
    role                TEXT    NOT NULL DEFAULT 'viewer',
    is_active           INTEGER NOT NULL DEFAULT 1,    -- soft deactivation only
    failed_login_count  INTEGER NOT NULL DEFAULT 0,
    locked_until        DATETIME,
    last_login_at       DATETIME,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_users_role_valid
        CHECK (role IN ('admin', 'member', 'viewer')),
    CONSTRAINT ck_users_is_active_bool
        CHECK (is_active IN (0, 1))
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email);

-- ---------------------------------------------------------------------
-- family_members — people the system recognises (DATABASE_DESIGN.md 3.2)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS family_members (
    id                  INTEGER NOT NULL PRIMARY KEY,
    user_id             INTEGER,
    full_name           TEXT    NOT NULL,
    relationship        TEXT,
    member_type         TEXT    NOT NULL DEFAULT 'family',
    status              TEXT    NOT NULL DEFAULT 'active',
    enrollment_status   TEXT    NOT NULL DEFAULT 'not_enrolled',
    notes               TEXT,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_family_members_user_id_users
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT ck_family_members_status_valid
        CHECK (status IN ('active', 'inactive', 'revoked')),
    CONSTRAINT ck_family_members_member_type_valid
        CHECK (member_type IN ('family', 'resident', 'staff', 'recurring_visitor')),
    CONSTRAINT ck_family_members_enrollment_status_valid
        CHECK (enrollment_status IN ('not_enrolled', 'enrolled', 'needs_reenrollment'))
);

CREATE INDEX IF NOT EXISTS ix_family_members_status
    ON family_members (status);

-- ---------------------------------------------------------------------
-- sessions — server-side refresh sessions (DATABASE_DESIGN.md 3.5)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id                  INTEGER NOT NULL PRIMARY KEY,
    user_id             INTEGER NOT NULL,
    refresh_token_hash  TEXT    NOT NULL,              -- HMAC only, never the token
    parent_session_id   INTEGER,                        -- rotation lineage
    ip_address          TEXT,
    user_agent          TEXT,
    issued_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          DATETIME NOT NULL,
    revoked_at          DATETIME,
    revoked_reason      TEXT,
    CONSTRAINT fk_sessions_user_id_users
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_sessions_parent_session_id_sessions
        FOREIGN KEY (parent_session_id) REFERENCES sessions (id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_sessions_refresh_token_hash
    ON sessions (refresh_token_hash);
CREATE INDEX IF NOT EXISTS ix_sessions_user_id   ON sessions (user_id);
CREATE INDEX IF NOT EXISTS ix_sessions_expires_at ON sessions (expires_at);

-- ---------------------------------------------------------------------
-- audit_log — append-only security configuration trail (DATABASE_DESIGN.md 7)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER NOT NULL PRIMARY KEY,
    occurred_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor_user_id   INTEGER,
    actor_label     TEXT    NOT NULL DEFAULT 'system',
    actor_ip        TEXT,
    action          TEXT    NOT NULL,
    entity_type     TEXT    NOT NULL,
    entity_id       TEXT,
    before_value    TEXT,
    after_value     TEXT,
    outcome         TEXT    NOT NULL DEFAULT 'success',
    correlation_id  TEXT,
    CONSTRAINT fk_audit_log_actor_user_id_users
        FOREIGN KEY (actor_user_id) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT ck_audit_log_outcome_valid
        CHECK (outcome IN ('success', 'failure'))
);

CREATE INDEX IF NOT EXISTS ix_audit_log_occurred_at   ON audit_log (occurred_at);
CREATE INDEX IF NOT EXISTS ix_audit_log_actor_user_id ON audit_log (actor_user_id);
CREATE INDEX IF NOT EXISTS ix_audit_log_action        ON audit_log (action);
CREATE INDEX IF NOT EXISTS ix_audit_log_entity
    ON audit_log (entity_type, entity_id);

-- =====================================================================
-- Migration 0002 — events, incidents, evidence, workflow executions
-- =====================================================================
--
-- Amendments to DATABASE_DESIGN.md sections 4-6 are recorded in DD-09:
-- outcomes follow the AccessEngine (allow/deny/hold, DD-01); security_events
-- stores every normalised pipeline event (the P2 audit trail); evidence is
-- referenced by a safe relative evidence_ref (P1), never an absolute path;
-- foreign keys into guarded tables use NO ACTION so history cannot be
-- rewritten through a cascade; append-only triggers are listed at the end.
--
-- permission_id, matched_embedding_id and automation_task_id have no foreign
-- key yet: permissions, face_embeddings and automation_tasks do not exist.

-- ---------------------------------------------------------------------
-- access_events — every AccessEngine decision (DATABASE_DESIGN.md 4.1)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_events (
    id                      INTEGER NOT NULL PRIMARY KEY,
    decision_id             TEXT    NOT NULL,             -- engine decision id
    request_id              TEXT    NOT NULL,
    occurred_at             DATETIME NOT NULL,            -- decided_at
    recorded_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    door_id                 TEXT    NOT NULL,
    source                  TEXT    NOT NULL,
    decision                TEXT    NOT NULL,
    rule_number             INTEGER NOT NULL,
    rule_name               TEXT    NOT NULL,
    reason_code             TEXT    NOT NULL,
    engine_version          TEXT    NOT NULL,
    family_member_id        INTEGER,                      -- NULL = unknown identity
    permission_id           INTEGER,                      -- FK when permissions exists
    matched_embedding_id    INTEGER,                      -- FK when face_embeddings exists
    match_confidence        REAL,
    threshold_used          REAL,
    review_of_decision_id   TEXT,                         -- HOLD this review resolves
    approver_user_id        INTEGER,
    camera_id               TEXT,
    correlation_id          TEXT    NOT NULL,
    decision_latency_ms     INTEGER,
    CONSTRAINT fk_access_events_family_member_id_family_members
        FOREIGN KEY (family_member_id) REFERENCES family_members (id),
    CONSTRAINT fk_access_events_approver_user_id_users
        FOREIGN KEY (approver_user_id) REFERENCES users (id),
    CONSTRAINT ck_access_events_decision_valid
        CHECK (decision IN ('allow', 'deny', 'hold')),
    CONSTRAINT ck_access_events_source_valid
        CHECK (source IN ('camera', 'admin_review', 'manual_override')),
    CONSTRAINT ck_access_events_rule_number_valid
        CHECK (rule_number >= 0),
    CONSTRAINT ck_access_events_review_link_only_for_reviews
        CHECK (source = 'admin_review' OR review_of_decision_id IS NULL),
    CONSTRAINT ck_access_events_review_never_holds
        CHECK (source <> 'admin_review' OR decision IN ('allow', 'deny')),
    CONSTRAINT ck_access_events_match_confidence_range
        CHECK (match_confidence IS NULL OR (match_confidence >= -1 AND match_confidence <= 1)),
    CONSTRAINT ck_access_events_threshold_range
        CHECK (threshold_used IS NULL OR (threshold_used > 0 AND threshold_used <= 1)),
    CONSTRAINT ck_access_events_latency_nonnegative
        CHECK (decision_latency_ms IS NULL OR decision_latency_ms >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_access_events_decision_id
    ON access_events (decision_id);
CREATE INDEX IF NOT EXISTS ix_access_events_occurred_at
    ON access_events (occurred_at);
CREATE INDEX IF NOT EXISTS ix_access_events_member_time
    ON access_events (family_member_id, occurred_at);
CREATE INDEX IF NOT EXISTS ix_access_events_decision
    ON access_events (decision);
CREATE INDEX IF NOT EXISTS ix_access_events_correlation_id
    ON access_events (correlation_id);

-- ---------------------------------------------------------------------
-- visitor_events — unrecognised-person encounters (DATABASE_DESIGN.md 4.2)
-- No member or user column: visitors are anonymous (SR-PRIV-01/02).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS visitor_events (
    id                      INTEGER NOT NULL PRIMARY KEY,
    occurred_at             DATETIME NOT NULL,
    recorded_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    camera_id               TEXT,
    access_event_id         INTEGER,
    visitor_cluster_key     TEXT,                         -- transient; cleared on purge
    sighting_count          INTEGER NOT NULL DEFAULT 1,
    dwell_seconds           INTEGER,
    face_count              INTEGER NOT NULL DEFAULT 1,
    snapshot_ref            TEXT,                         -- relative evidence_ref (P1)
    snapshot_sha256         TEXT,
    disposition             TEXT    NOT NULL DEFAULT 'unreviewed',
    retention_expires_at    DATETIME NOT NULL,
    purged_at               DATETIME,
    CONSTRAINT fk_visitor_events_access_event_id_access_events
        FOREIGN KEY (access_event_id) REFERENCES access_events (id),
    CONSTRAINT ck_visitor_events_disposition_valid
        CHECK (disposition IN ('unreviewed', 'benign', 'suspicious', 'promoted_to_member')),
    CONSTRAINT ck_visitor_events_sighting_count_positive
        CHECK (sighting_count >= 1),
    CONSTRAINT ck_visitor_events_face_count_positive
        CHECK (face_count >= 1),
    CONSTRAINT ck_visitor_events_dwell_nonnegative
        CHECK (dwell_seconds IS NULL OR dwell_seconds >= 0),
    CONSTRAINT ck_visitor_events_snapshot_ref_safe
        CHECK (snapshot_ref IS NULL OR (length(snapshot_ref) BETWEEN 1 AND 255 AND length(CAST(snapshot_ref AS BLOB)) = length(snapshot_ref) AND snapshot_ref NOT GLOB '*[^A-Za-z0-9._/-]*' AND substr(snapshot_ref, 1, 1) <> '/' AND substr(snapshot_ref, -1, 1) <> '/' AND instr(snapshot_ref, '//') = 0 AND snapshot_ref <> '..' AND substr(snapshot_ref, 1, 3) <> '../' AND substr(snapshot_ref, -3, 3) <> '/..' AND instr(snapshot_ref, '/../') = 0)),
    CONSTRAINT ck_visitor_events_snapshot_sha256_hex
        CHECK (snapshot_sha256 IS NULL OR (length(snapshot_sha256) = 64 AND snapshot_sha256 NOT GLOB '*[^0-9a-f]*')),
    CONSTRAINT ck_visitor_events_snapshot_hashed
        CHECK ((snapshot_ref IS NULL) = (snapshot_sha256 IS NULL)),
    CONSTRAINT ck_visitor_events_purge_complete
        CHECK (purged_at IS NULL OR (snapshot_ref IS NULL AND snapshot_sha256 IS NULL AND visitor_cluster_key IS NULL)),
    CONSTRAINT ck_visitor_events_retention_after_occurrence
        CHECK (retention_expires_at > occurred_at)
);

CREATE INDEX IF NOT EXISTS ix_visitor_events_occurred_at
    ON visitor_events (occurred_at);
CREATE INDEX IF NOT EXISTS ix_visitor_events_visitor_cluster_key
    ON visitor_events (visitor_cluster_key);
CREATE INDEX IF NOT EXISTS ix_visitor_events_retention_expires_at
    ON visitor_events (retention_expires_at);

-- ---------------------------------------------------------------------
-- incidents — investigation cases (DATABASE_DESIGN.md 5.1)
-- attack_chain is deterministic M15 output; ai_* columns are advisory and
-- can only be present when is_ai_enriched = 1 (SR-AI-14).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id                          INTEGER NOT NULL PRIMARY KEY,
    incident_uid                TEXT    NOT NULL,         -- M15 incident_id
    opened_at                   DATETIME NOT NULL,
    closed_at                   DATETIME,
    title                       TEXT    NOT NULL,
    category                    TEXT    NOT NULL,
    severity                    TEXT    NOT NULL,
    status                      TEXT    NOT NULL DEFAULT 'open',
    event_count                 INTEGER NOT NULL DEFAULT 0,
    first_event_at              DATETIME,
    last_event_at               DATETIME,
    notify_recommended          INTEGER NOT NULL DEFAULT 0,  -- deterministic M15 flag
    assigned_to_user_id         INTEGER,
    resolved_by_user_id         INTEGER,
    resolution_notes            TEXT,
    attack_chain                TEXT,
    attack_chain_generated_at   DATETIME,
    ai_summary                  TEXT,
    ai_recommendations          TEXT,
    ai_model_version            TEXT,
    ai_generated_at             DATETIME,
    is_ai_enriched              INTEGER NOT NULL DEFAULT 0,
    created_at                  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_incidents_assigned_to_user_id_users
        FOREIGN KEY (assigned_to_user_id) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_incidents_resolved_by_user_id_users
        FOREIGN KEY (resolved_by_user_id) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT ck_incidents_severity_valid
        CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    CONSTRAINT ck_incidents_status_valid
        CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
    CONSTRAINT ck_incidents_event_count_nonnegative
        CHECK (event_count >= 0),
    CONSTRAINT ck_incidents_notify_recommended_bool
        CHECK (notify_recommended IN (0, 1)),
    CONSTRAINT ck_incidents_is_ai_enriched_bool
        CHECK (is_ai_enriched IN (0, 1)),
    CONSTRAINT ck_incidents_closed_consistent
        CHECK ((status IN ('resolved', 'false_positive')) = (closed_at IS NOT NULL)),
    CONSTRAINT ck_incidents_window_ordered
        CHECK (first_event_at IS NULL OR last_event_at IS NULL OR first_event_at <= last_event_at),
    CONSTRAINT ck_incidents_attack_chain_json
        CHECK (attack_chain IS NULL OR json_valid(attack_chain)),
    CONSTRAINT ck_incidents_attack_chain_dated
        CHECK ((attack_chain IS NULL) = (attack_chain_generated_at IS NULL)),
    CONSTRAINT ck_incidents_ai_recommendations_json
        CHECK (ai_recommendations IS NULL OR json_valid(ai_recommendations)),
    CONSTRAINT ck_incidents_ai_content_labelled
        CHECK (is_ai_enriched = 1 OR (ai_summary IS NULL AND ai_recommendations IS NULL AND ai_model_version IS NULL AND ai_generated_at IS NULL)),
    CONSTRAINT ck_incidents_ai_provenance
        CHECK (is_ai_enriched = 0 OR (ai_summary IS NOT NULL AND ai_model_version IS NOT NULL AND ai_generated_at IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_incidents_incident_uid
    ON incidents (incident_uid);
CREATE INDEX IF NOT EXISTS ix_incidents_status
    ON incidents (status);
CREATE INDEX IF NOT EXISTS ix_incidents_severity
    ON incidents (severity);
CREATE INDEX IF NOT EXISTS ix_incidents_opened_at
    ON incidents (opened_at);

-- ---------------------------------------------------------------------
-- security_events — every normalised pipeline event, including each
-- failed login (P2), plus M13 detections (DATABASE_DESIGN.md 4.3, DD-09).
-- Values mirror app/domain/events.py; details are already redacted.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_events (
    id                      INTEGER NOT NULL PRIMARY KEY,
    event_uid               TEXT    NOT NULL,             -- SecurityEvent.event_id
    event_type              TEXT    NOT NULL,
    modality                TEXT    NOT NULL,
    severity                TEXT    NOT NULL,
    outcome                 TEXT    NOT NULL,
    suspicious              INTEGER NOT NULL DEFAULT 0,
    occurred_at             DATETIME NOT NULL,
    received_at             DATETIME NOT NULL,
    timestamp_assumed_utc   INTEGER NOT NULL DEFAULT 0,
    recorded_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source_module           TEXT    NOT NULL,
    detector_rule           TEXT,                         -- set by M13 detections
    confidence              REAL,
    family_member_id        INTEGER,
    user_id                 INTEGER,
    visitor_key             TEXT,                         -- transient; cleared on purge
    session_id              TEXT,
    request_id              TEXT,
    correlation_id          TEXT,
    ip_address              TEXT,
    door_id                 TEXT,
    camera_id               TEXT,
    decision_id             TEXT,
    evidence_ref            TEXT,
    incident_id             INTEGER,
    contributing_event_ids  TEXT,
    details                 TEXT    NOT NULL DEFAULT '{}',
    CONSTRAINT fk_security_events_family_member_id_family_members
        FOREIGN KEY (family_member_id) REFERENCES family_members (id),
    CONSTRAINT fk_security_events_user_id_users
        FOREIGN KEY (user_id) REFERENCES users (id),
    CONSTRAINT fk_security_events_incident_id_incidents
        FOREIGN KEY (incident_id) REFERENCES incidents (id),
    CONSTRAINT ck_security_events_event_uid_length
        CHECK (length(event_uid) BETWEEN 1 AND 128),
    CONSTRAINT ck_security_events_modality_valid
        CHECK (modality IN ('biometric', 'access', 'door', 'auth', 'api', 'admin', 'ai_agent', 'system', 'notification')),
    CONSTRAINT ck_security_events_severity_valid
        CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    CONSTRAINT ck_security_events_outcome_valid
        CHECK (outcome IN ('succeeded', 'blocked', 'failed', 'observed')),
    CONSTRAINT ck_security_events_suspicious_bool
        CHECK (suspicious IN (0, 1)),
    CONSTRAINT ck_security_events_timestamp_assumed_utc_bool
        CHECK (timestamp_assumed_utc IN (0, 1)),
    CONSTRAINT ck_security_events_confidence_range
        CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    CONSTRAINT ck_security_events_evidence_ref_safe
        CHECK (evidence_ref IS NULL OR (length(evidence_ref) BETWEEN 1 AND 255 AND length(CAST(evidence_ref AS BLOB)) = length(evidence_ref) AND evidence_ref NOT GLOB '*[^A-Za-z0-9._/-]*' AND substr(evidence_ref, 1, 1) <> '/' AND substr(evidence_ref, -1, 1) <> '/' AND instr(evidence_ref, '//') = 0 AND evidence_ref <> '..' AND substr(evidence_ref, 1, 3) <> '../' AND substr(evidence_ref, -3, 3) <> '/..' AND instr(evidence_ref, '/../') = 0)),
    CONSTRAINT ck_security_events_details_json
        CHECK (json_valid(details)),
    CONSTRAINT ck_security_events_contributing_json
        CHECK (contributing_event_ids IS NULL OR json_valid(contributing_event_ids))
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_security_events_event_uid
    ON security_events (event_uid);
CREATE INDEX IF NOT EXISTS ix_security_events_occurred_at
    ON security_events (occurred_at);
CREATE INDEX IF NOT EXISTS ix_security_events_severity
    ON security_events (severity);
CREATE INDEX IF NOT EXISTS ix_security_events_incident_id
    ON security_events (incident_id);
CREATE INDEX IF NOT EXISTS ix_security_events_event_type
    ON security_events (event_type);

-- ---------------------------------------------------------------------
-- incident_evidence (DATABASE_DESIGN.md 5.2, DD-09)
-- evidence_ref replaces file_path; incidents cannot be deleted, so evidence
-- cannot disappear through a cascade.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident_evidence (
    id                      INTEGER NOT NULL PRIMARY KEY,
    incident_id             INTEGER NOT NULL,
    evidence_type           TEXT    NOT NULL,
    evidence_ref            TEXT,
    content                 TEXT,
    sha256                  TEXT,
    byte_size               INTEGER,
    captured_at             DATETIME NOT NULL,
    source_module           TEXT    NOT NULL,
    retention_expires_at    DATETIME,
    purged_at               DATETIME,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_incident_evidence_incident_id_incidents
        FOREIGN KEY (incident_id) REFERENCES incidents (id),
    CONSTRAINT ck_incident_evidence_evidence_type_valid
        CHECK (evidence_type IN ('snapshot', 'clip', 'log_extract', 'event_export', 'note')),
    CONSTRAINT ck_incident_evidence_evidence_ref_safe
        CHECK (evidence_ref IS NULL OR (length(evidence_ref) BETWEEN 1 AND 255 AND length(CAST(evidence_ref AS BLOB)) = length(evidence_ref) AND evidence_ref NOT GLOB '*[^A-Za-z0-9._/-]*' AND substr(evidence_ref, 1, 1) <> '/' AND substr(evidence_ref, -1, 1) <> '/' AND instr(evidence_ref, '//') = 0 AND evidence_ref <> '..' AND substr(evidence_ref, 1, 3) <> '../' AND substr(evidence_ref, -3, 3) <> '/..' AND instr(evidence_ref, '/../') = 0)),
    CONSTRAINT ck_incident_evidence_sha256_hex
        CHECK (sha256 IS NULL OR (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*')),
    CONSTRAINT ck_incident_evidence_byte_size_nonnegative
        CHECK (byte_size IS NULL OR byte_size >= 0),
    CONSTRAINT ck_incident_evidence_file_hashed
        CHECK (evidence_ref IS NULL OR sha256 IS NOT NULL),
    CONSTRAINT ck_incident_evidence_has_payload
        CHECK (purged_at IS NOT NULL OR evidence_ref IS NOT NULL OR content IS NOT NULL),
    CONSTRAINT ck_incident_evidence_purge_complete
        CHECK (purged_at IS NULL OR (evidence_ref IS NULL AND content IS NULL))
);

CREATE INDEX IF NOT EXISTS ix_incident_evidence_incident_id
    ON incident_evidence (incident_id);
CREATE INDEX IF NOT EXISTS ix_incident_evidence_retention_expires_at
    ON incident_evidence (retention_expires_at);

-- ---------------------------------------------------------------------
-- workflow_executions — scheduled jobs and LangGraph runs (6.4, DD-09)
-- Written only by the non-AI recorder service (DD-08 decision 10).
-- run_uid is the opaque id the status API exposes.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS workflow_executions (
    id                      INTEGER NOT NULL PRIMARY KEY,
    run_uid                 TEXT    NOT NULL,
    execution_kind          TEXT    NOT NULL,
    workflow_name           TEXT,
    workflow_version        TEXT,
    automation_task_id      INTEGER,                      -- FK when automation_tasks exists
    incident_id             INTEGER,
    requested_by_user_id    INTEGER,
    trigger_source          TEXT    NOT NULL,
    status                  TEXT    NOT NULL DEFAULT 'running',
    started_at              DATETIME NOT NULL,
    finished_at             DATETIME,
    duration_ms             INTEGER,
    current_node            TEXT,
    steps                   TEXT,
    result_summary          TEXT,
    error_message           TEXT,
    tokens_used             INTEGER,
    CONSTRAINT fk_workflow_executions_incident_id_incidents
        FOREIGN KEY (incident_id) REFERENCES incidents (id),
    CONSTRAINT fk_workflow_executions_requested_by_user_id_users
        FOREIGN KEY (requested_by_user_id) REFERENCES users (id),
    CONSTRAINT ck_workflow_executions_execution_kind_valid
        CHECK (execution_kind IN ('scheduled_job', 'langgraph_workflow')),
    CONSTRAINT ck_workflow_executions_trigger_source_valid
        CHECK (trigger_source IN ('schedule', 'manual', 'event')),
    CONSTRAINT ck_workflow_executions_status_valid
        CHECK (status IN ('running', 'succeeded', 'failed', 'cancelled', 'timeout')),
    CONSTRAINT ck_workflow_executions_name_matches_kind
        CHECK ((execution_kind = 'langgraph_workflow') = (workflow_name IS NOT NULL)),
    CONSTRAINT ck_workflow_executions_task_only_for_jobs
        CHECK (execution_kind = 'scheduled_job' OR automation_task_id IS NULL),
    CONSTRAINT ck_workflow_executions_finished_consistent
        CHECK ((status = 'running') = (finished_at IS NULL)),
    CONSTRAINT ck_workflow_executions_duration_nonnegative
        CHECK (duration_ms IS NULL OR duration_ms >= 0),
    CONSTRAINT ck_workflow_executions_tokens_nonnegative
        CHECK (tokens_used IS NULL OR tokens_used >= 0),
    CONSTRAINT ck_workflow_executions_steps_json
        CHECK (steps IS NULL OR json_valid(steps))
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_workflow_executions_run_uid
    ON workflow_executions (run_uid);
CREATE INDEX IF NOT EXISTS ix_workflow_executions_kind_started
    ON workflow_executions (execution_kind, started_at);
CREATE INDEX IF NOT EXISTS ix_workflow_executions_automation_task_id
    ON workflow_executions (automation_task_id);
CREATE INDEX IF NOT EXISTS ix_workflow_executions_incident_id
    ON workflow_executions (incident_id);
CREATE INDEX IF NOT EXISTS ix_workflow_executions_status
    ON workflow_executions (status);
CREATE INDEX IF NOT EXISTS ix_workflow_executions_requested_by_user_id
    ON workflow_executions (requested_by_user_id);

-- ---------------------------------------------------------------------
-- Append-only guards (SR-AUDIT-06/07). Canonical text is generated by
-- app/database/append_only.py; tests check this copy matches it.
-- ---------------------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS trg_access_events_guard_update BEFORE UPDATE ON access_events
    FOR EACH ROW
    BEGIN SELECT RAISE(ABORT, 'access_events: update not permitted');
    END;

CREATE TRIGGER IF NOT EXISTS trg_access_events_no_delete BEFORE DELETE ON access_events
    FOR EACH ROW
    BEGIN SELECT RAISE(ABORT, 'access_events: delete not permitted');
    END;

CREATE TRIGGER IF NOT EXISTS trg_incident_evidence_guard_update BEFORE UPDATE ON incident_evidence
    FOR EACH ROW WHEN NEW.id IS NOT OLD.id
        OR NEW.incident_id IS NOT OLD.incident_id
        OR NEW.evidence_type IS NOT OLD.evidence_type
        OR NEW.sha256 IS NOT OLD.sha256
        OR NEW.byte_size IS NOT OLD.byte_size
        OR NEW.captured_at IS NOT OLD.captured_at
        OR NEW.source_module IS NOT OLD.source_module
        OR NEW.retention_expires_at IS NOT OLD.retention_expires_at
        OR NEW.created_at IS NOT OLD.created_at
        OR (NEW.evidence_ref IS NOT OLD.evidence_ref AND NEW.evidence_ref IS NOT NULL)
        OR (NEW.content IS NOT OLD.content AND NEW.content IS NOT NULL)
        OR (OLD.purged_at IS NOT NULL AND NEW.purged_at IS NOT OLD.purged_at)
    BEGIN SELECT RAISE(ABORT, 'incident_evidence: update not permitted');
    END;

CREATE TRIGGER IF NOT EXISTS trg_incident_evidence_no_delete BEFORE DELETE ON incident_evidence
    FOR EACH ROW
    BEGIN SELECT RAISE(ABORT, 'incident_evidence: delete not permitted');
    END;

CREATE TRIGGER IF NOT EXISTS trg_incidents_no_delete BEFORE DELETE ON incidents
    FOR EACH ROW
    BEGIN SELECT RAISE(ABORT, 'incidents: delete not permitted');
    END;

CREATE TRIGGER IF NOT EXISTS trg_security_events_guard_update BEFORE UPDATE ON security_events
    FOR EACH ROW WHEN NEW.id IS NOT OLD.id
        OR NEW.event_uid IS NOT OLD.event_uid
        OR NEW.event_type IS NOT OLD.event_type
        OR NEW.modality IS NOT OLD.modality
        OR NEW.severity IS NOT OLD.severity
        OR NEW.outcome IS NOT OLD.outcome
        OR NEW.suspicious IS NOT OLD.suspicious
        OR NEW.occurred_at IS NOT OLD.occurred_at
        OR NEW.received_at IS NOT OLD.received_at
        OR NEW.timestamp_assumed_utc IS NOT OLD.timestamp_assumed_utc
        OR NEW.recorded_at IS NOT OLD.recorded_at
        OR NEW.source_module IS NOT OLD.source_module
        OR NEW.detector_rule IS NOT OLD.detector_rule
        OR NEW.confidence IS NOT OLD.confidence
        OR NEW.family_member_id IS NOT OLD.family_member_id
        OR NEW.user_id IS NOT OLD.user_id
        OR NEW.session_id IS NOT OLD.session_id
        OR NEW.request_id IS NOT OLD.request_id
        OR NEW.correlation_id IS NOT OLD.correlation_id
        OR NEW.ip_address IS NOT OLD.ip_address
        OR NEW.door_id IS NOT OLD.door_id
        OR NEW.camera_id IS NOT OLD.camera_id
        OR NEW.decision_id IS NOT OLD.decision_id
        OR NEW.evidence_ref IS NOT OLD.evidence_ref
        OR NEW.contributing_event_ids IS NOT OLD.contributing_event_ids
        OR NEW.details IS NOT OLD.details
        OR (NEW.visitor_key IS NOT OLD.visitor_key AND NEW.visitor_key IS NOT NULL)
        OR (OLD.incident_id IS NOT NULL AND NEW.incident_id IS NOT OLD.incident_id)
    BEGIN SELECT RAISE(ABORT, 'security_events: update not permitted');
    END;

CREATE TRIGGER IF NOT EXISTS trg_security_events_no_delete BEFORE DELETE ON security_events
    FOR EACH ROW
    BEGIN SELECT RAISE(ABORT, 'security_events: delete not permitted');
    END;

CREATE TRIGGER IF NOT EXISTS trg_visitor_events_guard_update BEFORE UPDATE ON visitor_events
    FOR EACH ROW WHEN NEW.id IS NOT OLD.id
        OR NEW.occurred_at IS NOT OLD.occurred_at
        OR NEW.recorded_at IS NOT OLD.recorded_at
        OR NEW.camera_id IS NOT OLD.camera_id
        OR NEW.access_event_id IS NOT OLD.access_event_id
        OR NEW.sighting_count IS NOT OLD.sighting_count
        OR NEW.dwell_seconds IS NOT OLD.dwell_seconds
        OR NEW.face_count IS NOT OLD.face_count
        OR NEW.retention_expires_at IS NOT OLD.retention_expires_at
        OR (NEW.visitor_cluster_key IS NOT OLD.visitor_cluster_key AND NEW.visitor_cluster_key IS NOT NULL)
        OR (NEW.snapshot_ref IS NOT OLD.snapshot_ref AND NEW.snapshot_ref IS NOT NULL)
        OR (NEW.snapshot_sha256 IS NOT OLD.snapshot_sha256 AND NEW.snapshot_sha256 IS NOT NULL)
        OR (OLD.purged_at IS NOT NULL AND NEW.purged_at IS NOT OLD.purged_at)
    BEGIN SELECT RAISE(ABORT, 'visitor_events: update not permitted');
    END;

CREATE TRIGGER IF NOT EXISTS trg_visitor_events_no_delete BEFORE DELETE ON visitor_events
    FOR EACH ROW
    BEGIN SELECT RAISE(ABORT, 'visitor_events: delete not permitted');
    END;

CREATE TRIGGER IF NOT EXISTS trg_workflow_executions_guard_update BEFORE UPDATE ON workflow_executions
    FOR EACH ROW WHEN NEW.id IS NOT OLD.id
        OR NEW.run_uid IS NOT OLD.run_uid
        OR NEW.execution_kind IS NOT OLD.execution_kind
        OR NEW.workflow_name IS NOT OLD.workflow_name
        OR NEW.workflow_version IS NOT OLD.workflow_version
        OR NEW.automation_task_id IS NOT OLD.automation_task_id
        OR NEW.incident_id IS NOT OLD.incident_id
        OR NEW.requested_by_user_id IS NOT OLD.requested_by_user_id
        OR NEW.trigger_source IS NOT OLD.trigger_source
        OR NEW.started_at IS NOT OLD.started_at
        OR OLD.status <> 'running'
    BEGIN SELECT RAISE(ABORT, 'workflow_executions: update not permitted');
    END;

CREATE TRIGGER IF NOT EXISTS trg_workflow_executions_no_delete BEFORE DELETE ON workflow_executions
    FOR EACH ROW
    BEGIN SELECT RAISE(ABORT, 'workflow_executions: delete not permitted');
    END;

-- =====================================================================
-- Migration 0003 — retention extensions (DD-11)
-- =====================================================================
--
-- Original retention deadlines are never changed. An authorised admin
-- approves a separate, append-only extension record instead. The insert
-- trigger checks the record against the evidence, its incident, the approver
-- and the current effective deadline; a second trigger stops evidence from
-- being purged while an approved extension is still running.

CREATE TABLE IF NOT EXISTS retention_extensions (
    id                      INTEGER NOT NULL PRIMARY KEY,
    evidence_id             INTEGER NOT NULL,
    incident_id             INTEGER NOT NULL,
    requested_by_user_id    INTEGER NOT NULL,
    approved_by_user_id     INTEGER NOT NULL,
    reason                  TEXT    NOT NULL,
    original_deadline       DATETIME NOT NULL,            -- evidence.retention_expires_at
    previous_deadline       DATETIME NOT NULL,            -- effective deadline before this
    extended_deadline       DATETIME NOT NULL,
    requested_at            DATETIME NOT NULL,
    approved_at             DATETIME NOT NULL,
    recorded_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_retention_extensions_evidence_id_incident_evidence
        FOREIGN KEY (evidence_id) REFERENCES incident_evidence (id),
    CONSTRAINT fk_retention_extensions_incident_id_incidents
        FOREIGN KEY (incident_id) REFERENCES incidents (id),
    CONSTRAINT fk_retention_extensions_requested_by_user_id_users
        FOREIGN KEY (requested_by_user_id) REFERENCES users (id),
    CONSTRAINT fk_retention_extensions_approved_by_user_id_users
        FOREIGN KEY (approved_by_user_id) REFERENCES users (id),
    CONSTRAINT ck_retention_extensions_reason_length
        CHECK (length(trim(reason)) BETWEEN 10 AND 1000),
    CONSTRAINT ck_retention_extensions_extends_deadline
        CHECK (extended_deadline > previous_deadline),
    CONSTRAINT ck_retention_extensions_previous_not_before_original
        CHECK (previous_deadline >= original_deadline),
    CONSTRAINT ck_retention_extensions_approved_after_request
        CHECK (approved_at >= requested_at),
    CONSTRAINT ck_retention_extensions_approved_before_expiry
        CHECK (approved_at < previous_deadline),
    CONSTRAINT ck_retention_extensions_max_extension
        CHECK (julianday(extended_deadline) - julianday(previous_deadline) <= 365)
);

CREATE INDEX IF NOT EXISTS ix_retention_extensions_evidence_id
    ON retention_extensions (evidence_id);
CREATE INDEX IF NOT EXISTS ix_retention_extensions_incident_id
    ON retention_extensions (incident_id);

CREATE TRIGGER IF NOT EXISTS trg_retention_extensions_guard_update BEFORE UPDATE ON retention_extensions
    FOR EACH ROW
    BEGIN SELECT RAISE(ABORT, 'retention_extensions: update not permitted');
    END;

CREATE TRIGGER IF NOT EXISTS trg_retention_extensions_no_delete BEFORE DELETE ON retention_extensions
    FOR EACH ROW
    BEGIN SELECT RAISE(ABORT, 'retention_extensions: delete not permitted');
    END;

CREATE TRIGGER IF NOT EXISTS trg_retention_extensions_validate_insert BEFORE INSERT ON retention_extensions
    FOR EACH ROW WHEN NOT EXISTS (SELECT 1 FROM incident_evidence e JOIN incidents i ON i.id = e.incident_id WHERE e.id = NEW.evidence_id AND e.incident_id = NEW.incident_id AND e.purged_at IS NULL AND e.retention_expires_at = NEW.original_deadline AND i.status IN ('open', 'investigating'))
        OR NOT EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.approved_by_user_id AND u.role = 'admin' AND u.is_active = 1)
        OR NEW.previous_deadline IS NOT COALESCE((SELECT MAX(x.extended_deadline) FROM retention_extensions x WHERE x.evidence_id = NEW.evidence_id), NEW.original_deadline)
    BEGIN SELECT RAISE(ABORT, 'retention_extensions: extension not valid for this evidence');
    END;

CREATE TRIGGER IF NOT EXISTS trg_incident_evidence_respect_extensions BEFORE UPDATE OF purged_at ON incident_evidence
    FOR EACH ROW WHEN NEW.purged_at IS NOT NULL AND EXISTS (SELECT 1 FROM retention_extensions r WHERE r.evidence_id = NEW.id AND r.extended_deadline > NEW.purged_at)
    BEGIN SELECT RAISE(ABORT, 'incident_evidence: retention extended; purge not permitted');
    END;

-- =====================================================================
-- Migration 0004 — audit_log append-only (finding S4, SR-AUDIT-06/07)
-- =====================================================================
-- Audit entries cannot be edited or deleted, by anyone. The only permitted
-- change is actor_user_id becoming NULL, which ON DELETE SET NULL from users
-- performs; the entry itself, including actor_label, is preserved.

CREATE TRIGGER IF NOT EXISTS trg_audit_log_guard_update BEFORE UPDATE ON audit_log
    FOR EACH ROW WHEN NEW.id IS NOT OLD.id
        OR NEW.occurred_at IS NOT OLD.occurred_at
        OR NEW.actor_label IS NOT OLD.actor_label
        OR NEW.actor_ip IS NOT OLD.actor_ip
        OR NEW.action IS NOT OLD.action
        OR NEW.entity_type IS NOT OLD.entity_type
        OR NEW.entity_id IS NOT OLD.entity_id
        OR NEW.before_value IS NOT OLD.before_value
        OR NEW.after_value IS NOT OLD.after_value
        OR NEW.outcome IS NOT OLD.outcome
        OR NEW.correlation_id IS NOT OLD.correlation_id
        OR (NEW.actor_user_id IS NOT OLD.actor_user_id AND NEW.actor_user_id IS NOT NULL)
    BEGIN SELECT RAISE(ABORT, 'audit_log: update not permitted');
    END;

CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete BEFORE DELETE ON audit_log
    FOR EACH ROW
    BEGIN SELECT RAISE(ABORT, 'audit_log: delete not permitted');
    END;
