# DATABASE DESIGN

**Project:** AI-Powered Smart Home Security and Automated Access Management System
**Engine:** SQLite 3 (WAL journal mode) via SQLAlchemy 2.0, migrations by Alembic
**Version:** 1.0 (Day 1 design)
**Status:** Design only — no database file, no models and no migrations exist yet

---

## 1. Design Rules

1. **One table per concept, no duplicates.** Every table below was checked against the others for overlap; §8 records the duplicates that were considered and rejected, with reasons.
2. **Soft delete for people, never hard delete.** A historical access event must always resolve to a real person, so `family_members` and `users` deactivate rather than disappear.
3. **Events are append-only.** `access_events`, `security_events`, `visitor_events`, `pipeline_logs` and `audit_log` are never updated after insert. Mutable state lives in `incidents` and `notifications`.
4. **UTC in storage.** All timestamps are UTC ISO-8601. Local time appears only in permission windows, which carry an explicit timezone.
5. **Foreign keys enforced.** `PRAGMA foreign_keys = ON` on every connection — SQLite does not do this by default.
6. **Decisions are self-explaining.** Every `access_events` row stores the rule that fired and the engine version, so a decision can be explained years later without re-running code.
7. **Biometrics are minimised.** Embeddings, not images, and only for consenting enrolled members.

### 1.1 Type conventions

SQLite's dynamic typing is constrained deliberately: `INTEGER` primary keys, `TEXT` for ISO-8601 timestamps, `INTEGER` 0/1 for booleans, `TEXT` holding JSON for open-ended metadata, and `BLOB` for embedding vectors.

---

## 2. Entity Overview

Fourteen required tables plus one justified addition:

| # | Table | Kind | Purpose |
|---|---|---|---|
| 1 | `users` | Identity | Operator accounts that log into the system |
| 2 | `family_members` | Identity | People the system recognises at the door |
| 3 | `face_embeddings` | Biometric | Enrolled 512-D face vectors |
| 4 | `permissions` | Authorisation | Rules the AccessEngine evaluates |
| 5 | `sessions` | Identity | Server-side JWT refresh sessions |
| 6 | `access_events` | Event (append-only) | Every access decision, granted or denied |
| 7 | `visitor_events` | Event (append-only) | Unrecognised-person encounters |
| 8 | `security_events` | Event (append-only) | Detected suspicious patterns |
| 9 | `incidents` | Case (mutable) | Correlated groups of security events |
| 10 | `incident_evidence` | Case | Files and artefacts attached to an incident |
| 11 | `notifications` | Delivery | Outbound alerts and their delivery state |
| 12 | `pipeline_logs` | Observability (append-only) | Per-stage event-pipeline execution records |
| 13 | `automation_tasks` | Automation | Scheduled job definitions |
| 14 | `workflow_executions` | Automation (append-only) | Runs of scheduled jobs and LangGraph workflows |
| 15 | `audit_log` | Compliance (append-only) | Security-relevant configuration changes — **justified in §8.6** |

### 2.1 Relationships

```
users ──1:N──▶ sessions
users ──1:N──▶ notifications            (recipient)
users ──1:N──▶ permissions              (granted_by)
users ──1:N──▶ incidents                (assigned_to / resolved_by)
users ──1:N──▶ audit_log                (actor)

family_members ──1:N──▶ face_embeddings
family_members ──1:N──▶ permissions
family_members ──0:N──▶ access_events   (nullable — unknown attempts have no member)

access_events   ──0:N──▶ visitor_events  (an unknown denial spawns a visitor event)
access_events   ──0:N──▶ security_events (contributing evidence, via JSON id list)
visitor_events  ──0:N──▶ security_events

security_events ──N:1──▶ incidents
incidents       ──1:N──▶ incident_evidence
incidents       ──1:N──▶ notifications
incidents       ──1:N──▶ workflow_executions

automation_tasks ──1:N──▶ workflow_executions
```

---

## 3. Identity and Authorisation Tables

### 3.1 `users` — operator accounts

Who may *operate the system*. Distinct from `family_members`, who may *enter the door*. A household admin is typically both, represented by one row in each, linked by `family_members.user_id`.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK | |
| `email` | TEXT | NOT NULL, UNIQUE | Login identifier |
| `password_hash` | TEXT | NOT NULL | Argon2id — never a plaintext or reversible value |
| `full_name` | TEXT | NOT NULL | |
| `role` | TEXT | NOT NULL, CHECK in (`admin`,`member`,`viewer`) | RBAC source of truth |
| `is_active` | INTEGER | NOT NULL DEFAULT 1 | Soft deactivation |
| `failed_login_count` | INTEGER | NOT NULL DEFAULT 0 | Brute-force tracking |
| `locked_until` | TEXT | NULL | Progressive lockout expiry |
| `last_login_at` | TEXT | NULL | |
| `created_at` | TEXT | NOT NULL | |
| `updated_at` | TEXT | NOT NULL | |

Indexes: `UNIQUE(email)`.

### 3.2 `family_members` — recognised people

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK | |
| `user_id` | INTEGER | NULL, FK → `users.id` | Set only if this person also operates the system |
| `full_name` | TEXT | NOT NULL | |
| `relationship` | TEXT | NULL | e.g. parent, child, housekeeper |
| `member_type` | TEXT | NOT NULL, CHECK in (`family`,`resident`,`staff`,`recurring_visitor`) | |
| `status` | TEXT | NOT NULL, CHECK in (`active`,`inactive`,`revoked`) | **AccessEngine rule 4 reads this** |
| `enrollment_status` | TEXT | NOT NULL, CHECK in (`not_enrolled`,`enrolled`,`needs_reenrollment`) | Face-enrollment state |
| `notes` | TEXT | NULL | |
| `created_at` | TEXT | NOT NULL | |
| `updated_at` | TEXT | NOT NULL | |

Indexes: `idx_family_members_status(status)`.

Never hard-deleted: `revoked` members must remain resolvable from historical `access_events`.

### 3.3 `face_embeddings` — enrolled biometric vectors

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK | |
| `family_member_id` | INTEGER | NOT NULL, FK → `family_members.id` ON DELETE CASCADE | |
| `embedding` | BLOB | NOT NULL | float32 little-endian, L2-normalised |
| `dim` | INTEGER | NOT NULL DEFAULT 512 | Validated on read |
| `dtype` | TEXT | NOT NULL DEFAULT `float32` | Validated on read |
| `model_name` | TEXT | NOT NULL | e.g. `insightface_buffalo_l` |
| `model_version` | TEXT | NOT NULL | Mixing versions silently would corrupt matching |
| `quality_score` | REAL | NULL | Enrollment sample quality |
| `capture_context` | TEXT | NULL | e.g. frontal / low-light — aids diagnosis of match failures |
| `is_active` | INTEGER | NOT NULL DEFAULT 1 | Excluded from the match gallery when 0 |
| `created_at` | TEXT | NOT NULL | |

Indexes: `idx_face_embeddings_member(family_member_id)`, `idx_face_embeddings_active(is_active)`.

Design notes:
- Several rows per member (varied pose and lighting) is the intended pattern.
- `dim` + `dtype` + `model_version` together make a model change detectable instead of producing silently meaningless similarities.
- **Raw enrollment images are not stored.** An embedding is not reversible to a photograph, which materially reduces the harm of a database leak.
- **Unknown-visitor vectors never appear here.** They are transient and privacy-limited; see §4.2.

### 3.4 `permissions` — the rules M08 evaluates

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK | |
| `family_member_id` | INTEGER | NOT NULL, FK → `family_members.id` ON DELETE CASCADE | |
| `door_id` | TEXT | NOT NULL DEFAULT `main` | Virtual door identifier |
| `permission_type` | TEXT | NOT NULL, CHECK in (`permanent`,`temporary`,`scheduled`) | |
| `days_of_week` | TEXT | NULL | CSV `0`–`6`; NULL = all days |
| `start_time_local` | TEXT | NULL | `HH:MM`; NULL = no lower bound |
| `end_time_local` | TEXT | NULL | `HH:MM`; NULL = no upper bound |
| `timezone` | TEXT | NOT NULL DEFAULT `UTC` | Explicit, so DST is unambiguous |
| `valid_from` | TEXT | NULL | UTC |
| `valid_to` | TEXT | NULL | UTC; **rule 6** |
| `is_active` | INTEGER | NOT NULL DEFAULT 1 | Immediate revocation |
| `granted_by_user_id` | INTEGER | NULL, FK → `users.id` | Accountability |
| `created_at` | TEXT | NOT NULL | |
| `updated_at` | TEXT | NOT NULL | |

Indexes: `idx_permissions_member_door(family_member_id, door_id)`, `idx_permissions_active(is_active)`.

Every insert, update and revoke writes a paired `audit_log` row with before/after values. A silent permission change is indistinguishable from an attack, so it must be recorded.

### 3.5 `sessions` — server-side refresh sessions

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK | |
| `user_id` | INTEGER | NOT NULL, FK → `users.id` ON DELETE CASCADE | |
| `refresh_token_hash` | TEXT | NOT NULL, UNIQUE | **Hash only** — a stolen database must not yield usable tokens |
| `parent_session_id` | INTEGER | NULL, FK → `sessions.id` | Rotation lineage; enables reuse detection |
| `ip_address` | TEXT | NULL | |
| `user_agent` | TEXT | NULL | |
| `issued_at` | TEXT | NOT NULL | |
| `expires_at` | TEXT | NOT NULL | |
| `revoked_at` | TEXT | NULL | Non-null = unusable |
| `revoked_reason` | TEXT | NULL | e.g. `logout`, `rotation`, `reuse_detected`, `admin_revoke` |

Indexes: `UNIQUE(refresh_token_hash)`, `idx_sessions_user(user_id)`, `idx_sessions_expires(expires_at)`.

Rotation lineage lets M01 detect a replayed refresh token and revoke the whole family — the standard defence against refresh-token theft.

---

## 4. Event Tables (append-only)

### 4.1 `access_events` — every access decision

The system's most important table. One row per attempt, **granted or denied**.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK | |
| `occurred_at` | TEXT | NOT NULL | UTC |
| `door_id` | TEXT | NOT NULL | |
| `family_member_id` | INTEGER | NULL, FK → `family_members.id` | **NULL = unknown identity** |
| `decision` | TEXT | NOT NULL, CHECK in (`granted`,`denied`) | |
| `reason_code` | TEXT | NOT NULL | e.g. `permission_satisfied`, `no_permission`, `unknown_identity`, `engine_error` |
| `rule_number` | INTEGER | NOT NULL | Which ordered rule fired |
| `rule_name` | TEXT | NOT NULL | Human-readable rule name |
| `engine_version` | TEXT | NOT NULL | Reproducibility across engine changes |
| `match_confidence` | REAL | NULL | Cosine similarity; NULL when no face matched |
| `threshold_used` | REAL | NULL | The threshold in force at decision time |
| `matched_embedding_id` | INTEGER | NULL, FK → `face_embeddings.id` | |
| `permission_id` | INTEGER | NULL, FK → `permissions.id` | The permission relied upon, if any |
| `source` | TEXT | NOT NULL, CHECK in (`camera`,`manual_override`,`test`) | Manual overrides are rule-checked and recorded here too |
| `camera_id` | TEXT | NULL | |
| `correlation_id` | TEXT | NOT NULL | Threads this event through pipeline logs |
| `decision_latency_ms` | INTEGER | NULL | Measured, not assumed |

Indexes: `idx_access_events_time(occurred_at)`, `idx_access_events_member_time(family_member_id, occurred_at)`, `idx_access_events_decision(decision)`, `idx_access_events_corr(correlation_id)`.

`threshold_used` and `engine_version` are stored per row on purpose: when the threshold or the engine changes later, past decisions remain explainable under the rules that actually applied at the time.

### 4.2 `visitor_events` — unrecognised-person encounters

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK | |
| `occurred_at` | TEXT | NOT NULL | |
| `camera_id` | TEXT | NULL | |
| `access_event_id` | INTEGER | NULL, FK → `access_events.id` | The denial that created this |
| `visitor_cluster_key` | TEXT | NULL | Groups repeat sightings of one stranger |
| `sighting_count` | INTEGER | NOT NULL DEFAULT 1 | |
| `dwell_seconds` | INTEGER | NULL | Loitering signal |
| `snapshot_path` | TEXT | NULL | File on restricted-permission disk, not a BLOB |
| `snapshot_sha256` | TEXT | NULL | Integrity |
| `face_count` | INTEGER | NOT NULL DEFAULT 1 | Multiple unknown faces at once is an escalation signal |
| `disposition` | TEXT | NOT NULL, CHECK in (`unreviewed`,`benign`,`suspicious`,`promoted_to_member`) | |
| `retention_expires_at` | TEXT | NOT NULL | **Privacy deadline — purged by an M19 job** |
| `purged_at` | TEXT | NULL | Proof the purge ran |

Indexes: `idx_visitor_events_time(occurred_at)`, `idx_visitor_events_cluster(visitor_cluster_key)`, `idx_visitor_events_retention(retention_expires_at)`.

Privacy design: an unknown visitor has given no consent to biometric enrolment, so **no row is ever written to `face_embeddings` for them.** The cluster key is a transient grouping handle held in memory and discarded with the retention sweep. `retention_expires_at` and `purged_at` make the privacy promise auditable rather than aspirational.

### 4.3 `security_events` — detected suspicious patterns

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK | |
| `detected_at` | TEXT | NOT NULL | |
| `event_type` | TEXT | NOT NULL | e.g. `repeated_denial`, `brute_force_login`, `camera_offline`, `unknown_face_quiet_hours`, `impossible_travel`, `invalid_unlock_attempt` |
| `severity` | TEXT | NOT NULL, CHECK in (`info`,`low`,`medium`,`high`,`critical`) | |
| `detector_rule` | TEXT | NOT NULL | Names the rule that fired — explainability |
| `confidence` | REAL | NULL | |
| `family_member_id` | INTEGER | NULL, FK → `family_members.id` | |
| `camera_id` | TEXT | NULL | |
| `source_ip` | TEXT | NULL | For auth-originated events |
| `incident_id` | INTEGER | NULL, FK → `incidents.id` | Set when correlated |
| `contributing_event_ids` | TEXT | NULL | JSON, e.g. `{"access_events":[1,2],"visitor_events":[7]}` |
| `details` | TEXT | NULL | JSON |
| `correlation_id` | TEXT | NULL | |

Indexes: `idx_security_events_time(detected_at)`, `idx_security_events_severity(severity)`, `idx_security_events_incident(incident_id)`, `idx_security_events_type(event_type)`.

`contributing_event_ids` as JSON avoids three separate polymorphic join tables for a relationship that is only ever read as a whole, which is the pragmatic choice at household scale.

---

## 5. Incident Tables

### 5.1 `incidents` — mutable investigation cases

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK | |
| `opened_at` | TEXT | NOT NULL | |
| `closed_at` | TEXT | NULL | |
| `title` | TEXT | NOT NULL | |
| `category` | TEXT | NOT NULL | e.g. `intrusion_attempt`, `credential_attack`, `tamper`, `anomaly` |
| `severity` | TEXT | NOT NULL, CHECK in (`low`,`medium`,`high`,`critical`) | Escalates as events attach |
| `status` | TEXT | NOT NULL, CHECK in (`open`,`investigating`,`resolved`,`false_positive`) | |
| `event_count` | INTEGER | NOT NULL DEFAULT 0 | Denormalised for list views |
| `first_event_at` | TEXT | NULL | Chain window start |
| `last_event_at` | TEXT | NULL | Chain window end |
| `assigned_to_user_id` | INTEGER | NULL, FK → `users.id` | |
| `resolved_by_user_id` | INTEGER | NULL, FK → `users.id` | |
| `resolution_notes` | TEXT | NULL | Human-authored |
| `attack_chain` | TEXT | NULL | JSON — **deterministic** M15 output |
| `attack_chain_generated_at` | TEXT | NULL | |
| `ai_summary` | TEXT | NULL | **Gemini-generated narrative** |
| `ai_recommendations` | TEXT | NULL | JSON; advisory only |
| `ai_model_version` | TEXT | NULL | |
| `ai_generated_at` | TEXT | NULL | |
| `is_ai_enriched` | INTEGER | NOT NULL DEFAULT 0 | UI marks these as advisory |

Indexes: `idx_incidents_status(status)`, `idx_incidents_severity(severity)`, `idx_incidents_opened(opened_at)`.

The separation of `attack_chain` from `ai_summary` is deliberate and load-bearing: the chain is reproducible fact from M15, the summary is model prose from M16. Keeping them in distinct columns with distinct provenance timestamps means an operator can always tell which parts of an incident are verifiable and which are generated. `is_ai_enriched` drives the advisory labelling required by `SECURITY_REQUIREMENTS.md` §6.

### 5.2 `incident_evidence`

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK | |
| `incident_id` | INTEGER | NOT NULL, FK → `incidents.id` ON DELETE CASCADE | |
| `evidence_type` | TEXT | NOT NULL, CHECK in (`snapshot`,`clip`,`log_extract`,`event_export`,`note`) | |
| `file_path` | TEXT | NULL | Outside the web root; NULL for inline notes |
| `content` | TEXT | NULL | Inline text evidence |
| `sha256` | TEXT | NULL | **Computed at capture — later tampering is detectable** |
| `byte_size` | INTEGER | NULL | |
| `captured_at` | TEXT | NOT NULL | |
| `source_module` | TEXT | NOT NULL | Provenance, e.g. `M10`, `M14` |
| `retention_expires_at` | TEXT | NULL | |
| `purged_at` | TEXT | NULL | |

Indexes: `idx_incident_evidence_incident(incident_id)`, `idx_incident_evidence_retention(retention_expires_at)`.

Files are referenced by path, not stored as BLOBs: it keeps the database small and backups fast, and lets filesystem permissions carry part of the access control. The hash is what makes a path-based reference trustworthy.

---

## 6. Operations Tables

### 6.1 `notifications`

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK | |
| `created_at` | TEXT | NOT NULL | |
| `recipient_user_id` | INTEGER | NOT NULL, FK → `users.id` | |
| `channel` | TEXT | NOT NULL, CHECK in (`email`,`websocket`,`push`,`sms`) | |
| `severity` | TEXT | NOT NULL | Drives quiet-hour suppression |
| `subject` | TEXT | NOT NULL | |
| `body` | TEXT | NOT NULL | **Never contains face images or embeddings** |
| `incident_id` | INTEGER | NULL, FK → `incidents.id` | |
| `security_event_id` | INTEGER | NULL, FK → `security_events.id` | |
| `dedupe_key` | TEXT | NULL | Collapses alert storms |
| `status` | TEXT | NOT NULL, CHECK in (`queued`,`sent`,`failed`,`suppressed`,`read`) | |
| `attempt_count` | INTEGER | NOT NULL DEFAULT 0 | |
| `last_attempt_at` | TEXT | NULL | |
| `sent_at` | TEXT | NULL | |
| `error_message` | TEXT | NULL | |

Indexes: `idx_notifications_recipient_status(recipient_user_id, status)`, `idx_notifications_dedupe(dedupe_key)`, `idx_notifications_created(created_at)`.

### 6.2 `pipeline_logs`

One row per **stage** per event, which is what makes a stalled or failing pipeline diagnosable.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK | |
| `correlation_id` | TEXT | NOT NULL | Joins to `access_events.correlation_id` |
| `event_kind` | TEXT | NOT NULL | e.g. `access`, `visitor`, `auth`, `door` |
| `source_event_id` | INTEGER | NULL | Id within its own table |
| `stage` | TEXT | NOT NULL, CHECK in (`validate`,`enrich`,`persist`,`detect`,`correlate`,`dispatch`) | |
| `status` | TEXT | NOT NULL, CHECK in (`started`,`completed`,`failed`,`skipped`) | |
| `started_at` | TEXT | NOT NULL | |
| `duration_ms` | INTEGER | NULL | |
| `error_message` | TEXT | NULL | |
| `queue_depth` | INTEGER | NULL | Backpressure visibility |

Indexes: `idx_pipeline_logs_corr(correlation_id)`, `idx_pipeline_logs_started(started_at)`, `idx_pipeline_logs_status(status)`.

High-volume table. An M19 retention job trims it on a schedule.

### 6.3 `automation_tasks`

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK | |
| `name` | TEXT | NOT NULL, UNIQUE | |
| `description` | TEXT | NULL | |
| `job_callable` | TEXT | NOT NULL | Registry key — **not** an eval'd expression; see note |
| `trigger_type` | TEXT | NOT NULL, CHECK in (`cron`,`interval`,`date`) | |
| `trigger_config` | TEXT | NOT NULL | JSON APScheduler args |
| `parameters` | TEXT | NULL | JSON |
| `is_enabled` | INTEGER | NOT NULL DEFAULT 1 | |
| `last_run_at` | TEXT | NULL | |
| `last_status` | TEXT | NULL | |
| `next_run_at` | TEXT | NULL | |
| `created_at` | TEXT | NOT NULL | |
| `updated_at` | TEXT | NOT NULL | |

Indexes: `UNIQUE(name)`, `idx_automation_tasks_enabled(is_enabled)`.

`job_callable` is resolved against a **fixed in-code registry of allowed functions**. It is never imported dynamically or evaluated, because a database-driven import path would turn any write access to this table into remote code execution. No registered job is permitted to unlock the door (`MODULE_DESIGN.md` M19).

### 6.4 `workflow_executions`

Covers both APScheduler job runs and LangGraph workflow runs. One table, because both are "an orchestrated run with a status, a timeline and step records" — see §8.5 for why they are not split.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK | |
| `execution_kind` | TEXT | NOT NULL, CHECK in (`scheduled_job`,`langgraph_workflow`) | Discriminator |
| `automation_task_id` | INTEGER | NULL, FK → `automation_tasks.id` | Set for scheduled jobs |
| `workflow_name` | TEXT | NULL | Set for LangGraph runs |
| `incident_id` | INTEGER | NULL, FK → `incidents.id` | Subject, when analysing an incident |
| `trigger_source` | TEXT | NOT NULL, CHECK in (`schedule`,`manual`,`event`) | |
| `status` | TEXT | NOT NULL, CHECK in (`running`,`succeeded`,`failed`,`cancelled`,`timeout`) | |
| `started_at` | TEXT | NOT NULL | |
| `finished_at` | TEXT | NULL | |
| `duration_ms` | INTEGER | NULL | |
| `steps` | TEXT | NULL | JSON node/step transition trace |
| `current_node` | TEXT | NULL | Last node reached — pinpoints failures |
| `result_summary` | TEXT | NULL | |
| `error_message` | TEXT | NULL | |
| `tokens_used` | INTEGER | NULL | Gemini cost tracking |

Indexes: `idx_workflow_exec_kind_started(execution_kind, started_at)`, `idx_workflow_exec_task(automation_task_id)`, `idx_workflow_exec_incident(incident_id)`, `idx_workflow_exec_status(status)`.

---

## 7. `audit_log` — security-relevant configuration changes

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK | |
| `occurred_at` | TEXT | NOT NULL | |
| `actor_user_id` | INTEGER | NULL, FK → `users.id` | NULL for system actions |
| `actor_ip` | TEXT | NULL | |
| `action` | TEXT | NOT NULL | e.g. `permission.create`, `member.revoke`, `policy.threshold_change`, `lockdown.enable`, `login.failure`, `evidence.view` |
| `entity_type` | TEXT | NOT NULL | |
| `entity_id` | TEXT | NULL | |
| `before_value` | TEXT | NULL | JSON |
| `after_value` | TEXT | NULL | JSON |
| `outcome` | TEXT | NOT NULL, CHECK in (`success`,`failure`) | |
| `correlation_id` | TEXT | NULL | |

Indexes: `idx_audit_log_time(occurred_at)`, `idx_audit_log_actor(actor_user_id)`, `idx_audit_log_action(action)`, `idx_audit_log_entity(entity_type, entity_id)`.

---

## 8. Duplicate Analysis — tables deliberately NOT created

Task 6 asks that unnecessary duplicate tables be avoided. Each candidate below was considered and rejected.

### 8.1 Rejected: separate `visitors` table alongside `visitor_events`

A persistent visitor identity record would be a near-copy of `family_members` and, worse, would create a durable biometric profile of people who never consented. `visitor_cluster_key` on `visitor_events` provides the grouping needed for repeat-visitor detection without persisting an identity. When a visitor *should* become persistent, the operator promotes them into `family_members` — one path, no duplication.

### 8.2 Rejected: separate `auth_events` / `login_attempts` table

Failed logins are already covered twice over: `audit_log` records every attempt with actor and outcome, and `security_events` records the detected brute-force *pattern*. A third table would hold the same facts with no additional query.

### 8.3 Rejected: separate `door_events` table

A door transition is either the consequence of a decision (already in `access_events`, which records grant/deny and the rule) or an anomaly such as an invalid unlock attempt (already in `security_events`). A dedicated table would duplicate both.

### 8.4 Rejected: separate `ai_analyses` table

AI output is a 1:1 attribute of an incident, so it lives in `incidents` as `ai_summary`, `ai_recommendations`, `ai_model_version` and `is_ai_enriched`. A side table would add a join to every incident read for no gain. Should multi-version analysis history ever be required, this is the one table that would be worth splitting out.

### 8.5 Rejected: separate `scheduled_runs` and `langgraph_runs` tables

Both record an orchestrated run with status, timing, a step trace and an error. The columns overlap almost entirely, and operators want one unified "what ran recently" view. `workflow_executions` uses an `execution_kind` discriminator instead, with nullable `automation_task_id` and `workflow_name` for the kind-specific links.

### 8.6 **Accepted addition: `audit_log` — and why it is not a duplicate of `pipeline_logs` or `security_events`**

This is the one table beyond the fourteen named in Task 6, so its justification is explicit:

| Table | Records | Written by | Answers |
|---|---|---|---|
| `pipeline_logs` | Technical stage execution of event processing | M11 | "Did the pipeline run, and how fast?" |
| `security_events` | Detected suspicious *patterns* | M13 | "What looked like an attack?" |
| `audit_log` | **Deliberate human/system changes to security configuration, with before/after values** | M01, M02, M07, M09, API | **"Who changed the rules, when, and from what to what?"** |

No existing table answers the third question. `SECURITY_REQUIREMENTS.md` §7 requires that permission grants, member revocations, threshold changes, lockdown toggles and evidence views be attributable. Without `audit_log`, an attacker with admin access could widen a permission and the only trace would be the new value, with no record of the old one or of who changed it. That is the gap this table closes, and it overlaps with nothing above.

---

## 9. Integrity, Performance and Retention

### 9.1 Query patterns the indexes serve

| Pattern | Index |
|---|---|
| AccessEngine permission lookup (hot path, every attempt) | `idx_permissions_member_door` |
| Build the match gallery at startup | `idx_face_embeddings_active` |
| Access log, newest first | `idx_access_events_time` |
| One member's access history | `idx_access_events_member_time` |
| Open incidents by severity | `idx_incidents_status`, `idx_incidents_severity` |
| Trace one event end-to-end | `idx_pipeline_logs_corr` + `idx_access_events_corr` |
| Retention sweeps | `idx_visitor_events_retention`, `idx_incident_evidence_retention` |

Face matching does **not** query the database per frame: the gallery is loaded into memory at startup and invalidated on enrollment change (`MODULE_DESIGN.md` M06).

### 9.2 SQLite specifics

WAL journal mode for concurrent readers with the single writer; `foreign_keys = ON` per connection; `busy_timeout` set to absorb brief writer contention; short transactions; all writes serialised through the single pipeline consumer. Per `SYSTEM_ARCHITECTURE.md` §10 A1, write contention is the main scaling limit and is accepted at household scale.

### 9.3 Retention

| Data | Retention | Enforced by |
|---|---|---|
| Unknown-visitor snapshots and cluster keys | Short, privacy-driven | M19 purge job via `retention_expires_at`; `purged_at` proves it ran |
| Incident evidence | Longer, case-driven | M19 sweep, blocked while an incident is open |
| `pipeline_logs` | Short (high volume) | M19 trim job |
| `access_events`, `security_events`, `audit_log` | **Long — security record** | Not auto-purged |
| `face_embeddings` | Life of the member's active status | Cascade on member delete; deactivation on revoke |

### 9.4 Migration policy

Alembic from the first model. Every change is a reversible migration. No destructive column drop on event or audit tables without an explicit, reviewed data-preservation step.

---

## 10. Status

**Nothing in this document is implemented.** There is no `.db` file, no SQLAlchemy model, no Alembic environment and no migration. No query in §9.1 has been executed or profiled, so every performance statement is design intent, not measurement. Implementation begins on **Day 2**.
