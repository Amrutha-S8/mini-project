# Design Decisions (owner-approved, post Day 1)

Decisions made after the Day 1 documents were frozen. The Day 1 documents are
left unchanged so their backup checksums stay valid; where a decision here
differs from them, **this file takes precedence**.

## DD-01 — Access outcomes: ALLOW, DENY, HOLD (applies from Day 4)

The AccessEngine returns one of three outcomes. It remains the **only**
component that can produce any of them.

| Outcome | Door | Next step |
|---|---|---|
| `ALLOW` | Unlocks for the time-bounded TTL, then relocks | None |
| `DENY` | Stays LOCKED | None |
| `HOLD` | **Stays LOCKED** | A pending review is created for an authenticated admin |

Rules:

1. HOLD never opens the door. To the virtual door it is the same as DENY.
2. An admin reviews a HOLD through an authenticated, admin-only endpoint.
3. The admin's choice does **not** act on the door directly. It is submitted to
   the AccessEngine as a new attempt with `source = admin_review`, which links
   to the original HOLD. The engine re-runs its rules, including lockdown,
   member status and permission expiry, and issues the final ALLOW or DENY.
   An admin approval therefore cannot bypass a lockdown or a revoked member.
4. A HOLD expires after a configured window. An expired HOLD resolves to DENY.
5. Every step is audited: the original HOLD decision, the admin's review
   (actor, IP, choice) and the engine's final decision.
6. No AI component can create, approve or reject a HOLD. AI may only describe
   one in read-only, advisory text.

Which conditions produce HOLD rather than DENY (for example a known member
outside their time window) is decided on Day 4, when the rule table is
implemented. Unknown visitors are never auto-enrolled, so HOLD for an unknown
face only asks an admin about one entry; it does not add the person to
`face_embeddings`.

Schema impact (Day 4): `access_events.decision` gains `hold`; a review table
or columns link a review to its HOLD event. Delivered as a new Alembic
migration (0002 or later), not by editing 0001.

## DD-02 — First admin and registration (implemented Day 2B)

- The first admin is created with `python -m app.cli create-admin`. It refuses
  if any admin already exists. The password is prompted twice or read from
  stdin; it is never a command-line argument.
- `POST /api/v1/auth/register` is admin-only. The admin chooses the role
  (default `viewer`), and the audit entry records the issuing admin as actor.
- This closes the gap with SR-AUTHZ-01, which exempts only login, refresh and
  health from authentication.

## DD-03 — Persistence

Synchronous SQLAlchemy 2.0 on SQLite is confirmed. AI and agent data access
stays read-only by default (the `mode=ro` engine).

## DD-04 — InsightFace weights

The pretrained model licence must be read from the source before any weights
are downloaded or used. The MIT licence on the code does not cover the weights.

## DD-05 — Signing secret, login throttling and lockout model (implemented)

- `SECRET_KEY` is required in **every** environment. Empty, placeholder, short
  (< 32 chars) and low-variety values are rejected at startup, and the rejected
  value is never echoed (`hide_input_in_errors`, `repr=False`).
- Every login failure (unknown email, wrong password, locked, inactive) returns
  the same `401 invalid_credentials` after the same Argon2id work. The real
  reason goes to the audit log only.
- Accounts are **never locked automatically**. Throttling is in memory, per
  process:
  - 20 login attempts / 5 min per client IP
  - 5 failed logins / 15 min per (client IP, submitted email)
  - 60 refreshes / 5 min per client IP
  - Response: `429 rate_limited` with `Retry-After`, identical for existing and
    non-existent emails.
- `failed_login_count` is still recorded. `locked_until` is kept for a future
  admin-initiated lock and is still enforced.

Trade-offs accepted: state resets on restart (single worker); the client IP is
the socket peer, so a reverse proxy would need trusted-proxy handling; an
attacker behind the admin's own NAT can delay the admin for 15 minutes; there
is no per-account cap across many IPs, by design, because that cap is what
enables deliberate administrator lockout.

Also: security headers middleware (nosniff, frame DENY, no-referrer, COOP,
Permissions-Policy, deny-all CSP except `/docs`, `no-store` on `/api/`, HSTS in
production only), CORS without credentials and with validated origins, and the
standard error envelope for framework 404/405 errors.

## DD-06 — Deterministic core as a pure-Python package (implemented)

`backend/app/domain/` holds the security core: face matching over precomputed
embeddings, the AccessEngine, the virtual door, event normalisation, the event
pipeline and attack-chain reconstruction. It imports only the standard library
and itself (enforced by `tests/test_import_boundary.py`, with a negative
control). Time is always passed in. FastAPI, SQLAlchemy, OpenCV and the
recogniser wrap this core; they never re-implement its rules.

AccessEngine rule order (first match wins; any exception => DENY engine_error):

| # | Camera rule | Outcome |
|---|---|---|
| 1 | Lockdown | DENY |
| 2 | No face / multiple faces / poor quality | DENY / HOLD / HOLD |
| 3 | Ambiguous match; score just below threshold (hold band); unknown | HOLD / HOLD / policy (DENY default) |
| 4 | Member missing, inactive or revoked | DENY |
| 5 | No active permission for this door | DENY |
| 6 | Permission not yet valid or expired | DENY |
| 7 | Outside the permission's local time window | policy (HOLD default) |
| 8 | Attempt rate limit | DENY |
| 9 | All checks pass | ALLOW |

- The engine re-checks the match score against its own threshold.
- Policy can never be configured to ALLOW unknown visitors or out-of-window
  attempts (rejected at construction).
- Decisions are HMAC-SHA256 signed. The door verifies the signature, the door
  id, freshness (10 s) and single use before unlocking.
- Admin review of a HOLD re-runs lockdown, approver, HOLD validity (signed,
  same door, unresolved, unexpired), member status and permission validity.
  Only the time window is waived. Approving an unknown visitor's HOLD allows a
  single guest entry and enrolls nothing.
- Manual override requires an active admin and is blocked by lockdown.

## DD-07 — Unknown visitors default to DENY (configurable to HOLD)

`Policy.unknown_visitor_outcome` defaults to DENY so the system does not
create a review request for every passer-by. A household can switch it to
HOLD. ALLOW is impossible by construction.

## DD-08 — AI layer decisions (owner-approved 2026-11-15)

Approved after the read-only AI architecture audit. Where these differ from
`SYSTEM_ARCHITECTURE.md`, `MODULE_DESIGN.md` or `SECURITY_REQUIREMENTS.md`,
this entry takes precedence.

1. **SDK.** Gemini is reached through the Google GenAI SDK via
   `langchain-google-genai` 4.0 or later. The end-of-life
   `google-generativeai` package is not used.
2. **Agent tools.** "Tools" are allowlisted, read-only Python functions that
   LangGraph nodes call in code. Gemini receives no tool declarations and no
   function calling, and structured output must not use LangChain's
   function-calling mode (SR-AI-07 unchanged).
3. **Lockdown.** Agents may analyse incidents and *recommend* lockdown. They
   cannot execute lockdown or change any security setting. This replaces the
   M18 statement that a workflow may request lockdown, and narrows SR-AI-17:
   lockdown is triggered only by deterministic detection or an authenticated
   admin, never by AI output.
4. **Source tables.** Built in migration 0002 (DD-09). SQLite stays the
   operational source of truth; ChromaDB never replaces it.
5. **Retrieval permissions.**

   | Role | May retrieve |
   |---|---|
   | `admin` | All authorised household records |
   | `viewer` | Documentation, policies, security summaries and incident reports. No private visitor history, no individual member records |
   | `member` | Documentation, policies, and only their own access records |

   Enforced before retrieval (vector-store filter), after retrieval (each
   chunk re-checked) and against the SQLite source row.
6. **Embeddings.** A local Sentence Transformers model. Private visitor
   records, biometric data and household security events are never sent to
   Google's embedding API. Gemini remains the main LLM. The model, its
   licence and hardware needs are documented before it is selected.
   *Open point:* RAG answer generation sends the retrieved, redacted context
   to Gemini. This decision covers embeddings only; what generation may send
   needs an explicit owner rule before the Gemini adapter is built.
7. **Kill switch.** `AI_ENABLED=false` by default until checks V2–V5 are
   implemented, tested and recorded and the required live checks pass.
8. **Import tests.** The broad "no AI package anywhere" test is replaced by
   AI-package boundary checks and transitive isolation checks: AI code must not
   reach the AccessEngine, the virtual door or the database writer session.
9. **Adapters.** The standard-library AI core is built and tested first. The
   Gemini, LangChain, ChromaDB and LangGraph adapters are written only after
   package access returns and current package documentation is checked.
10. **Workflow status.** A separate non-AI recorder service writes
    `workflow_executions` and the advisory `incidents.ai_*` columns. The AI
    tier never receives a writer session.

## DD-09 — Migration 0002: events, incidents, evidence, workflows

Six tables from `DATABASE_DESIGN.md` §4–6 are built: `access_events`,
`visitor_events`, `security_events`, `incidents`, `incident_evidence`,
`workflow_executions`. Canonical models live in `app/models/`; the migration
is `alembic/versions/0002_events_incidents_workflows.py`; the reference DDL is
`app/database/schema_reference.sql`.

**Status.** The reference DDL is executed and tested with stdlib `sqlite3`.
The models and the migration are compared with it statically (columns,
defaults, indexes, foreign keys, CHECK constraints, triggers). **Neither has
been run**, because SQLAlchemy and Alembic are not installed.

Amendments to `DATABASE_DESIGN.md`:

| Table | Change | Reason |
|---|---|---|
| `access_events` | `decision` is `allow`/`deny`/`hold`; `source` is `camera`/`admin_review`/`manual_override` | Same values as the AccessEngine (DD-01); `test` is not an engine source |
| `access_events` | Added `decision_id` (unique), `request_id`, `recorded_at`, `review_of_decision_id`, `approver_user_id` | A stored row must fully explain the decision, including HOLD reviews |
| `access_events` | `permission_id`, `matched_embedding_id` without foreign keys | `permissions` and `face_embeddings` do not exist yet |
| `visitor_events` | `snapshot_path` → `snapshot_ref`; a snapshot requires a hash; a purge must clear key and snapshot | P1; SR-STORE-11; SR-PRIV-04 |
| `security_events` | Stores every normalised pipeline event, not only M13 detections. Added `event_uid` (unique), `modality`, `outcome`, `suspicious`, `received_at`, `timestamp_assumed_utc`, `source_module`, `user_id`, `visitor_key`, `session_id`, `request_id`, `door_id`, `decision_id`, `evidence_ref`. `detected_at` → `occurred_at`, `source_ip` → `ip_address`, `detector_rule` nullable | Every failed login must be a stored row (P2); the attack-chain core reads these fields |
| `incidents` | Added `incident_uid` (unique), `notify_recommended`; severity also allows `info` | Idempotent storage of M15 output, whose severity can be `info` |
| `incidents` | AI columns allowed only with `is_ai_enriched = 1`, a model version and a timestamp | SR-AI-14, enforced by CHECK |
| `incident_evidence` | `file_path` → `evidence_ref`; no cascade delete | P1, SR-STORE-12; evidence cannot vanish with its incident |
| `workflow_executions` | Added `run_uid` (unique, opaque), `workflow_version`, `requested_by_user_id`; `automation_task_id` without foreign key | Status API shows a run only to its requester or an admin, without guessable ids |
| All six | Foreign keys into these tables use NO ACTION | A cascade would rewrite history |

**Append-only triggers** (`app/database/append_only.py` is the canonical
text):

| Table | UPDATE allowed | DELETE |
|---|---|---|
| `access_events` | Never | Never |
| `security_events` | Set `incident_id` once; clear `visitor_key` (purge) | Never |
| `visitor_events` | Change `disposition`; clear key, snapshot ref and hash; set `purged_at` once | Never |
| `incident_evidence` | Clear `evidence_ref`/`content`; set `purged_at` once | Never |
| `incidents` | Allowed (cases are mutable) | Never |
| `workflow_executions` | Progress columns while `running`; frozen afterwards | Never |

Known limits:

- The database check on evidence references is a backstop. It rejects
  traversal, absolute paths, `//`, backslashes, colons, non-ASCII and NUL. It
  does not reject Windows device names, `.` components or leading dots or
  dashes, so `validate_evidence_ref` must run before every insert.
- SQLite's `length()` and `GLOB` stop at the first NUL character. A test found
  that `snap/x.jpg\0.png` passed the first version of the check. The check now
  also compares byte length with character length.
- Retention deadlines are immutable once written, so extending retention for
  an open incident needs a new design decision.
- A later migration that rebuilds one of these tables (Alembic batch mode)
  drops its triggers and must re-create them.

## DD-10 — Gemini privacy policy (owner-approved 2026-11-15)

Resolves the open point in DD-08 decision 6. Full text and the (empty)
exception allowlist: `docs/AI_PRIVACY_POLICY.md`.

- Never sent to Gemini: face images, biometric data, visitor identities,
  private visitor history, raw access logs, raw security events, incident
  evidence, credentials, tokens, personal household information.
- May be sent: general documentation, public technical information,
  non-sensitive security policies.
- Household-specific information stays local by default. An exception needs
  explicit owner approval, data minimisation, sanitisation and an entry in the
  documented allowlist. Redaction alone is never treated as anonymisation.
- Requests with prohibited data are rejected before they can reach the
  Gemini adapter (`app/ai/core/privacy.py`).
- Gemini stays disabled; the policy and its tests now exist, but the gate
  also requires a recorded live check.

**Consequence for the later phases.** Only documentation and policy
questions can use Gemini. Visitor history, incident analysis, security
reports, monitoring and escalation are answered by deterministic local rules
(`app/ai/core/reports.py`, `escalation.py`), with local retrieval and
citations but no LLM-written text. Generating prose about household records
would need either an approved exception or a local LLM, which is not part of
the approved stack.

## DD-11 — Retention extensions (owner-approved 2026-11-15)

Original retention deadlines are never modified (the `incident_evidence`
trigger from DD-09 already makes `retention_expires_at` immutable). Extended
retention is a separate append-only record in `retention_extensions`
(migration 0003), with requester, approver, reason, original, previous and
extended deadlines, and request and approval times.

- Approval by an active admin is required; the requester cannot approve
  their own request unless `allow_self_approval=True` is passed explicitly
  (two-person rule by default; see the open point below).
- The incident must be `open` or `investigating`; the evidence must not be
  purged and must have a deadline; the request must be at most 7 days old;
  approval must come before the current effective deadline; the new deadline
  must be later, by at most 365 days.
- The effective deadline is the latest approved extension
  (`app/domain/retention.py: effective_deadline`).
- The database enforces the essentials independently: an insert trigger
  checks the evidence row, the open incident, an active admin approver and the
  chain of previous deadlines; CHECK constraints cover the reason, ordering,
  approval before expiry and the 365-day cap; a second trigger blocks purging
  evidence while an extension is running; rows cannot be updated or deleted.
- No automatic extension exists.

*Open point:* with one admin in the household, the two-person default means
no extension can be approved. The owner should confirm whether
self-approval is acceptable for a single-admin home.

The table is not in the Day 1 `DATABASE_DESIGN.md`; it is added because the
owner's retention policy requires a separate record and none of the existing
tables can hold it without changing original deadlines.

## DD-12 — audit_log append-only at the database level (2026-11-16)

Finding S4 from the product audit: migration 0001 left `audit_log` writable,
so `UPDATE` and `DELETE` succeeded at the database level even though no API
path exists (SR-AUDIT-06/07 require append-only). Migration 0004 adds two
triggers, generated from `app/database/append_only.py`:

- every column is immutable except `actor_user_id`, which may only become
  NULL, so `ON DELETE SET NULL` from `users` still works and the entry keeps
  its `actor_label`;
- `DELETE` is always refused.

No table or column changes. `downgrade()` drops only the two triggers.
Tested on the reference schema (`tests/test_audit_log_append_only.py`);
migration 0004 has not been applied, because Alembic cannot be installed.
