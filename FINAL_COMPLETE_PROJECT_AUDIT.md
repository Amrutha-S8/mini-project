# Final Complete Project Audit

**Project:** AI-Powered Smart Home Security and Automated Access Management System
**Date:** 2026-11-16. **Type:** read-only audit; no application code, test,
migration or configuration was changed.
**Reference:** `backup/project-snapshot-20261116-153145Z.zip`. Verified: zip
SHA-256 OK, workspace identical to it (175 files), all 15 backups pass their
checksums.

Companion files: `API_ENDPOINT_INVENTORY.md`, `SECURITY_FINDINGS_STATUS.md`,
`COMPLETE_TESTING_AND_VERIFICATION_REPORT.md`,
`COMPLETE_MISSING_FEATURES_ROADMAP.md`.

## Status labels used

| Label | Meaning in this report |
|---|---|
| IMPLEMENTED AND RUNTIME-TESTED (core) | The module itself executed in automated tests with real inputs in this sandbox. **Not** inside the running application, which has never started |
| IMPLEMENTED BUT NOT RUNTIME-TESTED | Code exists; it has never executed (needs packages that cannot be installed here) |
| PARTIALLY IMPLEMENTED | Some layers exist; others missing (named) |
| ONLY DOCUMENTED | Design or decision text only |
| NOT IMPLEMENTED | Nothing exists |
| BLOCKED | Cannot start: missing packages, model licence, credentials or hardware |

**Nothing in this project has been runtime-tested inside the running
application.**

---

## 1. Project inventory

```
README.md, DEVELOPMENT_PROGRESS.md        project overview, tracker
FINAL_PRODUCT_GAP_ANALYSIS.md            2026-11-16 gap analysis
docs/                                    17 design, decision, install and test documents
scripts/                                 Windows Stage 1 check (PS1), audit-log check (Python)
backup/                                  15 verified zip snapshots + checksums
backend/
  app/main.py, cli.py                    FastAPI factory; create-admin CLI
  app/api/deps.py, api/v1/               auth dependencies; health, auth, members routers
  app/core/                              config, security, errors, logging, rate limit, headers, clock
  app/database/                          base, session (writer + read-only), codec, append_only, reference DDL
  app/models/                            10 SQLAlchemy model modules (11 tables)
  app/schemas/                           Pydantic request/response models (auth, members)
  app/services/                          auth, identity (members), audit
  app/utils/validators.py                password, email, secret, CORS validation
  app/domain/                            deterministic stdlib core (8 modules)
  app/ai/core/                           stdlib AI safety core (12 modules)
  alembic/                               env.py + migrations 0001–0004
  offline/                               wheelhouse build/install tooling
  tests/                                 31 test files + routing evaluation set
frontend/
  src/api, auth, access, config, design, lib   12 TypeScript modules (no UI), 10 test files
  scripts/lint.mjs, types/node-test.d.ts       interim lint and test types
```

Size: backend application ≈ 8,500 lines of Python; frontend ≈ 3,200 lines of
TypeScript including tests.

### 1.1 Backend application layer

| Module | Supposed to do | Actually implemented | Connected to | Executed? | Missing |
|---|---|---|---|---|---|
| `main.py` | Build the FastAPI app: lifespan, CORS, headers, error envelopes, routers | All of that | config, session, routers, middleware | **Never** | Startup evidence |
| `api/deps.py` | Resolve the user from the bearer token; admin guard; settings and throttle injection | Yes | security, models, session | Never | Session check (**S2**); viewer/member distinction (S5) |
| `api/v1/health.py` | Liveness and database readiness | Yes | session | Never | — |
| `api/v1/auth.py` | Register (admin), login, refresh, logout, me | Yes, with throttling and audit | auth_service, rate_limit | Never | Password change, user list, role change |
| `api/v1/members.py` | Member CRUD, soft deactivate, revoke | Yes, audited | identity_service | Never | Enrolment, permissions |
| `core/config.py` | Typed settings; strong secret required | Yes | everything | Never (pydantic missing) | Settings for vision, AI, notifications |
| `core/security.py` | Argon2id, PyJWT, refresh-token HMAC | Yes | auth_service, deps | Never | Session-id claim (S2) |
| `core/rate_limit.py` | Login/refresh throttling | Yes | deps, auth | **Executed** (19 tests) | Persistence (S9) |
| `core/security_headers.py` | Security headers middleware | Yes | main | Executed with a fake ASGI app (9 tests) | Run inside FastAPI |
| `core/logging.py` | JSON logs with secret redaction | Yes | app-wide | Executed (11 tests) | Rotation |
| `core/errors.py` | Typed errors, client-safe envelope | Yes | main, services | Indirectly (stdlib import) | — |
| `services/auth_service.py` | Auth flows, rotation, reuse detection, failure audit | Yes | models, security, audit | Never | S2, S10 |
| `services/identity_service.py` | Member registry | Yes | models, audit | Never | — |
| `services/audit_service.py` | Append audit entries | Yes | models | Never | — |
| `cli.py` | Create the first admin | Yes | auth_service, session | Executed with fakes (11 tests) | Real run |
| `database/session.py` | Writer and read-only (`mode=ro`) engines | Yes | config | Never via SQLAlchemy; the `mode=ro` mechanism executed with `sqlite3` (9+1 tests) | Windows path risk documented |
| `database/codec.py` | 512-D float32 embedding blob codec | Yes | nothing yet | Executed (11 tests) | A caller |
| `database/append_only.py` | Canonical trigger SQL | Yes (8 guarded tables) | models, migrations (copies), reference DDL | Executed via tests | — |
| `models/` (10 modules) | Canonical schema | users, sessions, family_members, audit_log, access_events, visitor_events, security_events, incidents, incident_evidence, workflow_executions, retention_extensions | migrations, services (identity tables only) | Never; statically matched to the reference (198 + 28 tests) | face_embeddings, permissions, notifications, automation_tasks, pipeline_logs |
| `alembic/versions/0001–0004` | Create schema; triggers | 0001 identity, 0002 events/incidents/workflows, 0003 retention extensions, 0004 audit_log guards | models | **Never applied** | Runtime run |

### 1.2 Deterministic core (`app/domain/`, stdlib only)

| Module | Supposed to do | Implemented | Connected to the app? | Executed? |
|---|---|---|---|---|
| `access_engine.py` | Sole ALLOW/DENY/HOLD authority, signed decisions, HOLD review, manual override, lockdown | Yes | **No** (no route or service uses it) | Yes: 63 tests + 200k random probe (2026-11-15) |
| `virtual_door.py` | Locked by default, TTL relock, rejects forged/replayed/stale decisions, lockdown | Yes | No | Yes: 22 tests + 20k probe |
| `face_matching.py` | Threshold and margin matching over embeddings | Yes | No | Yes: 18 tests, synthetic vectors |
| `events.py` | Normalise and redact security events | Yes | No | Yes: 33 tests |
| `pipeline.py` | Validate, dedupe by id, persist, dispatch | Yes (in-memory sink) | No | Yes: 33 + 8 tests |
| `evidence.py` | Safe evidence references (P1) | Yes | Events only | Yes: 195 tests |
| `attack_chain.py` | Cross-modal incident reconstruction | Yes | AI core reports/escalation | Yes: 12 tests + workflow |
| `retention.py` | Retention-extension approval rules | Yes | No | Yes: 50 tests (incl. SQLite) |

### 1.3 AI core (`app/ai/core/`, stdlib only; AI disabled)

`config` (kill switch, gate record), `types`, `access_policy` (retrieval
permissions, three checks), `sensitive` (secret/personal/biometric
detection), `privacy` (Gemini egress policy, sealed payloads), `prompt_safety`
(templates, delimiting, injection screening), `output_validation` (strict
schema, decision-language guard), `citations`, `routing` (supervisor rules,
action refusals), `reports` (deterministic reports), `escalation`
(deterministic advice), `evaluation` (metrics). **All executed** (335 tests
+ 21 isolation tests). **None is connected** to a model, vector store,
API route or the application. No Gemini, LangChain, ChromaDB, LangGraph or
embedding code exists.

### 1.4 Frontend (`frontend/src/`, no dependencies, no UI)

| Module | Does | Executed? |
|---|---|---|
| `config/apiConfig.ts` | Base URL validation (http only for localhost) | 97-test suite |
| `api/validate.ts`, `schemas.ts` | Runtime response validation mirroring backend schemas; forbidden-key rejection | Yes |
| `api/http.ts`, `errors.ts`, `endpoints.ts` | JSON client for the 13 endpoints; error types | Yes, against a fake backend |
| `auth/session.ts` | In-memory tokens; single-flight refresh; one retry on 401 | Yes, fake backend |
| `access/routes.ts`, `features.ts` | Seven page routes, role rules, safe `?next=`, per-page feature availability | Yes |
| `design/tokens.ts`, `status.ts` | Palette, glass, motion incl. reduced motion; outcome labels | Yes (incl. WCAG contrast) |
| `lib/initials.ts` | Initials avatars | Yes |

No React, no `.tsx`, no pages, no 3D, no charts, no webcam code.

### 1.5 Modules that do not exist

Webcam/OpenCV capture, face detection, embedding extraction, enrolment,
recognition service, engine/door services and routes, SQLite event writer,
M13 suspicious-pattern detector, incident manager, evidence storage and
retrieval, visitor service and purge job, notifications (any channel),
scheduler/automation, analytics aggregation, Gemini adapter, LangChain,
ChromaDB, local embeddings, document ingestion, RAG, LangGraph agents,
workflow recorder, AI routes, all frontend pages.

### 1.6 Tests, scripts, configuration, documentation

- **Tests:** 31 backend files (1,261 collected), 10 frontend files (97). See
  the testing report.
- **Scripts:** `scripts/windows_stage1_check.ps1` (never run),
  `scripts/stage1_audit_log_check.py` (run manually on reference DBs),
  `backend/offline/*` (unit-tested with fakes; never run against PyPI).
- **Configuration:** `backend/.env.example` (no secrets; `SECRET_KEY` empty;
  AI and Gemini off), `alembic.ini` (`script_location = alembic`, URL from
  settings), `pyproject.toml` (pytest, Ruff, mypy), `frontend/package.json`
  (scripts only, no dependencies).
- **Documentation:** accurate: `DEVELOPMENT_PROGRESS.md`,
  `docs/TESTING_REPORT.md`, `DESIGN_DECISIONS.md` (DD-01–DD-12),
  `AI_PRIVACY_POLICY.md`, `LOCAL_EMBEDDING_MODEL.md`,
  `WINDOWS_SETUP_GUIDE.md`. Out of date: see S14.

---

## 2. Feature-by-feature audit

### A. Authentication and user management

| Feature | Status | Evidence / gap |
|---|---|---|
| Registration (admin-only) | IMPLEMENTED BUT NOT RUNTIME-TESTED | `auth.py`, `auth_service.register_user`; 6 integration tests skipped |
| First-admin bootstrap | IMPLEMENTED BUT NOT RUNTIME-TESTED | `cli.py` (11 tests with fakes ran) |
| Login | IMPLEMENTED BUT NOT RUNTIME-TESTED | identical failure responses, throttling, audit; tests skipped |
| Logout | PARTIALLY IMPLEMENTED | revokes the refresh session; access token still valid (**S2**) |
| Access tokens | IMPLEMENTED BUT NOT RUNTIME-TESTED | PyJWT, pinned algorithm, `typ` check; not session-bound |
| Refresh tokens | IMPLEMENTED BUT NOT RUNTIME-TESTED | HMAC-hashed at rest, rotation, family revocation on reuse; S10 race unverified |
| Session management | PARTIALLY IMPLEMENTED | server-side refresh sessions; no session check on access (S2) |
| Password hashing | IMPLEMENTED BUT NOT RUNTIME-TESTED | Argon2id (argon2-cffi not installed); policy validators ran (36 tests) |
| Role-based access | PARTIALLY IMPLEMENTED | backend distinguishes admin vs any active user only |
| Admin and viewer permissions | PARTIALLY IMPLEMENTED | admin-only mutations exist; viewer/member read limits not enforced (S5) |
| Account lockout | IMPLEMENTED BUT NOT RUNTIME-TESTED (by design: throttling, no automatic lock, DD-05) | limiter ran (19 tests); admin-initiated lock is enforced but has no endpoint |
| Session revocation | PARTIALLY IMPLEMENTED | refresh family revocation exists; no admin revoke endpoint; access tokens unaffected |

### B. Database

| Feature | Status | Evidence / gap |
|---|---|---|
| SQLite setup (WAL, FK, busy timeout, read-only engine) | IMPLEMENTED BUT NOT RUNTIME-TESTED | `session.py`; pragmas and `mode=ro` proven with `sqlite3` only |
| SQLAlchemy models (11 tables) | IMPLEMENTED BUT NOT RUNTIME-TESTED | static model-vs-reference parity passed |
| Relationships | PARTIALLY IMPLEMENTED | ORM relationships only for users↔sessions and users↔family_members; others are foreign keys without ORM relationships |
| Alembic migrations 0001–0004 | IMPLEMENTED BUT NOT RUNTIME-TESTED | static parity 28 passed; runtime test skipped |
| Audit logs | IMPLEMENTED BUT NOT RUNTIME-TESTED (writer); triggers IMPLEMENTED AND RUNTIME-TESTED (core, reference DDL) | 16 tests |
| Access, visitor, security events; incidents; evidence; workflow executions | PARTIALLY IMPLEMENTED | tables, constraints and triggers tested on reference DDL (198 tests); **no code writes or reads them** |
| Constraints and triggers | IMPLEMENTED AND RUNTIME-TESTED (core, reference DDL) | not yet confirmed in a migrated database |
| Data retention and deletion | PARTIALLY IMPLEMENTED | extension rules + DB enforcement (50 tests); no purge job, no API |

### C. Face recognition

| Feature | Status |
|---|---|
| Face detection | NOT IMPLEMENTED (BLOCKED: OpenCV/model packages) |
| Face enrollment | NOT IMPLEMENTED (BLOCKED: model, `face_embeddings` table missing) |
| Family-member management | IMPLEMENTED BUT NOT RUNTIME-TESTED (records only, no faces) |
| Face embeddings | PARTIALLY IMPLEMENTED (storage codec only, 11 tests) |
| Face matching | IMPLEMENTED AND RUNTIME-TESTED (core, **synthetic vectors**) |
| Confidence and threshold handling | IMPLEMENTED AND RUNTIME-TESTED (core): matcher threshold + margin, engine re-check, hold band |
| Unknown visitor handling | PARTIALLY IMPLEMENTED: engine DENY by default/HOLD optional, never enrols; no visitor service |
| Multiple-face handling | IMPLEMENTED AND RUNTIME-TESTED (core): `MULTIPLE_FACES` → HOLD; no detector to produce it |
| Poor-lighting handling | PARTIALLY IMPLEMENTED: `POOR_QUALITY` → HOLD in core; no image quality measurement |
| Model integration | NOT IMPLEMENTED (BLOCKED) |
| Model licence verification | BLOCKED (DD-04: InsightFace weights licence unresolved) |

### D. Webcam and virtual door

| Feature | Status |
|---|---|
| Webcam capture, live feed, frame processing | NOT IMPLEMENTED (BLOCKED: OpenCV; camera architecture undecided) |
| Recognition integration | NOT IMPLEMENTED |
| AccessEngine integration into the app | NOT IMPLEMENTED |
| ALLOW, DENY, HOLD | IMPLEMENTED AND RUNTIME-TESTED (core) |
| Virtual door locking, automatic relocking | IMPLEMENTED AND RUNTIME-TESTED (core); not exposed; S8 open |
| Replay protection (signature, freshness, single use) | IMPLEMENTED AND RUNTIME-TESTED (core) |
| Camera failure handling | NOT IMPLEMENTED (only the `system.camera_error` event type exists) |

### E. Security monitoring

| Feature | Status |
|---|---|
| Failed access attempts | PARTIALLY IMPLEMENTED: event types and pipeline (core tested); failed logins audited (not run); no persistence of access attempts |
| Unknown visitors | PARTIALLY IMPLEMENTED (event model and table only) |
| Suspicious activity detection (M13 rules) | NOT IMPLEMENTED (only DOCUMENTED in MODULE_DESIGN M13) |
| Attack-chain reconstruction | IMPLEMENTED AND RUNTIME-TESTED (core); not persisted or exposed |
| Incident creation | PARTIALLY IMPLEMENTED (table only) |
| Evidence storage | PARTIALLY IMPLEMENTED (reference validation and DB checks; no capture, hashing or retrieval) |
| Security notifications | NOT IMPLEMENTED |
| Audit trail | IMPLEMENTED BUT NOT RUNTIME-TESTED (writer); append-only DB tested on reference |

### F. AI, RAG and agentic AI

| Feature | Status |
|---|---|
| Gemini integration | NOT IMPLEMENTED (BLOCKED: package, key); privacy gate exists |
| LangChain | NOT IMPLEMENTED (BLOCKED) |
| LangGraph workflows | NOT IMPLEMENTED (BLOCKED) |
| ChromaDB | NOT IMPLEMENTED (BLOCKED) |
| Local embeddings | ONLY DOCUMENTED (`LOCAL_EMBEDDING_MODEL.md`; not downloaded) |
| Document ingestion, retrieval | NOT IMPLEMENTED |
| Permission checks for retrieval | IMPLEMENTED AND RUNTIME-TESTED (core, fake verifier) |
| AI assistant | NOT IMPLEMENTED |
| Incident summaries | PARTIALLY IMPLEMENTED: deterministic, audience-redacted reports (core tested); no AI narration |
| Read-only tools | NOT IMPLEMENTED |
| AI workflow tracking | PARTIALLY IMPLEMENTED (`workflow_executions` table only; no recorder) |
| Kill switch | IMPLEMENTED AND RUNTIME-TESTED (core); off by default |

### G. Notifications

WhatsApp, SMS, triggers, retries, internet-failure handling, delivery status:
**NOT IMPLEMENTED.** Credentials: **BLOCKED** (none provided). The
`notifications` table does not exist. Only `ai/core/escalation.py` produces a
deterministic *recommendation* to notify (core tested); it sends nothing.

### H. Frontend

| Page | Designed only | Partially coded | Fully coded | Connected to backend | Runtime-tested |
|---|---|---|---|---|---|
| 1 Dashboard | Yes (reference image, feature register) | No UI | No | No | No |
| 2 Live Monitoring | Yes | No | No | No | No |
| 3 Access Management | Yes | No | No | No | No |
| 4 Security Events | Yes | No | No | No | No |
| 5 AI Assistant | Yes | No | No | No | No |
| 6 Analytics | Yes | No | No | No | No |
| 7 Settings | Yes | No | No | No | No |

Shared foundations (API client, session, routes, tokens) are coded and
unit-tested against a fake backend. **Not implemented:** 3D robotic face
scanner, animations, charts, webcam display, sidebar/navigation UI. BLOCKED
on npm access.

---

## 3. Windows readiness audit

**Windows compatibility has not been verified.** No command in the guide has
been executed on Windows; the sandbox has no PowerShell.

| Item | Finding |
|---|---|
| Folder layout in the guide | Matches the project: `C:\SmartHome\backend` holds `alembic.ini`, `alembic\`, `app\`, `.env.example`, `requirements.txt`; `scripts\` is at the project root (verified against the snapshot listing) |
| Required software | Windows 10/11, Python 3.11 64-bit (last Windows installer 3.11.9), PowerShell 5.1+. Git not needed. Node not needed for Stage 1 |
| Package versions | Ranges only (`requirements.txt`, e.g. `fastapi>=0.115,<1.0`, `sqlalchemy>=2.0,<3.0`, `pydantic>=2.7,<3.0`, `argon2-cffi>=23.1,<26.0`, `pyjwt>=2.8,<3.0`, `pytest>=8.0`, `httpx>=0.27,<1.0`). No lock file (S6) |
| Configuration | `.env` must be created with a ≥32-character `SECRET_KEY` **before** tests, migrations and the server (the integration fixture imports `app.main`, which builds an app from the real settings) |
| Commands not executed anywhere | venv creation, `pip install`, `pytest` with the stack, `python -m alembic upgrade head`, `python -m app.cli create-admin`, `python -m uvicorn app.main:app`, the health requests, both check scripts on Windows |
| Compatibility risks | (1) 9 symlink tests need Developer Mode, otherwise skipped with a reason; (2) read-only SQLite `file:` URI breaks on folder names containing `#` or `?` (unused so far); (3) OneDrive-synced folders may lock the database; (4) PowerShell execution policy blocks `Activate.ps1` (guide gives a process-scoped fix); (5) the PS1 script itself is untested; (6) `test_offline_wheelhouse.py` has only ever run on Linux |
| Expected test result in the guide | "1,261 passed" is an expectation, not evidence |
| Manual steps | All 14 guide steps; Developer Mode; pasting `SECRET_KEY`; choosing the admin password |

`docs/INSTALLATION_GUIDE.md` §2 now points to the Windows guide; its old
command list is kept for reference and is not wrong, but omits the test
database and `python -m` forms.

---

## 4. End-to-end workflow audit

| # | Step | Status | Missing integration |
|---|---|---|---|
| 1 | Admin creates a household account | IMPLEMENTED BUT NOT RUNTIME-TESTED (CLI + register endpoint) | — |
| 2 | Admin logs in | IMPLEMENTED BUT NOT RUNTIME-TESTED | — |
| 3 | Admin registers a family member | IMPLEMENTED BUT NOT RUNTIME-TESTED | — |
| 4 | Member's face is enrolled | NOT IMPLEMENTED / BLOCKED | vision service, model, `face_embeddings`, enrolment route |
| 5 | Webcam captures a visitor | NOT IMPLEMENTED / BLOCKED | camera capture (architecture undecided) |
| 6 | Model identifies the person | NOT IMPLEMENTED / BLOCKED | embedding extraction → `face_matching` |
| 7 | AccessEngine decides | Core tested; NOT INTEGRATED | service building `AccessRequest` from SQLite + server clock (S3); `permissions` table |
| 8 | Virtual door responds | Core tested; NOT INTEGRATED | door service/state, lockdown source (S8) |
| 9 | Access event saved | NOT IMPLEMENTED (table exists) | SQLite event sink for the pipeline |
| 10 | Dashboard shows the event | NOT IMPLEMENTED | read API + React page |
| 11 | Suspicious activity detected | PARTIALLY (attack chain in core); M13 rules missing | detector, incident persistence |
| 12 | Homeowner notified | NOT IMPLEMENTED | notification service, credentials |
| 13 | AI explains permitted information | NOT IMPLEMENTED (safety core only) | embeddings, ChromaDB, RAG, Gemini adapter, agents, AI routes |

Steps 1–3 are the only steps with application code; none has run. The
chain breaks at step 4.

---

## 5. Overall assessment

- **Stage:** an early prototype. The deterministic security core, the
  database design and the AI safety rules are built and well tested in
  isolation. The application has never run, and the product's main flow
  (camera → recognition → decision → door → event → UI) does not exist.
- **Not** a working local product; **not** release-ready.
- Measured progress: **0 of 10** real-execution milestones achieved
  (testing report §9).
- Main blockers: no package access in the sandbox (Stage 1 must run on the
  owner's Windows laptop), the face-model licence, the camera architecture
  decision, and missing credentials for Gemini and notifications.
