# Complete Missing-Features Roadmap

**Date:** 2026-11-16. Based on `FINAL_COMPLETE_PROJECT_AUDIT.md`. **For owner
review; nothing here has been started.**

Order matters: each phase lists what it depends on. Do not start a phase
before its dependencies are complete with runtime evidence.

```
P0 ──► P1 ──► P2 ──► P3 ──► P4 ──► P5 (pages need P1–P4 APIs)
              │                    │
              └──────► P7 ◄────────┘ (notifications need P4 events)
P6 needs P1, P4 and the P3 safety gate (V2–V5 recorded)
P8 needs P1–P7 (whatever is in scope)
P9 runs alongside P1 and closes after P8
P10 after P9
```

---

## P0 — Critical blockers and security risks

| # | What | Why | Files / modules | Depends on | Tests required | Done when |
|---|---|---|---|---|---|---|
| P0-1 | Run Stage 1 on the Windows laptop (guide Steps 1–14) | Nothing has ever run; package access exists only there | `docs/WINDOWS_SETUP_GUIDE.md`, both check scripts | Owner's laptop | full suite with the stack | 1,261 collected; 0 failed; skips only for symlinks (or none); `/health/ready` returns ok |
| P0-2 | Fix whatever fails in P0-1 | Code written without running had 15 defects on Day 2B | any | P0-1 | the failing tests | suite green on Windows |
| P0-3 | Fix S2: bind access tokens to sessions | Logout/revocation must actually end access | `core/security.py`, `api/deps.py`, `services/auth_service.py` | P0-2 | new failing-first tests: access token after logout, after revocation, after reuse → 401 | all 62 + new tests pass |
| P0-4 | Confirm S4 on a migrated database | DB-level audit integrity | migration 0004 | P0-1 | `stage1_audit_log_check.py` on `data\stage1_test.db` | all PASS |
| P0-5 | Lock dependencies; run `pip-audit` (S6) | Reproducible, scanned installs | `backend/requirements.lock.txt` (new) | P0-1 | `pip install --require-hashes -r requirements.lock.txt` in a clean venv | lock committed to backups; no known high CVEs |
| P0-6 | Owner decisions | Later phases depend on them | `docs/DESIGN_DECISIONS.md` | — | — | recorded: face model + licence (DD-04); camera architecture; S5 viewer/member rules; S8 lockdown semantics; retention self-approval; embedding model; Gemini's role |

## P1 — Core backend and database

| # | What | Why | Files / modules | Depends on | Tests | Done when |
|---|---|---|---|---|---|---|
| P1-1 | Live API check against the running server (register, login, refresh, logout, roles) | In-process tests are not the running app | new verification script | P0-3 | script run recorded | every flow returns the expected status codes |
| P1-2 | Enforce S5 in the backend | Viewers must not read member records | `api/v1/members.py`, deps | P0-6 | per-role tests | viewer/member get 403 where required |
| P1-3 | Migration 0005: `face_embeddings`, `permissions` | Needed by enrolment and the engine | models, migration, reference DDL | P0-2 | parity + constraint tests, runtime migration | applied on a test DB |
| P1-4 | SQLite event sink for the pipeline | Events must persist (P2 fix must hold in the DB) | `domain/pipeline.py` sink, new repository | P0-2 | every failed login is a row; idempotent by `event_uid` | rows match pipeline stats |
| P1-5 | Fix S10 (atomic refresh rotation) | Prevent double refresh | `auth_service.refresh_tokens` | P0-3 | concurrency test | only one refresh succeeds |
| P1-6 | Update stale docs (S14) | Accurate project record | docs listed in S14 | — | — | no contradictory status text |

## P2 — Face recognition and webcam

| # | What | Why | Files | Depends on | Tests | Done when |
|---|---|---|---|---|---|---|
| P2-1 | Camera capture per the chosen architecture | Input for the whole flow | new `vision/` (or browser capture + upload route) | P0-6 | manual camera test on the laptop; failure handling tests (no camera, disconnect) | frames captured; failures reported |
| P2-2 | Detector + embedder adapter with quality gate | Produce `MatchResult` | new vision modules; reuse `face_matching.py`, `codec.py` | P2-1, licensed model | recorded test images; no-face, multiple-face, dark-image cases | correct status for each case |
| P2-3 | Enrolment with consent | Members only; never visitors | members route extension, `face_embeddings` | P1-3, P2-2 | embedding stored, no image kept; admin-only | enrol yourself |
| P2-4 | Measure threshold on real faces | Calibrate hold band | evaluation notes | P2-3 | genuine/impostor scores recorded | threshold chosen from measurements |

## P3 — Access control and virtual door integration

| # | What | Why | Files | Depends on | Tests | Done when |
|---|---|---|---|---|---|---|
| P3-1 | Access service: recognition → AccessEngine → door → event | The core product flow | new service + route; reuse `access_engine.py`, `virtual_door.py`, `pipeline.py` | P1-3, P1-4, P2-2 | facts derived from SQLite and server clock (S3); forged/replayed decisions rejected | enrolled face → ALLOW then relock; unknown → DENY; rows in `access_events` |
| P3-2 | Door state, lockdown (single source, S8), admin release | Visible and controllable state | door route | P0-6, P3-1 | lockdown relocks; release admin-only, audited | tests pass |
| P3-3 | HOLD persistence and admin review; persistent signing key (S12) | DD-01 workflow | engine wiring | P3-1 | review revalidated by engine; restart keeps HOLDs verifiable | tests pass |
| P3-4 | Day 7 V1–V15 verification run | Safety gate for AI and release | tests | P3-1–P3-3 | route enumeration (V5), IDOR (V9), purge (V13) | results recorded; gate entries for V2–V5 |

## P4 — Security monitoring and incident management

| # | What | Why | Files | Depends on | Tests | Done when |
|---|---|---|---|---|---|---|
| P4-1 | M13 explainable detection rules (repeated denials, brute-force login, unknown face at night, rejected unlock) | Suspicious activity without AI | new `domain/detection.py` (stdlib) | P1-4 | rule tests; no intent claims | detections stored with the rule name |
| P4-2 | Incident manager: persist attack chains | Investigable cases | reuse `attack_chain.py`; `incidents` table | P4-1 | idempotent by `incident_uid` | incidents stored and readable |
| P4-3 | Evidence capture with SHA-256; authenticated, audited retrieval | SR-STORE-11/13 | reuse `evidence.py` | P4-2, P2-1 | traversal, TOCTOU-safe open, hash mismatch event | tests pass |
| P4-4 | Visitor service and purge job; retention-extension API | Privacy rules | reuse `retention.py` | P4-2 | purge stamps `purged_at`; extensions block purge | tests pass |
| P4-5 | Read APIs: events, incidents, analytics aggregates | Pages need data | new routers | P4-1, P4-2 | per-role tests; counts match the DB | tests pass |

## P5 — Complete frontend

| # | What | Depends on | Tests | Done when |
|---|---|---|---|---|
| P5-1 | Restore npm; Vite + React + Tailwind + R3F shell, Login, sidebar, routes | npm access (Windows laptop or sandbox) | build, type check, lint, route tests | build passes; console clean |
| P5-2 | Dashboard with 3D face scanner, reduced-motion option | P5-1, P4-5 | render tests; manual visual check | matches the reference layout with real data or empty states |
| P5-3 | Live Monitoring (webcam start/stop, permission denied, disconnect, backend result) | P3-1, P5-1 | manual laptop test recorded | stream stops on leaving the page |
| P5-4 | Access Management, Security Events, Analytics, Settings | P1-2, P4-5, P5-1 | page tests; no sample data (source-safety test) | data matches the DB |
| P5-5 | AI Assistant page (shows "disabled" until P6) | P6 or none | — | correct unavailable state |

## P6 — RAG, Gemini and agentic AI

Depends on P1, P4 and P3-4 (gate). Kept disabled until the gate record has
evidence for V2–V5, `privacy_policy` and live checks.

| # | What | Reuse | Tests | Done when |
|---|---|---|---|---|
| P6-1 | Local embedding model (approved one), offline loading | `LOCAL_EMBEDDING_MODEL.md` | live check with network off | `live_local_embeddings` gate entry |
| P6-2 | Ingestion, chunking, ChromaDB store, SQLite sync | `access_policy.py`, `sensitive.py` | no biometric data indexed; permission filters on a real store | retrieval metrics on a labelled set |
| P6-3 | Gemini adapter accepting only sealed payloads (documentation questions) | `privacy.py`, `prompt_safety.py`, `output_validation.py`, `citations.py` | refused requests never leave the machine; live call | `live_gemini` gate entry |
| P6-4 | LangGraph agents with read-only tools; workflow recorder (non-AI) | `routing.py`, `reports.py`, `escalation.py` | isolation tests still pass; agent state tests | AI routes and page work while flagged on |

## P7 — WhatsApp and SMS notifications

| # | What | Depends on | Tests | Done when |
|---|---|---|---|---|
| P7-1 | `notifications` table, channel interface, retry with backoff, dedupe, delivery log | P4-1 | failure and retry tests; no faces or names in bodies | tests pass |
| P7-2 | WhatsApp Cloud API channel; SMS fallback | P7-1, credentials | real message received; offline failure logged and retried | evidence recorded |

## P8 — End-to-end testing

Depends on everything in scope. Record, on the Windows laptop: the 13-step
workflow in the audit §4; webcam start/stop; enrolled member ALLOW and relock;
unknown visitor DENY; HOLD and admin review; event visible in the UI;
detection and notification; AI permission refusals. **Done when** every step
has recorded evidence.

## P9 — Windows local launch

Starts with P0-1; closes after P8. Update `WINDOWS_SETUP_GUIDE.md` with
measured results; add frontend install/build, database backup and restore,
troubleshooting from real errors, a user guide, and
`FINAL_LAUNCH_READINESS_REPORT.md`. **Done when** a clean install on the
laptop follows the guide without help.

## P10 — Public release preparation

Liveness detection (S1); MFA and encryption at rest (S7); HTTPS, trusted
proxy handling and persistent rate limits (S9); restrict readiness detail
(S11); dependency and secret scanning in CI; penetration test; performance
measurements; accessibility audit. **Done when** each item has evidence and
the security findings are closed or formally accepted.

---

## Immediate next step

P0-1: on the Windows laptop, `py -3.11 --version` (guide Step 1), then the
following steps one at a time.
