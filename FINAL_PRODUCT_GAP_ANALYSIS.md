# Final Product Gap Analysis

**Date:** 2026-11-16. **Workspace before this stage:** identical to
`backup/project-snapshot-20261115-142009Z.zip` (169 files; checksum verified
on 2026-11-16).

**Environment checked on 2026-11-16 (container booted 2026-11-16 13:48):**

| Check | Result |
|---|---|
| Network mode | `INTEGRATIONS_ONLY` |
| `pip download fastapi` | `No matching distribution found` (proxy refuses PyPI) |
| `npm view react` | `403 Forbidden` |
| `https://pypi.org`, `https://huggingface.co` | no connection (`000`) |
| Approved Python stack (FastAPI, SQLAlchemy, Alembic, Pydantic, argon2, PyJWT, OpenCV, NumPy, InsightFace, ONNX Runtime, LangChain, LangGraph, ChromaDB, sentence-transformers, Google GenAI, APScheduler) | none installed, no wheels on disk |
| Webcam (`/dev/video*`) | none |
| Git repository | none |
| Tools available | Python 3.11.15 stdlib, pytest, Ruff, mypy, Node 22.23, TypeScript 5.9, ESLint 10 (no plugins), Prettier |

**Consequence:** Stage 1 (install, start the backend, run migrations, test
the running API) cannot be executed in this environment, and every later
stage depends on it. Only standard-library work can be built and verified.

## 1. Completed features, with evidence

Evidence = code plus tests that were executed in this environment. None of
these has run inside the real application, because the application has
never started.

| Feature | Evidence | Limits |
|---|---|---|
| AccessEngine ALLOW/DENY/HOLD, signed decisions, HOLD review re-validated by the engine, manual override, lockdown rule | `app/domain/access_engine.py`; 63 tests; 200k random-request probe (2026-11-15) | No API, no persistence; trusts caller-supplied facts (finding S3) |
| Virtual door: starts locked, TTL relock, rejects forged/replayed/stale/wrong-door decisions, lockdown | `app/domain/virtual_door.py`; 22 tests; 20k random-sequence probe | Not exposed; DENY does not relock an open door (P4) |
| Event normalisation and pipeline; every failed login kept (P2) | `events.py`, `pipeline.py`; 33 + 8 tests | In-memory sink only |
| Evidence-reference validation and containment (P1) | `evidence.py`; 195 tests; database CHECK backstop | No evidence capture or retrieval |
| Cross-modal attack-chain reconstruction | `attack_chain.py`; 12 tests + core workflow C | Not persisted or exposed |
| Face-matching logic (threshold, margin, ambiguous, no/multiple face, quality) | `face_matching.py`; 18 tests | **Synthetic vectors only**; no model |
| Retention extensions (owner rules) | `retention.py`; 50 tests incl. SQLite triggers | No API; no purge job |
| Schema design for 11 tables with append-only triggers | `schema_reference.sql`; 248 tests on real SQLite | Reference DDL only; migrations never applied |
| Stdlib AI safety core: kill switch, privacy policy, retrieval permissions, injection screening, output/citation validation, routing, deterministic reports and escalation, metrics, AI isolation | `app/ai/core/`; 335 tests + 21 import-boundary tests | No model, vector store or LLM; AI disabled |
| Rate limiter, security headers, validators, log redaction, create-admin CLI, offline-install tooling | 19 + 9 + 36 + 11 + 11 + 42 tests | Not verified inside FastAPI |
| Frontend foundations: API client, response validation, session and single-flight token refresh, route/role rules, feature register, design tokens | `frontend/src/`; 97 Node tests against a scripted fake backend | No UI; never talked to a real backend |

## 2. Incomplete features (code written, never executed)

| Feature | Files | Missing for runtime evidence |
|---|---|---|
| FastAPI app, error envelopes, CORS | `app/main.py` | Packages; startup |
| Auth: register, login, refresh rotation and reuse revocation, logout, `/me` | `api/v1/auth.py`, `services/auth_service.py`, `core/security.py` | 62 integration tests skipped |
| Family member CRUD with audit | `api/v1/members.py`, `services/identity_service.py` | Same |
| Migrations 0001–0003 | `alembic/versions/` | Statically matched only; runtime parity test skipped |
| SQLAlchemy models | `app/models/` | Statically matched only |
| Read-only database engine for the AI tier | `database/session.py` | Mechanism proven with `sqlite3`, not via SQLAlchemy |

## 3. Missing features

| Area | Missing |
|---|---|
| Vision (Stage 2) | OpenCV capture, face detection, embedding, enrolment, `face_embeddings` table, approved model (InsightFace weight licence unresolved, DD-04) |
| Access flow (Stage 3) | `permissions` table, recognition endpoint, engine and door services, door state API, HOLD review API, lockdown API |
| Events (Stage 4) | SQLite event writer, M13 suspicious-pattern rules, incident manager, evidence capture, read APIs, visitor purge job |
| Frontend (Stage 5) | All seven pages, 3D scanner, webcam UI, charts (0 React files) |
| AI (Stage 6) | Gemini adapter, local embeddings, ingestion and chunking, ChromaDB, RAG, LangGraph agents, workflow recorder, AI endpoints |
| Notifications (Stage 7) | WhatsApp, SMS, email, retries, dedupe, delivery log, `notifications` table |
| Automation | APScheduler, `automation_tasks`, `pipeline_logs` |
| Operations (Stage 9) | Database backup/restore, HTTPS, user guide, verified Windows install |

## 4. Failed tests and runtime errors

Run on 2026-11-16 in this environment:

| Suite | Passed | Failed | Skipped |
|---|---|---|---|
| Backend pytest | 1,180 | 0 | 63 (62 API integration: stack missing; 1 runtime migration parity: SQLAlchemy/Alembic missing) |
| Backend Ruff, Ruff format, mypy | clean | | |
| Frontend `npm run check` (tsc, interim ESLint, Prettier, `node --test`) | 97 | 0 | 0 |

No test fails. **The runtime errors of the real application are unknown,
because it has never been started.** The 2026-11-15 Day 2B review found 15
defects in code that had only been read, so further defects should be
expected at first startup.

Defects found by execution in this audit:

- **S4:** `audit_log` accepts `UPDATE` and `DELETE` (confirmed on the
  reference schema with `sqlite3`). Fixed in this stage; see section 8.

## 5. Dependencies that cannot be installed

Everything outside the Python standard library and the globally installed
Node tools: all of `backend/requirements.txt`; OpenCV, NumPy, InsightFace,
ONNX Runtime; LangChain, `langchain-google-genai`, `langchain-chroma`,
`langchain-huggingface`, LangGraph and its checkpoint packages, ChromaDB,
sentence-transformers; APScheduler; WhatsApp and SMS provider SDKs (if any);
every npm package (React, Vite, Tailwind, Three.js, React Three Fiber, Drei,
Recharts, Framer Motion, Lucide, `@types/node`, `typescript-eslint`); model
weights (InsightFace, `BAAI/bge-small-en-v1.5`).

Credentials not available: Gemini API key, WhatsApp Cloud API, SMS provider.

## 6. Security and privacy risks

| ID | Severity | Risk | Status |
|---|---|---|---|
| S1 | Critical for real use | No liveness detection; a photo could pass recognition | Open; label the demo as a simulation |
| S2 | High | Access tokens are not bound to sessions: logout, revocation and reuse detection do not stop a still-valid 15-minute access token | Open; needs the auth code to run |
| S3 | High (latent) | AccessEngine trusts caller-supplied approver, attempt count and time | Open; must be derived from SQLite and the server clock in Stage 3 |
| S4 | Medium | `audit_log` mutable at the database level | **Fixed in this stage** (reference DDL tested; migration 0004 not applied) |
| S5 | Medium | Any signed-in role can read member names and notes, which conflicts with DD-08 rule 5 | Owner decision needed |
| S6 | Medium | No lock file; no dependency vulnerability scan possible | Open |
| S7 | Medium | No encryption at rest; no MFA | Open (documented residual risks) |
| S8 | Medium | Two lockdown states (P3); DENY does not relock an open door (P4) | Open; Stage 3 |
| S9 | Medium | In-memory rate limits; proxy IP handling | Acceptable for one local laptop |
| S10–S14 | Low | Refresh-rotation race, health endpoint detail, per-process signing key (P7), name detection limits, documentation drift | Open |

## 7. Exact implementation order

Each step needs the previous ones. Steps marked **(blocked)** cannot start
in this environment.

1. **Restore package access** (owner: Kiro Internet Access → "Common
   dependencies", or upload a wheelhouse built with `backend/offline/`). *(blocked)*
2. Stage 1: install, lock dependencies, `pip-audit`, apply migrations
   0001–0004 to a test database, run the 62 integration tests and the runtime
   parity test, start Uvicorn, test the live API; fix S2. *(blocked)*
3. Owner decisions: recognition model and its licence (DD-04), camera
   architecture (OpenCV on the laptop as the master prompt states, or browser
   frames), S5, Gemini's role, retention self-approval, embedding model.
4. Stage 2: migration for `face_embeddings` and `permissions`; OpenCV
   capture; detector/embedder adapter; enrolment with consent; quality
   gates. *(blocked: packages, model, webcam must be the owner's laptop)*
5. Stage 3: recognition → AccessEngine → door endpoint, with facts derived
   from SQLite and the server clock (S3); HOLD review; lockdown with one
   source of truth (S8). *(blocked: step 2)*
6. Stage 4: SQLite event writer; explainable suspicious-pattern rules
   (M13); incidents; read APIs. The rule logic itself is stdlib and could be
   written early with owner approval.
7. Stage 5: frontend pages on the existing foundations. *(blocked: npm)*
8. Stage 7: notifications (credentials needed for real sends).
9. Stage 6: local embeddings, ChromaDB, RAG, Gemini adapter (documentation
   only, DD-10), LangGraph agents. Kept disabled until the gate checks pass.
10. Stage 8: full end-to-end run on the Windows laptop, recorded.
11. Stage 9: README, troubleshooting, release checklist,
    `FINAL_LAUNCH_READINESS_REPORT.md`.

## 8. Work done in this stage

Stage 1 was attempted and is **BLOCKED** at its first step (dependency
installation). The only Stage 1 item verifiable here was database
integrity:

- **S4 fixed:** `audit_log` is now append-only at the database level.
  Every column is immutable except `actor_user_id`, which may only become
  NULL (so the existing `ON DELETE SET NULL` from `users` keeps working); all
  `DELETE`s are refused. Files: `app/database/append_only.py`,
  `app/database/schema_reference.sql`, `app/models/audit_log.py` (one line),
  new `alembic/versions/0004_audit_log_append_only.py`, tests. Migration 0004
  is checked statically; it has **not** been applied, like 0002 and 0003.
