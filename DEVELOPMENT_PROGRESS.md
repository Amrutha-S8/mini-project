# DEVELOPMENT PROGRESS

**Project:** AI-Powered Smart Home Security and Automated Access Management System
**Last updated:** 2026-11-15
**Overall:** backend foundation and deterministic security core written; the
application has **never been started**. Blocked on dependency installation.

The Day 1 version of this file is preserved in
`backup/day1-docs-20261114-140308Z.zip`.

## Status vocabulary

Not started · In progress · Implemented (written) · Tested (automated tests
pass) · Verified (works end to end in the real runtime) · Blocked

A day is complete only when **Verified**.

## 15-day tracker

| Day | Theme | Status | Evidence | Blocker |
|---|---|---|---|---|
| 1 | Audit, backup, architecture | **Verified** | Day 1 docs, audits, backups | — |
| 2 | Backend foundation and database | Implemented; pure parts Tested; **Blocked** | Auth, RBAC, audit, CLI, hardening (DD-05) written; limiter, headers, validators, route guard tested; 62 API tests skip | FastAPI/SQLAlchemy not installable |
| 3 | Family management and face recognition | Matching core **Tested**; rest Not started | `face_matching.py`, 18 tests on synthetic vectors | Packages; InsightFace weight licence (DD-04); no webcam in sandbox |
| 4 | AccessEngine and virtual door | Core **Tested**; API/persistence Not started | 63 engine + 22 door tests | Persistence/API need the stack |
| 5 | Visitor monitoring and security events | Event core **Tested**; persistence/API Not started | `events.py`, 32 tests (shared with Day 6) | Same |
| 6 | Central data pipeline | Core **Tested**; SQLite sink Not started | `pipeline.py` | Same; Pandas/NumPy not installed |
| 7 | Application security and testing | In progress | Hardening done in code; integration security tests written, skipped | Stack |
| 8 | Attack chain reconstruction | Core **Tested**; API/storage Not started | `attack_chain.py`, 12 tests + workflow C | Same |
| 9 | Gemini | Not started | — | Package not installable; no API key |
| 10 | RAG | Not started | — | LangChain/ChromaDB not installable |
| 11 | LangGraph agents | Not started | — | Package not installable |
| 12 | Automation | Not started | — | APScheduler not installable |
| 13 | Notifications, analytics, backend completion | Not started | — | Credentials; packages |
| 14 | Frontend | Not started | — | npm registry unreachable |
| 15 | Final integration and release | Not started | — | All of the above |

## Current test result

`1198 passed, 0 failed, 63 skipped` — details in `docs/TESTING_REPORT.md`.

## AI layer (DD-08), in progress

| Phase | Status |
|---|---|
| 0. Source tables: migration 0002, models, reference DDL (DD-09) | Reference DDL **Tested**; models and migration statically matched, **never run** |
| 1. Standard-library AI core (`app/ai/core/`), Gemini privacy policy (DD-10), retention extensions (DD-11, migration 0003), isolation tests, embedding-model documentation | AI core and retention policy **Tested**; migration 0003 statically matched, **never run**; embedding model documented, **not downloaded or tested** |
| 2+. Gemini, LangChain, ChromaDB, LangGraph adapters, API | Blocked until package access returns (DD-08 decision 9) |

## Final product stages (master prompt, 2026-11-16)

Gap analysis: `FINAL_PRODUCT_GAP_ANALYSIS.md`.

| Stage | Status |
|---|---|
| 1. Backend and database verification | **Blocked** at dependency install (PyPI and npm refused). Finding S4 fixed: `audit_log` append-only (migration 0004, reference DDL tested, migration not applied) |
| 1 on Windows (owner's laptop) | Prepared, **not yet run**: `docs/WINDOWS_SETUP_GUIDE.md`, `scripts/windows_stage1_check.ps1` (never executed; no PowerShell in the sandbox), `scripts/stage1_audit_log_check.py` (tested on reference-schema databases) |
| 2–9 | Not started; all depend on Stage 1 |

## Frontend (Day 14 work, started early by owner decision)

| Stage | Status |
|---|---|
| Option B: API client, auth and token refresh, response validation, route access, design tokens (`frontend/`) | **Tested** (97 Node tests, against a scripted fake backend); no UI |
| Option A: seven React pages, 3D scanner, webcam | Not started. Waits for Phase 1 decisions, backend endpoints and npm access |

## What was done in the latest stage (2026-11-15)

1. **Security hardening (DD-05):** mandatory strong `SECRET_KEY`; identical
   login failures; per-IP and per-(IP, email) throttling with 429 instead of
   account lockout; refresh throttling; security headers; CORS without
   credentials and with validated origins; 404/405 error envelope.
2. **Deterministic core (DD-06), `backend/app/domain/`:** AccessEngine with
   ALLOW/DENY/HOLD and signed decisions; virtual door simulation; face matching;
   event normalisation; event pipeline; cross-modal attack-chain
   reconstruction. Stdlib only, enforced by a tested import guard.
3. **Documentation:** README, backend README, DESIGN_DECISIONS (DD-05–07),
   OFFLINE_INSTALL, new TESTING_REPORT and INSTALLATION_GUIDE.

## Blockers needing the owner

| # | Blocker | Needed |
|---|---|---|
| B1 | No PyPI/npm/GitHub access in the sandbox (`INTEGRATIONS_ONLY`) | Fix the account's Internet Access setting, or upload the wheelhouse (`docs/OFFLINE_INSTALL.md`) |
| B2 | InsightFace pretrained weights reported non-commercial | Confirm permitted use, or approve an alternative |
| B3 | No Gemini key, WhatsApp Cloud API credentials or SMS provider | Provide when ready (Days 9 and 13) |
| B4 | No webcam in the sandbox | Live camera runs on the Windows laptop (decided, D2) |
| B5 | No Git repository | Owner decision (D5) |

## Next steps once B1 is resolved

1. Install, generate the lock file, run migrations and the 62 integration tests;
   fix what fails.
2. Persist the core: run migration 0002 (events, incidents, evidence,
   workflows; written, DD-09); add permissions, face embeddings and holds in a
   later migration; SQLite event sink.
3. API routes for permissions, door, holds, events, incidents.
4. Vision layer (OpenCV capture, recogniser adapter) once the model licence is
   settled.
