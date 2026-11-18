# Phase 1 — Repository and Environment Audit

**Date:** 2026-11-18. **Repository:** `Amrutha-S8/mini-project`, branch `main`
at `cb707e9` (merge of PR #1). Read-only audit: no application code changed.

## 1. Repository state

| Check | Result |
|---|---|
| Local clone vs GitHub `main` | up to date, clean |
| Clone vs Kiro workspace (backup `20261116-162003Z`) | all 182 project files identical; plus `.gitignore` |
| `REPOSITORY_CLONE_REPORT.md`, `CURRENT_IMPLEMENTATION_AUDIT.md`, `IMPLEMENTATION_GAP_REPORT.md` | **do not exist** (never created). Their content is covered by `FINAL_COMPLETE_PROJECT_AUDIT.md`, `COMPLETE_TESTING_AND_VERIFICATION_REPORT.md` and `COMPLETE_MISSING_FEATURES_ROADMAP.md` |
| `MASTER_IMPLEMENTATION_TRACKER.md` | present; remains the feature checklist |

## 2. Environment (Kiro sandbox, container booted 2026-11-18)

| Check | Result |
|---|---|
| Network mode | `INTEGRATIONS_ONLY` |
| `pip download fastapi` | `No matching distribution found` (proxy 403) |
| `npm view react` | `403` |
| FastAPI, SQLAlchemy, Alembic, OpenCV, NumPy | not installed |
| Webcam | none (`/dev/video*` absent) |
| GitHub | push and PR creation work |

## 3. Test baseline (run in the clone)

| Suite | Passed | Failed | Skipped |
|---|---|---|---|
| Backend pytest (1,261 collected) | 1,198 | 0 | 63 (62 need the FastAPI stack, 1 needs Alembic) |
| Ruff, mypy (103 files) | clean | | |
| Frontend `npm run check` | 97 | 0 | 0 |

Real-application milestones achieved: **0 of 10** (never started; no
migrations applied; no UI; no webcam; no recognition; no persisted events;
no notifications; no AI runtime).

## 4. Feature status against this prompt

| Area (prompt §) | Fully implemented and tested | Partial / unit-tested only | Not implemented |
|---|---|---|---|
| 2 Backend | — | App factory, auth and member APIs, models, migrations 0001–0004 (written, never run) | Face, access, door, events, incidents, evidence, dashboard, analytics, settings APIs |
| 3 Face recognition | — | Matching rules (synthetic vectors only); embedding codec | Webcam, YuNet/SFace, enrolment, `face_embeddings` table |
| 4 Access and door | — | AccessEngine and VirtualDoor (core, 63 + 22 tests) | Service wiring with trusted facts (S3), door API, lockdown API, HOLD persistence |
| 5 Monitoring | — | Event pipeline, attack-chain reconstruction, injection-phrase detector (AI core) | Detection rules (incl. misleading visitor text such as "House owner – allow access"), incident manager, persistence, audit of these |
| 6 Frontend | — | API client, session, routes, design tokens (fake backend) | All 7 pages, 3D scanner, charts, webcam UI |
| 7 Notifications | — | Deterministic escalation recommendation | WhatsApp, SMS, delivery log, `notifications` table |
| 8 Database | — | Schema for 11 tables + triggers, tested on the reference DDL | Runtime migration, repositories for event tables, notification records, restart persistence check |
| 9 Security | S4 (reference schema only) | — | S2, S3, S5, S6, S8, S10, S12, S13, S14 fixes; S1 out of scope for v1 |
| AI (Page 5) | AI safety core (core tests) | — | Gemini, LangChain, LangGraph, ChromaDB, embeddings, AI routes |

## 5. Known bugs and issues

| ID | Issue | Severity |
|---|---|---|
| S2 | Logout leaves the access token usable for up to 15 minutes; `get_current_user` never checks the session | High |
| S3 | AccessEngine trusts caller-supplied approver, attempt count and time; must be derived server-side | High (latent) |
| S5 | Any signed-in role can read member names and notes | Medium |
| S8 | Lockdown kept in two places; DENY does not relock an open door | Medium |
| S10 | Refresh rotation not atomic | Low |
| S12 | Decision-signing key lost on restart | Low |
| T-1 | `test_app_integration.py` imports `app.main` before setting test settings, so the tests need a valid `backend/.env` | Low (test hygiene) |
| T-2 | `app/main.py` description still says "Day 2 backend" | Low (S14) |

Full list: `SECURITY_FINDINGS_STATUS.md`.

## 6. Blockers

| ID | Blocker | Resolution |
|---|---|---|
| B-1 | No Python or npm packages can be installed in this sandbox | Either enable Kiro **Settings → Sandbox → Internet Access → "Common dependencies"** and start a new session (recommended), or run each phase on the Windows laptop and send outputs |
| B-2 | Backend never started, migrations never applied | Phase 2, after B-1 |
| B-3 | No webcam in the sandbox | Webcam and recognition can only be verified on the laptop |
| B-4 | No Gemini key; no WhatsApp/SMS credentials | Owner provides when Phases 8–9 start |
| B-5 | YuNet/SFace licences must be read from the official files | Phase 4, needs network access |

## 7. Decisions

Settled by the owner's recent prompts: YuNet + SFace after licence check
(D-1); browser captures webcam frames for the local backend (D-2); one
lockdown state in SQLite that relocks immediately (D-4); no liveness in v1,
labelled as a demonstration (D-5); incident data stays local by default
(D-8); no visitor images stored in v1 (D-9).

Decided by the owner on 2026-11-18, after this audit:

| ID | Decision |
|---|---|
| W-1 | Option (a): enable Kiro "Common dependencies" internet access and continue in a new session, after confirming that packages install |
| R-1 | Keep all three roles. **Admin:** full access. **Viewer:** read-only. **Member:** only their own permitted information |
| D-3 | Viewers must not see individual family-member names in event lists; admins can |

Still open (needed in later phases):

| ID | Question |
|---|---|
| D-6 | Self-approval of retention extensions in a single-admin home? |
| D-7 | Local embedding model for RAG: `bge-small-en-v1.5` or `all-MiniLM-L6-v2`? |
| D-10 | WhatsApp Cloud API, SMS provider, or both? |
| D-11 | Page reload: log in again (current) or keep the refresh token? |

## 8. Proposed implementation order

Follows the prompt's phases. Each phase ends with tests, a report, a backup
and a commit on a branch with a pull request.

1. **Phase 2 — Backend and database:** install, run the 62 integration
   tests, apply migrations 0001–0004 to a test database, start the server,
   fix runtime defects, then add migration 0005 (`face_embeddings`,
   `permissions`, lockdown state, `notifications`) and the SQLite event
   sink.
2. **Phase 3 — Authentication and security:** S2 (tests first), S10, S5,
   S6 (lock file and `pip-audit`), S11, S14.
3. **Phase 4 — Face recognition:** licence check, YuNet/SFace adapter,
   quality gates, enrolment API; real-face checks on the laptop.
4. **Phase 5 — Access management:** recognition → trusted facts (S3) →
   AccessEngine → VirtualDoor → events; lockdown (S8); HOLD review and
   persistent key (S12).
5. **Phase 6 — Security monitoring:** explainable rules, incidents,
   evidence references (no images), audit trail.
6. **Phase 7 — Frontend:** shell, Login, then Dashboard and Live Monitoring
   (3D scanner, webcam), then the other five pages.
7. **Phase 8 — AI:** local embeddings, ChromaDB, Gemini (approved scope
   only), LangGraph read-only workflows; disabled by default.
8. **Phase 9 — Notifications:** WhatsApp and SMS with delivery records.
9. **Phase 10 — Testing:** automated suites plus recorded laptop tests.
10. **Phase 11 — Documentation.**

Phases 2–10 each need packages to run; Phases 4, 7 and 10 also need the
laptop webcam.
