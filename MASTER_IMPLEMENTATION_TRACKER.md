# Master Implementation Tracker

**Created:** 2026-11-16 from `project-snapshot-20261116-155729Z.zip`
(verified). **Update rule:** a row changes to DONE only with recorded
evidence: the command, where it ran, and its output, or a test report file.
Source code alone is never evidence.

## Status vocabulary

| Status | Meaning |
|---|---|
| DONE (core) | Executed in automated tests in the sandbox; not inside the running application |
| WRITTEN | Code exists, never executed |
| PARTIAL | Some layers exist (named in Notes) |
| DOCUMENTED | Design text only |
| TODO | Nothing exists |
| BLOCKED | Waiting on packages, hardware, licence, credentials or an owner decision (named) |
| DONE | Runtime evidence in the real application (none yet) |

Where tasks run: **W** = owner's Windows laptop (packages, webcam);
**S** = Kiro sandbox (stdlib Python, Node without packages).

---

## 1. Owner decisions required

Nothing marked BLOCKED on a decision can start until it is answered.

| ID | Decision | Options and my recommendation | Blocks |
|---|---|---|---|
| D-1 | Face model | **Recommended: OpenCV Zoo YuNet (detector, MIT) + SFace (recogniser, Apache-2.0)**, run through `opencv-python` on the CPU, Windows-friendly, no extra ML runtime. Licences as reported by third-party redistributions ([adamoberley DOCS](https://github.com/adamoberley/ha-addons/blob/main/local_faces/DOCS.md), [HF mirror](https://huggingface.co/mumallaeng/wardy-m02-identity)); the official `LICENSE` files in [opencv_zoo](https://github.com/opencv/opencv_zoo/blob/main/models/face_detection_yunet/LICENSE) must be read in Phase 3. **Not recommended:** InsightFace pretrained models, which the official docs restrict to non-commercial research ([model_zoo.md](https://github.com/deepinsight/insightface/blob/master/python-package/docs/model_zoo.md)). Accuracy on your faces is unmeasured for either | Phase 3, 4, 5 |
| D-2 | Camera architecture | Your master prompt prefers: browser captures frames → local FastAPI processes them. **Recommended: yes**, frames over HTTP to `127.0.0.1`, never stored except as policy allows (D-9) | Phase 4 |
| D-3 | Viewer and member visibility (S5) | Proposal from your prompt: admin all household management; viewer dashboard, summaries, analytics, no member records or visitor details; member own access records and policies. Confirm whether viewers may see member **names** in event lists | Phase 2 (S5), 7, 8 |
| D-4 | Lockdown and DENY behaviour (S8) | **Recommended:** one lockdown state in SQLite, read by the engine; entering lockdown relocks the door; a DENY while open does not unlock but also relocks | Phase 2, 5 |
| D-5 | Liveness for the demo (S1) | **Recommended:** no real liveness in v1; label the demo a simulation; research options in Phase 2 and treat as P10. A simple blink/turn challenge is weak and should not be called liveness | Phase 2 |
| D-6 | Retention extension with one admin | Two-person rule blocks a single-admin home. Allow self-approval (audited) or keep two-person | Phase 7 |
| D-7 | Local embedding model for RAG | Proposed `BAAI/bge-small-en-v1.5` (MIT, ~134 MB) or `all-MiniLM-L6-v2` (Apache-2.0) (`docs/LOCAL_EMBEDDING_MODEL.md`) | Phase 9 |
| D-8 | Gemini scope | Your prompt lists "summarising approved incidents". DD-10 forbids sending household records unless an owner-approved, minimised exception is in the allowlist. Choose: incident summaries stay local and deterministic, or approve a documented exception (aggregate fields only) | Phase 9 |
| D-9 | Visitor snapshots | Store a small snapshot of unknown visitors as evidence (hashed, retained N days, purged) or store no images at all | Phase 4, 6 |
| D-10 | Notification provider | WhatsApp Cloud API (needs a Meta business account and approved templates) and/or an SMS provider; credentials only you can create | Phase 10 |
| D-11 | Frontend session | Tokens in memory (reload = login again, current default) or persisted refresh token | Phase 8 |

---

## 2. P0 blockers (exact)

| ID | Blocker | Type | Resolution | Status |
|---|---|---|---|---|
| B-1 | Sandbox cannot install Python or npm packages | Environment | Run Phase 1 on the Windows laptop (`docs/WINDOWS_SETUP_GUIDE.md`) | BLOCKED (W) |
| B-2 | Backend has never started; migrations never applied | Runtime | Guide Steps 7–14 | BLOCKED on B-1 |
| B-3 | S2: logout leaves access tokens valid | Security (High) | Phase 2, after B-2, tests first | BLOCKED on B-2 |
| B-4 | S3: engine input trust | Security (High, latent) | Enforced in the Phase 5 access service | TODO |
| B-5 | Face model and licence | Licence | D-1 | BLOCKED (decision) |
| B-6 | No webcam or browser in the sandbox | Hardware | All camera work verified on W | BLOCKED (W) |
| B-7 | No npm in the sandbox | Environment | Frontend build on W, or sandbox access change | BLOCKED |
| B-8 | No Gemini key, notification credentials | Credentials | D-8, D-10 | BLOCKED |

---

## 3. Feature tracker

### Phase 0 — Baseline

| ID | Feature | Status | Evidence |
|---|---|---|---|
| 0.1 | Backup verified, workspace compared, tests baselined | DONE (S) | `PROJECT_BASELINE_REPORT.md` |

### Phase 1 — Windows backend and database (W)

| ID | Feature | Status | Depends on | Tests / evidence required |
|---|---|---|---|---|
| 1.1 | Python 3.11 on Windows | TODO | — | `py -3.11 --version` output |
| 1.2 | venv + `pip install -r requirements.txt` + `pip check` | TODO | 1.1 | `pip list` output |
| 1.3 | `.env` with strong `SECRET_KEY` | TODO | 1.2 | check script PASS (value never shown) |
| 1.4 | Full test suite with the stack | TODO | 1.3 | 1,261 collected, 0 failed; skip reasons listed |
| 1.5 | Migrations 0001→0004 on a test DB | WRITTEN | 1.3 | four `Running upgrade` lines; `alembic current` = 0004 head |
| 1.6 | Audit-log immutability on the migrated DB (S4) | DONE (core, reference DDL) | 1.5 | `stage1_audit_log_check.py` all PASS |
| 1.7 | FastAPI starts; health and readiness | WRITTEN | 1.5 | uvicorn log; both endpoints return `ok` |
| 1.8 | Auth APIs against the running server | WRITTEN | 1.7 | new live-check script (to be written after 1.7) |
| 1.9 | Lock file + `pip-audit` (S6) | TODO | 1.4 | lock file; scan output |
| 1.10 | Report | TODO | 1.1–1.9 | `PHASE_1_BACKEND_VERIFICATION.md` |

### Phase 2 — Security findings

| ID | Finding | Status | Depends on | Tests required |
|---|---|---|---|---|
| S1 | Liveness | TODO (research) | D-5 | none until a method is chosen |
| S2 | Session-bound access tokens | TODO, confirmed open | 1.4 | failing-first: token after logout/revocation/reuse → 401; all 62 integration tests |
| S3 | Trusted engine inputs | TODO | Phase 5 | client cannot supply approver, attempts or time |
| S4 | audit_log append-only | DONE (core) | 1.6 | migrated-DB check |
| S5 | Role privacy in the backend | TODO | D-3, 1.4 | per-role 403 tests |
| S6 | Lock + scan | TODO | 1.9 | scan output |
| S7 | Encryption at rest, MFA, secret storage | TODO (evaluate) | — | written evaluation; BitLocker guidance |
| S8 | Single lockdown state | TODO | D-4 | engine + door + persistence tests |
| S9 | Rate-limit persistence / proxy | Accepted for local use | — | revisit for release |
| S10 | Atomic refresh rotation | TODO | S2 | concurrent refresh test |
| S11 | Readiness detail | Accepted for local use | — | revisit for release |
| S12 | Persistent signing key | TODO | Phase 5 | HOLD survives restart |
| S13 | Household term list for AI filter | TODO | Phase 9 | filter test with member names |
| S14 | Outdated docs | TODO | — | none (docs) |
| 2.R | Report | TODO | — | `SECURITY_REMEDIATION_REPORT.md` |

### Phase 3 — Family management and face enrolment

| ID | Feature | Status | Depends on | Tests required |
|---|---|---|---|---|
| 3.1 | Member CRUD (exists) | WRITTEN | 1.4 | 7 integration tests run |
| 3.2 | Model comparison and licence check | TODO | D-1 | written comparison with primary licence files |
| 3.3 | Migration 0005: `face_embeddings`, `permissions` | TODO | 3.2 (dimension), 1.5 | parity, constraint, runtime migration tests |
| 3.4 | Detector + recogniser adapter, quality gate | TODO | 3.2, 1.2 + `opencv-python` | recorded images: no face, multiple, dark, blurred |
| 3.5 | Enrolment (multiple samples, admin-only, consent) | TODO | 3.3, 3.4 | stores embeddings only; never for visitors |
| 3.6 | Biometric deletion | TODO | 3.5 | embeddings removed; audited |
| 3.R | Report | TODO | — | `FACE_RECOGNITION_IMPLEMENTATION_REPORT.md` |

Note: `codec.py` and `face_matching.py` take the dimension as a parameter
(default 512); SFace produces 128-D vectors, so 3.3 must record the model
and dimension per embedding (already required by SR-STORE-02).

### Phase 4 — Webcam and live monitoring

| ID | Feature | Status | Depends on | Tests required |
|---|---|---|---|---|
| 4.1 | Frame upload endpoint (admin, localhost, size limits) | TODO | D-2, 3.4 | malformed, oversized, unauthenticated uploads rejected |
| 4.2 | Browser capture, start/stop, cleanup | TODO | 8.1 | manual W test: permission denied, camera busy, disconnect |
| 4.3 | Detection status from the backend (no invented scores) | TODO | 4.1 | values come only from the response |
| 4.R | Report | TODO | — | `PHASE_4_WEBCAM_TEST_REPORT.md` |

### Phase 5 — Access-control integration

| ID | Feature | Status | Depends on | Tests required |
|---|---|---|---|---|
| 5.1 | AccessEngine rules | DONE (core) | — | 63 tests + probe |
| 5.2 | VirtualDoor rules | DONE (core) | — | 22 tests + probe |
| 5.3 | Access service: match → trusted facts (S3) → engine → door → event | TODO | 3.3, 3.4, 7.1, D-4 | enrolled → ALLOW then relock; unknown → DENY; uncertain → HOLD; forged/stale/replayed rejected |
| 5.4 | HOLD persistence, admin review, persistent key (S12) | TODO | 5.3 | review revalidated; restart safe |
| 5.5 | Lockdown API (single state) | TODO | D-4 | lockdown overrides everything |
| 5.6 | V1–V15 verification run | PARTIAL (V2–V4, V6, V15 static/core) | 5.3–5.5 | recorded results |
| 5.R | Report | TODO | — | `ACCESS_CONTROL_INTEGRATION_REPORT.md` |

### Phase 6 — Suspicious-activity detection

| ID | Feature | Status | Depends on | Tests required |
|---|---|---|---|---|
| 6.1 | Attack-chain reconstruction | DONE (core) | — | 12 tests |
| 6.2 | Explainable rules (stdlib) | TODO | 7.1 | each rule fires and names itself; no intent claims |
| 6.3 | Incident persistence | TODO | 6.2 | idempotent by incident id |
| 6.4 | Evidence capture/retrieval | PARTIAL (validation only) | D-9 | hash at capture; audited retrieval; traversal blocked |
| 6.R | Report | TODO | — | `SECURITY_MONITORING_REPORT.md` |

### Phase 7 — Event, incident and analytics backend

| ID | Feature | Status | Depends on | Tests required |
|---|---|---|---|---|
| 7.1 | SQLite event sink (pipeline → `security_events`) | TODO | 1.5 | every failed login is a row |
| 7.2 | Tables for events, incidents, evidence, workflows, retention | DONE (core, reference DDL) | — | runtime migration (1.5) |
| 7.3 | Read APIs: dashboard, recent activity, access history, events, incidents, door, lockdown, analytics | TODO | 7.1, 5.3, D-3 | pagination, filters, per-role tests |
| 7.4 | Retention and purge jobs | PARTIAL (rules only) | D-6 | purge stamps; extensions respected |
| 7.R | Report | TODO | — | `EVENT_AND_ANALYTICS_API_REPORT.md` |

### Phase 8 — Frontend

| ID | Feature | Status | Depends on | Tests required |
|---|---|---|---|---|
| 8.0 | Foundations (client, session, routes, tokens) | DONE (core, fake backend) | — | 97 tests |
| 8.1 | Vite/React/Tailwind shell, login, sidebar | TODO | B-7 | build, typecheck, lint |
| 8.2 | Dashboard + 3D scanner (R3F), reduced motion | TODO | 8.1, 7.3 | renders; empty states |
| 8.3 | Live Monitoring | TODO | 4.x, 5.3 | manual W test |
| 8.4 | Access Management, Security Events, Analytics, Settings | TODO | 7.3 | data matches DB |
| 8.5 | AI Assistant (unavailable state until Phase 9) | TODO | 8.1 | shows disabled |
| 8.R | Report | TODO | — | `FRONTEND_IMPLEMENTATION_REPORT.md` |

### Phase 9 — RAG, Gemini, agents (disabled by default)

| ID | Feature | Status | Depends on | Tests required |
|---|---|---|---|---|
| 9.0 | AI safety core | DONE (core) | — | 335 + 21 tests |
| 9.1 | Local embeddings, offline | DOCUMENTED | D-7 | live check, network off |
| 9.2 | Ingestion, ChromaDB, permission-checked retrieval | TODO | 9.1, 7.3 | no biometric data indexed |
| 9.3 | Gemini adapter (sealed payloads only) | TODO | D-8, key | live check; refusals stay local |
| 9.4 | LangGraph workflows, read-only tools, recorder | TODO | 9.2 | isolation tests still pass |
| 9.R | Report | TODO | — | `AI_RAG_AGENT_IMPLEMENTATION_REPORT.md` |

### Phase 10 — Notifications

| ID | Feature | Status | Depends on | Tests required |
|---|---|---|---|---|
| 10.1 | Table, channel interface, retry, dedupe, rate limit, delivery log | TODO | 6.2 | failure/retry tests |
| 10.2 | WhatsApp / SMS channels | BLOCKED | D-10, credentials | provider-confirmed delivery |
| 10.R | Report | TODO | — | `NOTIFICATION_IMPLEMENTATION_REPORT.md` |

### Phases 11–13

| ID | Feature | Status | Depends on | Evidence |
|---|---|---|---|---|
| 11 | 22 end-to-end workflows on W | TODO | 1–10 in scope | `FINAL_END_TO_END_TEST_REPORT.md` |
| 12 | Windows launch guide (backend, frontend, webcam, backup/restore) | PARTIAL (`WINDOWS_SETUP_GUIDE.md`, backend only, unexecuted) | 11 | `WINDOWS_PRODUCT_LAUNCH_GUIDE.md` |
| 13 | Release readiness | TODO | 12 | `FINAL_LAUNCH_READINESS_REPORT.md` |

---

## 4. Recommended sequence

1. **Phase 1 on Windows**, one step at a time (B-1, B-2).
2. Meanwhile, answer **D-1, D-2, D-3, D-4** (they gate Phases 2–5).
3. **Phase 2:** S2 (tests first), S10, S5, S6, S14, S7 evaluation.
4. **Phase 3:** model licence check → migration 0005 → adapter → enrolment.
5. **Phase 7.1** (event sink) → **Phase 5** (access service, S3, S8, S12).
6. **Phase 4** (frame upload) and **Phase 8.1–8.3** (shell, Dashboard, Live
   Monitoring), so the webcam demo flow works end to end.
7. **Phase 6**, then **7.3** read APIs, then **8.4**.
8. **Phase 10** if credentials exist (D-10).
9. **Phase 9** after the V1–V15 run (5.6), with D-7 and D-8 answered.
10. **Phase 11 → 12 → 13.**

Steps 1–6 are the minimum for a webcam demonstration.

## 5. First Windows action

Open PowerShell on the laptop and run:

```powershell
py -3.11 --version
```

Send the output. Then follow `docs/WINDOWS_SETUP_GUIDE.md` Step 2, using
the newest backup.
