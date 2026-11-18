# 15-DAY DEVELOPMENT PLAN

**Project:** AI-Powered Smart Home Security and Automated Access Management System
**Order:** Fixed as agreed with the project owner. Day numbers and themes are not re-sequenced.
**Current position:** **Day 1 complete. Day 2 not started.**

---

## Schedule Overview

| Day | Theme | Modules | Status |
|---|---|---|---|
| 1 | Architecture and audit | — (documentation) | ✅ **COMPLETE** |
| 2 | Backend and database | M12, M01, M02 | ⬜ Not started |
| 3 | Face recognition | M03, M04, M05, M06 | ⬜ Not started |
| 4 | Access control | M07, **M08**, M09 | ⬜ Not started |
| 5 | Visitor monitoring | M10 | ⬜ Not started |
| 6 | Data pipeline | M11 | ⬜ Not started |
| 7 | Security testing | Verification of M01–M11 | ⬜ Not started |
| 8 | Attack chain reconstruction | M13, M14, M15 | ⬜ Not started |
| 9 | Gemini | M16 | ⬜ Not started |
| 10 | RAG | M17 | ⬜ Not started |
| 11 | LangGraph | M18 | ⬜ Not started |
| 12 | Automation | M19 | ⬜ Not started |
| 13 | Notifications and backend integration | M20 + integration | ⬜ Not started |
| 14 | Frontend | React client | ⬜ Not started |
| 15 | Final integration and testing | Whole system | ⬜ Not started |

### Dependency gates

Three gates control the schedule:

- **Day 4 is the security milestone.** M08 must be complete and exhaustively tested before any other module is trusted to interact with the door.
- **Day 7 is the AI gate.** Checks V2–V5 in `SECURITY_REQUIREMENTS.md` §9 must pass before Day 9 enables the first AI module. If they fail, the AI tier stays disabled and Days 9–11 slip rather than proceeding unverified.
- **Day 13 is the integration gate.** The full backend must work end-to-end before frontend work begins on Day 14.

### Environment dependency

Days 3, 9, 10 and 11 need resources that are currently unavailable (model weights, Gemini key, package installation). See `PROJECT_AUDIT.md` §6. Each affected day below states its offline fallback, so work can proceed in mock mode and be swapped to live later.

---

## DAY 1 — Architecture and Audit ✅ COMPLETE

**Goal.** Establish the full design and an honest baseline before writing code.

**Delivered.**
- `docs/PROJECT_AUDIT.md` — empty-baseline record, GitHub access findings, open-source reuse assessment, eight environment blockers
- `docs/SYSTEM_ARCHITECTURE.md` — five principles, stack, five tiers, decision path, AI containment
- `docs/MODULE_DESIGN.md` — 20 modules with responsibilities, inputs, outputs, dependencies, integrations
- `docs/DATABASE_DESIGN.md` — 14 required tables + `audit_log`, with rejected-duplicate analysis
- `docs/DATA_FLOW.md` — complete Mermaid flow, structurally checked
- `docs/SECURITY_REQUIREMENTS.md` — threat model, ~90 requirements, verification plan
- `docs/15_DAY_DEVELOPMENT_PLAN.md` — this document
- `DEVELOPMENT_PROGRESS.md`, `README.md`

**Not done, by instruction.** No code, no frontend, no Day 2 work, no commit, no push.

**Key outcome.** The AccessEngine was designed as pure offline Python specifically so the most security-critical module can be fully built and verified despite every environment blocker.

---

## DAY 2 — Backend and Database

**Goal.** A running FastAPI application with the full schema, repositories, and operator authentication.

**Build.**
1. Project scaffold: `app/` package layout per `SYSTEM_ARCHITECTURE.md` §7.1, `pyproject.toml`, `.env.example`, `.gitignore`
2. Pydantic `BaseSettings` configuration; refuse to boot on a default signing secret (SR-STORE-09)
3. SQLAlchemy 2.0 models for all 15 tables in `DATABASE_DESIGN.md`
4. Alembic initialised; first migration generated and applied
5. SQLite setup: WAL mode, `foreign_keys = ON` per connection, `busy_timeout`
6. **M12** repositories per aggregate, plus the **read-only session factory** that the AI tier will later receive
7. **M01** auth: Argon2id hashing, JWT issue/verify, refresh rotation with reuse detection, lockout, `sessions` lifecycle
8. **M02** identity registry CRUD with soft deactivation
9. FastAPI app factory, lifespan, health endpoint, error envelope, structured JSON logging
10. `audit_log` writer wired into auth and member mutations

**Verify.** App boots; migration applies cleanly; login/refresh/logout round-trip; embedding BLOB encode-decode preserves 512 float32 values exactly; unauthenticated request to a protected route returns 401.

**Done when.** `uvicorn` serves, all 15 tables exist, auth works, every write goes through a repository.

**Blocker.** E1 — `pip install` needs PyPI access. Mitigation: owner provides egress or a wheel cache.

**Requirements covered.** SR-AUTH-02…14, SR-AUTHZ-01/02/05, SR-STORE-06/07/09/14/15/17, SR-AUDIT-03/04/11/12.

---

## DAY 3 — Face Recognition

**Goal.** Frames in, embeddings out, identities matched — with a working offline substitute.

**Build.**
1. **M03** `FrameSource` interface; `WebcamSource`, `FileSource`, `SyntheticSource`; throttling, newest-frame-wins dropping, reconnect backoff; worker thread
2. **M04** InsightFace detection + 5-point alignment; `quality.py` gates for size, blur, pose, detector score; `undecidable` verdict path
3. **M05** 512-D embedding extraction, L2 normalisation; enrollment workflow accepting multiple samples per member; quality and duplicate-identity rejection; discard raw images after extraction
4. **M06** NumPy vectorised cosine matching over an in-memory gallery; **second-best margin rule** returning UNKNOWN on ambiguity; gallery cache with invalidation on enrollment change
5. **`Recognizer` protocol** with `InsightFaceRecognizer` and **`StubRecognizer`**
6. Enrollment API endpoints, admin-only

**Verify.** Synthetic frames flow end-to-end; quality gate rejects a deliberately blurred frame; embedding round-trips through the database unchanged; the margin rule returns UNKNOWN for two near-identical candidates; `StubRecognizer` gives reproducible identities.

**Done when.** The chain capture → detect → embed → match runs on `FileSource`/`SyntheticSource` with no camera and no model weights, using the stub.

**Blockers.** E5 no webcam, E6 no model weights, E8 CPU only. Mitigation: `FileSource` + `SyntheticSource` + `StubRecognizer` make the whole chain exercisable. Live InsightFace is enabled only after the licence question in `PROJECT_AUDIT.md` §5.2 R1 is resolved.

**Requirements covered.** SR-AUTH-15/16/17, SR-STORE-01/02/03/16, SR-PRIV-01.

---

## DAY 4 — Access Control ★ SECURITY MILESTONE

**Goal.** The deterministic decision authority, complete and exhaustively tested.

**Build.**
1. **M07** permission and policy store: CRUD, timezone-aware window evaluation data, immediate revocation, lockdown and threshold policy values, audited mutations
2. **M08 AccessEngine** — the project's core:
   - `AccessDecision` dataclass, constructible only here, carrying an engine signature
   - Nine ordered rules, first match wins, per `SYSTEM_ARCHITECTURE.md` §5.1
   - Blanket exception guard returning `DENY / engine_error`
   - **Pure Python: no network, no AI imports, no external integration**
3. **M09** virtual door controller: state machine, grant validation asserting `granted is True` plus engine signature, time-bounded unlock with auto-relock, LOCKED on startup and crash recovery, invalid-unlock attempts raised as security events
4. Manual admin override routed **through M08** with `source = manual_override`
5. `access_events` persistence capturing rule, reason, engine version, confidence, threshold, latency
6. Door state API + WebSocket broadcast

**Verify (this is the heaviest test day).**
- Exhaustive rule matrix: each of rules 1–9 fires under the exact condition intended and not otherwise
- Boundary cases: confidence exactly at threshold; permission expiring this second; time window at both edges; DST-ambiguous local time resolving to the **more restrictive** reading
- Fail-secure matrix: null identity, missing permission, inactive member, lockdown, injected database error, injected engine exception — **all must DENY**
- Forged `AccessDecision` rejected by M09
- Door initialises LOCKED; unlock auto-relocks; no indefinite unlock reachable
- Determinism: identical inputs produce byte-identical decisions across repeated runs

**Done when.** Every rule and every fail-secure case is covered by a passing test, and the engine has zero non-stdlib runtime dependencies beyond SQLAlchemy models.

**Blockers.** **None.** M08 is pure offline Python. This day is fully achievable in the current environment, which is why the architecture was shaped this way.

**Requirements covered.** SR-AUTHZ-06…16, SR-AI-03/04, SR-AUDIT-01/02.

---

## DAY 5 — Visitor Monitoring

**Goal.** Handle unknown people correctly and privately.

**Build.**
1. **M10** visitor event recording triggered by `unknown_identity` denials
2. Transient embedding clustering for repeat-sighting grouping — **in memory, never written to `face_embeddings`**
3. Snapshot capture: minimal crop, SHA-256 at capture, restricted-permission path outside the web root, `retention_expires_at` set at creation
4. Escalation rules: repeated denials in a window, loitering duration, quiet-hours appearance, multiple simultaneous unknown faces
5. Operator review API: mark benign/suspicious, promote to member (handing off to consented M05 enrollment)
6. Authenticated, audited snapshot retrieval route with server-generated filenames

**Verify.** Three denials by one synthetic stranger group into one cluster with three sightings; retention deadline is set on every row; no `face_embeddings` row is created for an unknown; path traversal on snapshot retrieval is rejected; unauthenticated snapshot access returns 401.

**Done when.** Unknown encounters are recorded, grouped, escalated and privacy-bounded, with the deny record always written first.

**Requirements covered.** SR-PRIV-01…11, SR-STORE-10/11/12/13.

---

## DAY 6 — Data Pipeline

**Goal.** Asynchronous event propagation that keeps the AI tier off the critical path.

**Build.**
1. **M11** bounded `asyncio.Queue` with an explicit backpressure policy — **access events never dropped**, enrichment shed first
2. Stages `validate → enrich → persist → detect → correlate → dispatch`, each with error isolation
3. `pipeline_logs` row per stage with status, duration and queue depth
4. Correlation id threading every stage and every log line
5. Consumer task started in the app lifespan; graceful drain on shutdown
6. WebSocket broadcaster fed from the dispatch stage

**Verify.** An event traverses all six stages and produces six log rows sharing one correlation id; a deliberately failing enrich stage is logged and skipped while the event still persists; queue saturation sheds enrichment but not access events; a stalled pipeline does not affect door behaviour.

**Done when.** Events flow asynchronously with per-stage observability, and pipeline failure is proven not to affect access decisions.

**Requirements covered.** SR-AUDIT-05/11, plus architecture principle P2.

---

## DAY 7 — Security Testing ★ AI GATE

**Goal.** Prove the security claims made in `SECURITY_REQUIREMENTS.md` before any AI module is enabled.

**Execute the V1–V15 plan** from `SECURITY_REQUIREMENTS.md` §9. The four gating checks:

| Check | Asserts |
|---|---|
| **V2** | No AI package is reachable from M08's import graph |
| **V3** | M15–M18 contain no import path to M08 or M09 |
| **V4** | A forged `AccessDecision` is rejected by M09 |
| **V5** | No route, job or AI path reaches `unlock()` without an engine grant |

Also: V1 rule matrix re-run, V6 read-only session enforcement, V8 fail-secure matrix, V9 IDOR probes, V10 refresh reuse, V11 audit completeness, V12 append-only enforcement, V13 purge verification, V14 secret and embedding leak scan, V15 path traversal.

Plus the first real **performance measurement**: decision latency, detection and embedding time, pipeline throughput. These replace the design-intent figures in `SYSTEM_ARCHITECTURE.md` §10 A3 with measured numbers.

**Gate rule.** If V2, V3, V4 or V5 fails, **Day 9 does not start.** The AI tier remains disabled until the claim "AI cannot unlock the door" is demonstrably true.

**Done when.** V1–V15 results are recorded with actual command output, and the four gating checks pass.

**Note.** This is the first day on which any test result exists. Until it completes, **no test claim may be made anywhere in this project's documentation.**

---

## DAY 8 — Attack Chain Reconstruction

**Goal.** Deterministic incident reconstruction, built before any LLM touches it.

**Build.**
1. **M13** rule-based security detection: repeated denial, denial burst, brute-force login, camera offline, quiet-hours unknown face, impossible travel, invalid unlock attempt, possible presentation signal — each naming its own rule
2. **M14** incident correlation by time/camera/identity window; evidence attachment with capture-time SHA-256; status lifecycle; severity escalation
3. **M15** deterministic chain assembly: UTC timeline normalisation, actor resolution, stage labelling (reconnaissance → attempt → repetition → escalation → breach), **explicit gap marking**, per-step confidence from supporting event count
4. Lockdown trigger on high severity (deny-side only)
5. Incident and chain API endpoints

**Verify.** A scripted multi-step intrusion sequence produces one incident, not fifteen alerts; the reconstructed chain is **byte-identical across repeated runs** on the same data; a deliberate evidence gap is marked as a gap and **no step is invented to fill it**; evidence hash mismatch raises a security event.

**Done when.** Incidents reconstruct deterministically with zero model involvement — the property that makes Day 9's narratives trustworthy.

**Requirements covered.** SR-AI-13, SR-STORE-11, SR-AUDIT-06/07.

---

## DAY 9 — Gemini

**Goal.** Narrative generation, contained.

**Build.**
1. **M16** Gemini gateway: timeout, bounded retry with backoff, token budget, response caching keyed on input hash
2. Versioned prompt templates in code; untrusted content delimited and labelled as data
3. **Tools and function calling disabled** (SR-AI-07)
4. Strict Pydantic response schema; unparseable output discarded and logged, never passed through
5. `MockGeminiClient` for offline development
6. Incident narrative and recommendation generation from M15's deterministic chain
7. Advisory storage: `ai_summary`, `ai_recommendations`, `ai_model_version`, `is_ai_enriched = 1`

**Verify.** Mock client drives the full path with no key; adversarial fixtures — including responses that instruct the system to unlock — produce **no action** and are discarded; the AI tier's write attempt to `permissions` raises on the read-only session; Gemini unavailable leaves the incident valid but unenriched; the door is provably unaffected throughout.

**Done when.** Narratives are generated and stored as advisory, and V7 passes with adversarial fixtures.

**Blocker.** E7 — no API key, no egress. Mitigation: `MockGeminiClient` is the development path; live calls deferred.

**Requirements covered.** SR-AI-01/02/05/06/07/08/10/11/12/14/15/16.

---

## DAY 10 — RAG

**Goal.** Ground narratives in this household's actual history.

**Build.**
1. **M17** ChromaDB persistent client; collections `security_knowledge` and `event_history`
2. LangChain splitter and retriever; chunking with overlap; **source attribution on every chunk**
3. Ingestion of curated policy and threat-pattern documents
4. **De-identified** incident summarisation into `event_history` — no embeddings, no biometric vectors, no face images (SR-PRIV-07)
5. Incremental re-indexing hook for the Day 12 scheduler
6. Read-only insight query endpoint

**Verify.** Retrieved chunks carry resolvable source references; a seeded past incident is retrieved for a similar new query; the vector store contains **no biometric data** (asserted by test); ChromaDB unavailable degrades Gemini to context-free operation with no effect on access.

**Done when.** Retrieval improves narrative grounding and the no-biometrics assertion passes.

**Blocker.** E1 for package installation.

**Requirements covered.** SR-PRIV-07, SR-AI-05.

---

## DAY 11 — LangGraph

**Goal.** The analyst workflow as an inspectable state machine.

**Build.**
1. **M18** typed workflow state
2. Nodes: `triage` (deterministic routing) → `retrieve` (M17) → `reconstruct` (M15) → `analyse` (M16) → `recommend` → `persist`
3. Conditional edges letting low-severity incidents skip LLM nodes
4. Checkpointing for resume after failure
5. Hard caps on node count and total duration
6. `workflow_executions` recording every transition, `current_node`, status, timing, token usage

**Verify.** A full run records node-by-node transitions and is replayable; low severity skips the expensive nodes; a forced mid-workflow failure records the last good state and is resumable; node-count cap halts a deliberate loop; **no node can reach M08 or M09** (V3 re-run); the strongest requestable action is lockdown, never unlock.

**Done when.** Workflows run, persist, resume, and remain provably contained.

**Requirements covered.** SR-AI-01/02/17/18.

---

## DAY 12 — Automation

**Goal.** Scheduled maintenance that survives restarts.

**Build.**
1. **M19** APScheduler `BackgroundScheduler` with `SQLAlchemyJobStore` on the project SQLite file; `max_instances=1`, `coalesce=True`, misfire grace handling
2. Job registry — a **fixed in-code allowlist**; `automation_tasks.job_callable` resolves against it and is **never dynamically imported or evaluated**
3. Jobs: unknown-visitor privacy purge, evidence retention sweep, daily security digest, embedding-gallery refresh, stale-session cleanup, database backup, camera health check, nightly incident analysis
4. `workflow_executions` recording for every run
5. Task management API, admin-only and audited

**Verify.** Jobs survive a process restart; the purge job deletes expired visitor data and **stamps `purged_at`** (V13); overlapping triggers do not double-run; a scheduler-initiated unlock attempt is **rejected by M09's grant validation**; an arbitrary string in `job_callable` fails to resolve rather than importing anything.

**Done when.** Scheduled jobs run reliably and the no-unlock-from-automation property is tested.

**Requirements covered.** SR-PRIV-03/04, SR-AI-02, SR-AUDIT-08/09.

---

## DAY 13 — Notifications and Backend Integration ★ INTEGRATION GATE

**Goal.** A complete, coherent backend.

**Build.**
1. **M20** notification service: severity routing, deduplication, quiet hours that always pass critical, bounded retry with backoff, full delivery history
2. `NotificationChannel` interface; SMTP email and WebSocket in-app implementations
3. Per-user preferences
4. **No biometric content in message bodies**; incident id + authenticated UI link only (SR-PRIV-08)
5. Full backend integration pass: all 20 modules wired through the app lifespan
6. OpenAPI schema finalised for the Day 14 client
7. End-to-end scenario runs: known-member grant, unknown-visitor escalation to incident to AI narrative, scheduled purge

**Verify.** One intrusion sequence produces a single deduplicated alert rather than a storm; quiet hours suppress low severity and pass critical; delivery failure is recorded and retried; no notification body contains an image or embedding (V14); the three end-to-end scenarios complete; the full V1–V15 suite is re-run against the integrated system.

**Done when.** The backend works end-to-end and the security suite still passes after integration.

**Requirements covered.** SR-PRIV-08, SR-AUDIT-10, plus full re-verification.

---

## DAY 14 — Frontend

**Goal.** The React operator dashboard. **Not started before Day 14.**

**Build.**
1. Vite + React scaffold; TanStack Query against the OpenAPI schema
2. Views: Live Monitor, Family Members, Permissions, Access Log, Visitors, Incidents, Automation, Settings
3. WebSocket live updates for door state and events
4. **AI panels visually marked advisory** (SR-AI-15); recommendations require explicit operator action (SR-AI-16)
5. Auth flow with silent refresh; role-based UI gating
6. Evidence viewing through authenticated routes only

**Verify.** Live door state updates over WebSocket; role gating hides admin controls from `viewer`; AI content is visibly labelled advisory; no recommendation auto-applies; **no endpoint relies on UI gating for authorisation** — server-side checks re-verified.

**Done when.** An operator can monitor, manage and investigate through the UI.

**Note.** UI gating is cosmetic. Authorisation is server-side, and Day 14 must not introduce a client-trusted control path.

---

## DAY 15 — Final Integration and Testing

**Goal.** Verified, documented, shippable.

**Execute.**
1. Full-system end-to-end scenarios across frontend and backend
2. Complete V1–V15 re-run with recorded output
3. Performance measurement under sustained load; compare against Day 7 figures
4. Fail-secure drill: kill the camera, the database, Gemini, ChromaDB and the scheduler in turn, and confirm the door's behaviour in each case
5. **Final AI containment audit** — V2–V5 re-run against the complete system as the last security act of the project
6. Backup and restore drill
7. Residual-risk review: confirm the three open risks in `SECURITY_REQUIREMENTS.md` §8.1 are still accurately documented
8. Deployment documentation, operator runbook, `README.md` finalisation
9. `THIRD_PARTY_NOTICES.md` if any third-party source was ultimately vendored

**Done when.** Every verification check has recorded output, the fail-secure drill passes in all five cases, and the AI containment audit passes on the finished system.

---

## Cross-Cutting Discipline

Applied every day, not deferred:

| Practice | Rule |
|---|---|
| Fail secure | Every new failure mode must resolve to DENY and gain a test |
| Audit | Every new security-relevant action writes to `audit_log` |
| AI containment | Every new AI code path re-runs V2 and V3 |
| No invented results | A test is "passing" only with recorded command output |
| Licence hygiene | No third-party source enters the repository until its `LICENSE` is read and recorded in `PROJECT_AUDIT.md` |
| Migrations | Every schema change is a reversible Alembic migration |
| Secrets | Never in code, logs, errors or prompts |

---

## Risks to the Schedule

| Risk | Affects | Mitigation |
|---|---|---|
| **E1 no network** — cannot install dependencies | Days 2–14 | **Owner action required.** Highest-priority blocker. |
| **E2/E3 no repository** — work is unbacked | All days | Owner supplies credential + `owner/repo` |
| **R1 InsightFace model-weight licence unresolved** | Day 3 onward | Recogniser interface allows substitution; clear the licence before live use |
| E6 no model weights | Day 3 | `StubRecognizer` |
| E7 no Gemini key | Days 9–11 | `MockGeminiClient` |
| E5 no webcam | Days 3, 5 | `FileSource`, `SyntheticSource` |
| Day 7 gate fails | Days 9–11 | AI tier stays disabled; fix containment before proceeding |
| CPU-only inference too slow | Day 3, 7 | Quality gating, frame skipping, downscaling |

### The schedule's structural strength

Days 2 and 4 — the database and the AccessEngine — depend on **no blocked resource**. The single most security-critical component in the system can be built and exhaustively verified today, in this environment, with nothing installed and no network. Everything that is blocked is either substitutable by a stub or confined to the advisory tier, where failure costs narrative quality rather than security.

---

## Current Status

**Day 1 is complete.** Days 2–15 have not started. No code exists. No test has been run. No result is claimed.

**Day 2 begins only on the project owner's approval.**
