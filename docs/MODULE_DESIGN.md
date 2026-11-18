# MODULE DESIGN — 20 Modules

**Project:** AI-Powered Smart Home Security and Automated Access Management System
**Version:** 1.0 (Day 1 design)
**Status:** Design only — none of these modules is implemented

---

## Module Index

| ID | Module | Tier | Can decide access? | Built on |
|---|---|---|---|---|
| M01 | Auth & Session | Deterministic | No | Day 2 |
| M02 | Identity Registry | Deterministic | No | Day 2 |
| M03 | Camera Capture & Frame Ingest | Deterministic | No | Day 3 |
| M04 | Face Detection & Alignment | Deterministic | No | Day 3 |
| M05 | Face Embedding & Enrollment | Deterministic | No | Day 3 |
| M06 | Face Matching & Identification | Deterministic | No | Day 3 |
| M07 | Permission & Policy Store | Deterministic | No (supplies rules) | Day 4 |
| **M08** | **AccessEngine** | Deterministic | **YES — sole authority** | Day 4 |
| M09 | Virtual Door Controller | Deterministic | No (executes only) | Day 4 |
| M10 | Visitor Monitoring | Deterministic | No | Day 5 |
| M11 | Event Pipeline | Deterministic | No | Day 6 |
| M12 | Persistence & Repository Layer | Data | No | Day 2 |
| M13 | Security Event Detection | Deterministic | No | Day 7 |
| M14 | Incident Manager & Evidence Store | Deterministic | No | Day 8 |
| M15 | Attack Chain Reconstruction | Advisory | No | Day 8 |
| M16 | Gemini Gateway | Advisory | **No — structurally cannot** | Day 9 |
| M17 | RAG Knowledge Service | Advisory | **No — structurally cannot** | Day 10 |
| M18 | LangGraph Orchestrator | Advisory | **No — structurally cannot** | Day 11 |
| M19 | Automation Scheduler | Deterministic | No (deny-side actions only) | Day 12 |
| M20 | Notification Service | Deterministic | No | Day 13 |

The React frontend is a **client surface**, not one of the 20 backend modules. It is specified in `SYSTEM_ARCHITECTURE.md` §7.7 and scheduled for Day 14.

---

## M01 — Auth & Session

**Responsibility.** Authenticate operators (household admins and viewers), issue and rotate JWTs, manage server-side session records, enforce role-based authorisation, and lock out brute-force attempts. This module governs *who may operate the system*. It is distinct from M08, which governs *who may walk through the door*. Conflating the two would be a security error.

| | |
|---|---|
| **Inputs** | Login credentials (email + password); refresh token; bearer token on each request |
| **Outputs** | Access token (short-lived), refresh token (rotating), `sessions` rows, auth audit entries, 401/403 responses |
| **Depends on** | M12 (users, sessions), `core.security` (Argon2id, JWT) |
| **Consumed by** | Every FastAPI route via dependency injection; M20 (recipient resolution) |
| **Integrations** | FastAPI dependency system |
| **Key behaviours** | Argon2id hashing; refresh-token rotation with reuse detection (reuse revokes the family); progressive lockout after repeated failures; logout revokes server-side so a stolen token dies early |
| **Failure mode** | Any uncertainty → 401. Never degrade to anonymous access. |

---

## M02 — Identity Registry

**Responsibility.** Own the roster of people the system recognises: family members and named recurring visitors. Manages lifecycle (create, update, deactivate, revoke) and holds the per-person attributes the AccessEngine reads, such as active status and role.

| | |
|---|---|
| **Inputs** | Member create/update payloads; deactivation requests; enrollment status callbacks from M05 |
| **Outputs** | `family_members` rows; member detail responses; change audit entries |
| **Depends on** | M12, M01 (admin-only writes) |
| **Consumed by** | M05, M06, M07, M08, M10, M14, M20 |
| **Integrations** | — |
| **Key behaviours** | Deactivation is a **soft** state change, never a delete — historical access events must keep resolving to a real person. Deactivating a member immediately invalidates their permissions at decision time (AccessEngine rule 4). |
| **Failure mode** | Member not found → treated as UNKNOWN by M08 → deny. |

---

## M03 — Camera Capture & Frame Ingest

**Responsibility.** Produce a stream of frames from whatever source is available, at a controlled rate, and hand them to the recognition chain. Isolates the rest of the system from camera hardware reality.

| | |
|---|---|
| **Inputs** | Camera device index / RTSP URL / video file path / synthetic generator config |
| **Outputs** | `Frame` objects (BGR ndarray + capture timestamp + camera id + sequence number) |
| **Depends on** | OpenCV |
| **Consumed by** | M04 |
| **Integrations** | OpenCV `VideoCapture` |
| **Key behaviours** | Single `FrameSource` interface with three drivers: `WebcamSource`, `FileSource`, `SyntheticSource`. Frame-rate throttling and frame dropping under load (newest frame wins — a stale frame is worse than no frame). Automatic reconnect with backoff. Runs in a worker thread so blocking reads never stall the API event loop. |
| **Environment note** | **No webcam exists in the current sandbox (blocker E5).** `FileSource` and `SyntheticSource` make the whole downstream chain exercisable without hardware. |
| **Failure mode** | Source unavailable → emit no frames, raise a `security_events` entry for camera offline. Absence of frames never produces a grant. |

---

## M04 — Face Detection & Alignment

**Responsibility.** Locate faces in a frame, assess whether each is good enough to identify, and produce aligned crops suitable for embedding.

| | |
|---|---|
| **Inputs** | `Frame` |
| **Outputs** | Zero or more `DetectedFace` (bounding box, 5-point landmarks, detector score, aligned crop, quality verdict) |
| **Depends on** | M03, InsightFace detector, OpenCV |
| **Consumed by** | M05, M10 (visitor snapshots), M14 (evidence) |
| **Integrations** | InsightFace detection model via ONNX runtime |
| **Key behaviours** | Quality gating **before** any identification attempt: minimum face pixel size, blur/variance-of-Laplacian threshold, pose limits, detector-score floor. A face failing quality is reported as `undecidable`, not as a weak match. This prevents the system from guessing. |
| **Failure mode** | No face → no decision, no event. Model unavailable → `engine_error` path, fail secure. |

---

## M05 — Face Embedding & Enrollment

**Responsibility.** Convert aligned face crops into 512-dimensional embeddings, and manage the enrollment workflow that binds embeddings to a family member.

| | |
|---|---|
| **Inputs** | `DetectedFace` crops; enrollment requests (member id + a set of sample images) |
| **Outputs** | L2-normalised 512-D float32 embedding vectors; `face_embeddings` rows; enrollment quality report |
| **Depends on** | M04, M02, M12, InsightFace recognition model |
| **Consumed by** | M06, M14 |
| **Integrations** | InsightFace ArcFace-family ONNX model; NumPy |
| **Key behaviours** | Multiple embeddings per member (varied pose/lighting) improve match reliability. Embeddings are stored as `BLOB` with explicit `dim` and `model_version`, so a model upgrade is detected rather than silently comparing incompatible vectors. **Raw enrollment images are not retained by default** — only embeddings — which limits biometric exposure. Enrollment rejects low-quality or duplicate-identity samples. |
| **Environment note** | **Model weights are absent and cannot be downloaded (blocker E6).** A `StubRecognizer` returning deterministic vectors stands in, so M06/M08 remain fully testable. |
| **Failure mode** | Embedding failure → no identity → M08 denies. |

---

## M06 — Face Matching & Identification

**Responsibility.** Compare a probe embedding against enrolled embeddings and return either a candidate identity with a confidence score, or UNKNOWN. **It reports; it does not authorise.**

| | |
|---|---|
| **Inputs** | Probe embedding; in-memory enrolled-embedding cache |
| **Outputs** | `MatchResult` (`family_member_id` or null, similarity score, matched embedding id, threshold used) |
| **Depends on** | M05, M12, NumPy |
| **Consumed by** | M08, M10 |
| **Integrations** | NumPy vectorised cosine similarity |
| **Key behaviours** | Cosine similarity over a normalised matrix — one dot product for the whole gallery, so matching cost does not grow with per-frame database queries. Cache rebuilt on enrollment change. Applies a configured threshold plus a **margin rule**: if the best and second-best candidates are within a small margin, the result is UNKNOWN rather than the top pick. Ambiguity resolves to unknown, never to a guess. |
| **Boundary** | Returns a *claim*, not a decision. M08 independently re-checks the threshold (rule 3) rather than trusting M06's verdict. |
| **Failure mode** | Empty gallery or error → UNKNOWN → deny. |

---

## M07 — Permission & Policy Store

**Responsibility.** Hold the authorisation rules the AccessEngine evaluates: which member may open which door, during which time windows, over which validity period. Also holds global policy state such as lockdown mode and the match threshold.

| | |
|---|---|
| **Inputs** | Permission create/update/revoke (admin only); policy setting changes |
| **Outputs** | `permissions` rows; effective-permission lookups; policy values; change audit entries |
| **Depends on** | M12, M01, M02 |
| **Consumed by** | **M08** (its primary consumer), API, M19 |
| **Integrations** | — |
| **Key behaviours** | Time windows stored as explicit day-of-week plus start/end local times, evaluated against the household timezone. Revocation is immediate and takes effect on the next decision. Every permission mutation is written to `audit_log` with before/after values, because a silent permission change is indistinguishable from an attack. |
| **Boundary** | Stores and serves rules. **Does not evaluate them** — evaluation belongs solely to M08. |
| **Failure mode** | Lookup failure → no permission found → deny. |

---

## M08 — AccessEngine ★ SOLE ACCESS DECISION AUTHORITY

**Responsibility.** Decide GRANT or DENY for every access attempt. This is the only module in the system with that power.

It is **pure, synchronous, deterministic Python**: ordered rules over data it is given plus permission lookups. It performs **no network I/O**. It imports **no AI library** — not Gemini, not LangChain, not ChromaDB, not LangGraph. It has no awareness that the AI tier exists. Given identical inputs it always returns an identical decision.

| | |
|---|---|
| **Inputs** | `MatchResult` from M06; door id; decision timestamp; permission + policy data from M07; recent attempt counts from M12; request source (`camera` / `manual_override`) |
| **Outputs** | `AccessDecision` — `granted` (bool), `reason_code`, `rule_number`, `rule_name`, `family_member_id` or null, `confidence`, `engine_version`, `decided_at`. Plus an `access_events` row and a command to M09 on grant. |
| **Depends on** | M06, M07, M12 — **and nothing else** |
| **Consumed by** | M09, M11 |
| **Integrations** | **None.** Deliberate: zero external integrations is what makes it verifiable. |
| **Rule order** | lockdown → unknown identity → low confidence → member inactive → no permission → permission expired → outside time window → rate limited → grant. First match wins. Full table in `SYSTEM_ARCHITECTURE.md` §5.1. |
| **Enforcement** | A CI import-graph test asserts no AI package is reachable from this module. `AccessDecision` is constructible only here and carries an engine signature that M09 verifies. |
| **Failure mode** | **Any** unhandled exception → `DENY / engine_error`. There is no code path that returns GRANT by default, on timeout, or on error. |
| **Why it matters** | Because this module is pure and offline, it is the one security-critical component that is **fully implementable and exhaustively testable in the current no-network sandbox.** It is therefore built first (Day 4) and its rule matrix is the project's highest-priority test suite. |

---

## M09 — Virtual Door Controller

**Responsibility.** Model the lock. Hold door state, execute unlock commands that carry a valid grant, auto-relock after a timeout, and expose state for the UI. It is an actuator, not a decider.

| | |
|---|---|
| **Inputs** | `AccessDecision` objects (grants only); relock timer expiry; lockdown commands from M19/M01 |
| **Outputs** | Door state (`LOCKED` / `UNLOCKED` / `LOCKDOWN`), state-transition events, WebSocket state broadcasts |
| **Depends on** | M08 |
| **Consumed by** | M11, API, React UI |
| **Integrations** | WebSocket broadcaster; future physical-lock driver behind the same interface |
| **Key behaviours** | **Validates every unlock request**: asserts `decision.granted is True` and that the engine signature is valid; rejects anything else and raises a `security_events` entry, since an invalid unlock attempt is itself a signal. Unlock is always time-bounded (configurable TTL) and auto-relocks. Resting state is **LOCKED**; on startup, restart or crash recovery the door initialises LOCKED. |
| **Boundary** | **No public unlock entry point.** There is no route, scheduler job, or AI path that can call unlock without an AccessEngine-issued grant. Admin manual override goes through M08 as a `manual_override` source so it is rule-checked and audited like any other attempt. |
| **Failure mode** | Unclear state → LOCKED. |

---

## M10 — Visitor Monitoring

**Responsibility.** Handle people the system does not recognise: record the encounter, capture minimal evidence, apply privacy rules, group repeat appearances, and escalate when behaviour warrants it.

| | |
|---|---|
| **Inputs** | UNKNOWN `MatchResult` + the denying `AccessDecision`; detected face crop; frame metadata |
| **Outputs** | `visitor_events` rows; snapshot evidence files; escalation signals to M13/M14; notification requests to M20 |
| **Depends on** | M04, M06, M08, M12, M14 |
| **Consumed by** | M11, M13, M20, API |
| **Integrations** | Local filesystem (evidence); OpenCV (snapshot encode) |
| **Key behaviours** | Repeat-visitor grouping via a transient embedding cluster, so three appearances by one stranger read as one visitor with three sightings rather than three unrelated events. Escalation rules: repeated denials in a short window, loitering duration, unusual hours, multiple unknown faces at once. Supports operator promotion of an unknown visitor to a named member (which hands off to M05 enrollment). |
| **Privacy** | Unknown visitors have not consented to biometric enrolment. Their transient embeddings and snapshots carry a retention deadline and are purged by an M19 job. They are **never** written to `face_embeddings`. Full rules in `SECURITY_REQUIREMENTS.md` §5. |
| **Failure mode** | Monitoring failure must not suppress the deny record — the `access_events` row is written first. |

---

## M11 — Event Pipeline

**Responsibility.** Carry every operational event from where it occurred to everything that needs to react, asynchronously and in order, with per-stage observability. This is the seam that keeps the AI tier off the critical path.

| | |
|---|---|
| **Inputs** | Events enqueued by M08, M09, M10, M01, M19 |
| **Outputs** | Persisted events; `pipeline_logs` rows per stage; downstream invocations of M13/M14/M20; WebSocket broadcasts |
| **Depends on** | M12; `asyncio` |
| **Consumed by** | M13, M14, M20; indirectly the AI tier |
| **Integrations** | `asyncio.Queue`; WebSocket broadcaster |
| **Key behaviours** | Stages: `validate → enrich → persist → detect → correlate → dispatch`. Per-stage error isolation — a failing enrichment stage is logged and skipped rather than discarding the event. Bounded queue with an explicit backpressure policy; **access events are never dropped**, lower-priority enrichment is shed first. Correlation id threads one event through every stage and every log line. |
| **Boundary** | The pipeline runs **after** the decision. It cannot alter a decision; it only propagates and enriches the record of one. |
| **Failure mode** | Pipeline stall degrades reporting and notifications. The door and the AccessEngine keep working, because they do not depend on the pipeline to function. |

---

## M12 — Persistence & Repository Layer

**Responsibility.** Own all database access. Provide typed repositories, transaction management, migrations, and the read-only facade handed to the AI tier.

| | |
|---|---|
| **Inputs** | Repository method calls from every other module |
| **Outputs** | ORM entities and DTOs; committed transactions; migration state |
| **Depends on** | SQLAlchemy 2.0, SQLite, Alembic |
| **Consumed by** | All modules |
| **Integrations** | SQLite (WAL); Alembic; APScheduler's `SQLAlchemyJobStore` shares the same file |
| **Key behaviours** | One repository per aggregate. No raw SQL outside this layer. `PRAGMA foreign_keys = ON` on every connection. Short transactions to respect SQLite's single-writer constraint. Embedding BLOB encode/decode with dimension and dtype validation on read. **A separate read-only session factory is the only database handle the AI tier ever receives**, which is how the containment rule in `SYSTEM_ARCHITECTURE.md` §6 is made structural rather than advisory. |
| **Failure mode** | Database unavailable → M08 cannot verify permissions → deny (P3). |

---

## M13 — Security Event Detection

**Responsibility.** Apply deterministic rules over the event stream to recognise suspicious patterns, and raise classified security events. Rule-based by design, so detection is explainable and reproducible.

| | |
|---|---|
| **Inputs** | Access events, visitor events, auth events, door state transitions, camera health |
| **Outputs** | `security_events` rows (type, severity, confidence, contributing event ids); incident-creation requests to M14; notification requests to M20 |
| **Depends on** | M11, M12 |
| **Consumed by** | M14, M15, M20 |
| **Integrations** | — |
| **Key behaviours** | Detection rules include: repeated denials for one identity or camera; denial burst across identities; unknown face during defined quiet hours; door opened outside any permitted window; credential brute force on M01; camera offline or frame starvation; impossible travel (same identity at two cameras within an implausible interval); a possible presentation/spoof signal from detector metadata. Each rule names itself in the output so an analyst can trace why it fired. |
| **Boundary** | Raising a security event **cannot** change an access outcome retroactively. It can trigger lockdown, which is deny-side and therefore safe under P3. |
| **Failure mode** | Detection failure loses a warning but never opens the door. |

---

## M14 — Incident Manager & Evidence Store

**Responsibility.** Group related security events into a single investigable incident, collect and protect its evidence, and track its lifecycle through to resolution.

| | |
|---|---|
| **Inputs** | Security events from M13; snapshots from M04/M10; operator actions (acknowledge, assign, resolve, add note) |
| **Outputs** | `incidents` rows; `incident_evidence` rows; evidence files on disk; incident timelines |
| **Depends on** | M12, M13, M01 |
| **Consumed by** | M15, M16, M17, M20, API |
| **Integrations** | Local filesystem with restricted permissions |
| **Key behaviours** | Correlation window groups events by time, camera and identity so one intrusion attempt becomes one incident rather than fifteen alerts. Evidence records a **SHA-256 hash at capture time**, so later tampering is detectable — evidence without integrity verification is not evidence. Status lifecycle `open → investigating → resolved → false_positive`, with severity escalation as new events attach. Evidence files live outside the web root and are served only through an authenticated, authorised route. |
| **Failure mode** | Evidence write failure is itself logged as a security event; the incident is still created. |

---

## M15 — Attack Chain Reconstruction

**Responsibility.** Rebuild the ordered sequence of actions that constitutes an incident: what happened, in what order, from which source, against which target, and which stage of an intrusion each step represents.

**This module is deterministic.** Chain assembly is fixed-rule correlation over stored events, not model inference. The factual chain is reproducible byte-for-byte without any LLM. Gemini is invoked later, by M16, only to *narrate* a chain that M15 already built. This separation is what makes the reconstruction defensible.

| | |
|---|---|
| **Inputs** | An incident id; its security events, access events, visitor events, auth events and door transitions |
| **Outputs** | An ordered `AttackChain` (steps with timestamp, actor, action, target, stage classification, supporting event ids, confidence), stored against the incident |
| **Depends on** | M12 (read), M13, M14 |
| **Consumed by** | M16, M17, M18, API |
| **Integrations** | **None** — no network, no model |
| **Key behaviours** | Timeline normalisation to UTC; actor resolution (member, unknown visitor cluster, or operator account); stage labelling such as reconnaissance → attempt → repetition → escalation → breach; gap detection that explicitly marks missing-evidence intervals instead of interpolating; confidence per step derived from how many independent events support it. |
| **Boundary** | Read-only. Writes only the reconstruction artefact against the incident. **Cannot affect access control.** |
| **Failure mode** | Insufficient data → return a partial chain with explicit gaps. **Never invent steps to fill a gap.** |

---

## M16 — Gemini Gateway

**Responsibility.** The single, controlled door to the Gemini API. Every LLM call in the system passes through here. Produces human-readable narrative from facts assembled deterministically elsewhere.

| | |
|---|---|
| **Inputs** | A structured request: task type, the deterministic facts (chain from M15, retrieved context from M17), and a template id |
| **Outputs** | A validated, schema-constrained response (summary text, severity opinion, recommendation list) tagged `is_ai_generated = true`; token-usage records |
| **Depends on** | `google-generativeai`; M15; M17 |
| **Consumed by** | M18, API (read-only insight routes) |
| **Integrations** | Gemini API (the system's only outbound dependency) |
| **Key behaviours** | Timeout, bounded retry with backoff, token budget, response caching keyed on input hash. Versioned prompt templates. **Function calling and tool declarations are disabled** — the model is given no mechanism to invoke anything. Untrusted content (visitor-derived text, filenames, operator notes) is delimited and labelled as data within the prompt. Responses are parsed into a strict Pydantic schema; unparseable output is discarded and logged, never passed through raw. A `MockGeminiClient` allows Days 9–11 to be developed and tested with no API key. |
| **Containment** | **Cannot grant access.** It has no import of M08 or M09, no write-capable database session, and no tools. Its entire output surface is text. Even a fully adversary-controlled response is inert, because nothing in the system treats model text as a command. |
| **Environment note** | **No API key and no egress exist today (blocker E7).** Mock mode is the Day 9 development path. |
| **Failure mode** | Unavailable → omit the narrative, mark the artefact as unenriched. Access control is unaffected. |

---

## M17 — RAG Knowledge Service

**Responsibility.** Retrieve relevant context — security policies, threat patterns, and summaries of past incidents — so that M16's narratives are grounded in this household's actual history rather than generic advice.

| | |
|---|---|
| **Inputs** | Documents and incident summaries for ingestion; retrieval queries from M16/M18 |
| **Outputs** | Ranked context chunks with source attribution; ChromaDB collection state |
| **Depends on** | LangChain, ChromaDB, M12 (read-only), M14 |
| **Consumed by** | M16, M18, API |
| **Integrations** | ChromaDB persistent client; LangChain retriever and splitter |
| **Key behaviours** | Two collections: `security_knowledge` (curated policy and threat-pattern documents) and `event_history` (summarised incidents). Chunking with overlap; every chunk keeps a source reference so retrieved claims are traceable. Incremental re-indexing via an M19 job. **Indexed event summaries are de-identified**: no raw embeddings, no biometric vectors, no face images enter the vector store, because a vector store is a far softer target than the primary database. |
| **Containment** | Read-only over operational data. Retrieval results are context for text generation, never inputs to M08. |
| **Failure mode** | Retrieval unavailable → M16 proceeds without context or is skipped. No effect on access. |

---

## M18 — LangGraph Orchestrator

**Responsibility.** Run the multi-step analyst workflow over an incident — triage, retrieve, analyse, reconstruct, recommend — as an explicit, inspectable state machine with persisted execution records.

| | |
|---|---|
| **Inputs** | Workflow trigger (incident id, trigger source); typed initial state |
| **Outputs** | `workflow_executions` rows (node-by-node state transitions, status, timing), written by the non-AI recorder service; the final advisory analysis attached to the incident; escalation *recommendations* that M20 acts on only after authorised approval (DD-08) |
| **Depends on** | LangGraph, M15, M16, M17, M12 (read-only) |
| **Consumed by** | M19 (scheduled runs), API, M20 |
| **Integrations** | LangGraph with checkpointing |
| **Key behaviours** | Nodes: `triage` (deterministic severity routing) → `retrieve` (M17) → `reconstruct` (M15) → `analyse` (M16) → `recommend` → `persist`. Conditional edges let low-severity incidents skip expensive LLM nodes. Every transition is recorded, so a run is replayable and explainable. Checkpointing allows resume after failure. Hard caps on node count and total duration prevent runaway loops. |
| **Containment** | **No node has write access to access-control tables, and no node can call M09.** Recommendations are stored as advisory text for an operator to act on. A workflow may *recommend* lockdown, but it cannot execute lockdown, release it, request an unlock, or change any security setting (DD-08 decision 3). Nodes call only allowlisted, read-only Python functions; Gemini has no tools (DD-08 decision 2). |
| **Failure mode** | Workflow failure is recorded with its last good state. The incident remains valid without its AI analysis. |

---

## M19 — Automation Scheduler

**Responsibility.** Run recurring and deferred maintenance, retention, digest and health jobs on a schedule that survives restarts.

| | |
|---|---|
| **Inputs** | `automation_tasks` definitions (cron/interval/date triggers, enabled flag, parameters); manual trigger requests |
| **Outputs** | Job executions recorded in `workflow_executions`; side effects of each job; failure notifications |
| **Depends on** | APScheduler, M12, and the modules each job invokes |
| **Consumed by** | M18 (scheduled analysis), M20 (digests), M06 (cache refresh), M10/M14 (retention) |
| **Integrations** | APScheduler `BackgroundScheduler` with `SQLAlchemyJobStore` on the project SQLite file |
| **Representative jobs** | Unknown-visitor privacy purge; evidence retention sweep; daily security digest; embedding-cache refresh; stale-session cleanup; database backup; camera health check; nightly incident analysis |
| **Key behaviours** | `max_instances=1` and `coalesce=True` prevent overlap and pile-up after downtime. Every run writes start, end, status and error. Misfire grace handling for jobs missed while offline. |
| **Boundary** | **No job may grant access or unlock the door.** Jobs may *enable* lockdown (deny-side). Attempting an unlock from a job is rejected by M09's grant validation. |
| **Failure mode** | A failed job is logged and notified; it never alters door state. |

---

## M20 — Notification Service

**Responsibility.** Deliver the right alert to the right person over the right channel, with deduplication, quiet-hour handling, retry and a delivery audit trail.

| | |
|---|---|
| **Inputs** | Notification requests from M10, M13, M14, M18, M19; per-user channel preferences |
| **Outputs** | `notifications` rows with delivery status; outbound messages; WebSocket toasts |
| **Depends on** | M12, M01 (recipient resolution), M11 |
| **Consumed by** | React UI; external transports |
| **Integrations** | Email (SMTP) as the baseline transport; WebSocket for in-app; a `NotificationChannel` interface so push or SMS can be added without touching callers |
| **Key behaviours** | Severity-based routing; deduplication so one intrusion does not produce twenty identical alerts; quiet hours that suppress low severity while **always** passing critical; bounded retry with backoff; full delivery-attempt history. |
| **Privacy** | Notification bodies never embed face images or embeddings. They reference an incident id and link into the authenticated UI, so evidence is only ever viewed behind authorisation. |
| **Failure mode** | Delivery failure is recorded and retried. A notification failure never changes an access outcome. |

---

## Integration Matrix

| Producer → Consumer | Carried data | Transport |
|---|---|---|
| M03 → M04 | Frames | In-process (worker thread) |
| M04 → M05 | Aligned face crops | In-process |
| M05 → M06 | Probe embedding | In-process |
| M06 → **M08** | `MatchResult` | In-process, synchronous |
| M07 → **M08** | Permissions + policy | Repository read |
| **M08** → M09 | `AccessDecision` (grant only) | Validated call |
| **M08** → M11 | Access event | Async queue |
| M08/M06 → M10 | Unknown identity + denial | In-process |
| M11 → M12 | All events | Repository write |
| M11 → M13 | Event stream | In-process |
| M13 → M14 | Security events | In-process |
| M14 → M15 | Incident + events | Read-only repository |
| M15 → M16 | Deterministic attack chain | In-process |
| M17 → M16 | Retrieved context | In-process |
| M16 → M18 | Narrative + recommendations | In-process |
| M18 → M20 | Analysis-complete alert | Async |
| M19 → M18/M20/M06/M10/M14 | Job triggers | APScheduler |
| M20 → client | Alerts | SMTP / WebSocket |

### Containment check

Reading the matrix bottom-up: **no arrow runs from M15, M16, M17 or M18 back to M08 or M09.** The AI tier is a terminal consumer. That absence is the architecture's central security property, and it is asserted by an automated import-graph test rather than left to convention.
