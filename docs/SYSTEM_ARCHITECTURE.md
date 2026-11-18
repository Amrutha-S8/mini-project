# SYSTEM ARCHITECTURE

**Project:** AI-Powered Smart Home Security and Automated Access Management System
**Version:** 1.0 (Day 1 design)
**Status:** Design only — no implementation exists yet

---

## 1. Architectural Principles

These five principles constrain every decision in this document. Where a convenience conflicts with one of them, the principle wins.

### P1 — Deterministic access authority (non-negotiable)

**The Python `AccessEngine` (M08) is the only component permitted to decide whether the virtual door opens.** It is pure, synchronous, deterministic Python: rules, comparisons and database lookups only. It performs no network I/O, imports no AI library, and is unaware that Gemini, LangChain, ChromaDB or LangGraph exist.

**No AI component can unlock the door.** Gemini, the RAG service and the LangGraph orchestrator are strictly read-only and advisory. They receive events and produce text, summaries and recommendations. They have no code path, no API surface, and no database write permission that reaches the door. This is enforced structurally (§6), not by prompt instructions.

### P2 — One-way data flow into AI

Data flows **recognition → decision → event → database → AI**. It never flows back. The AI tier is a downstream consumer. A failure, timeout, hallucination or prompt injection in the AI tier can degrade reporting but cannot alter an access outcome, because the outcome was already computed, recorded and acted upon before the AI tier ever saw it.

### P3 — Fail secure

Every uncertainty resolves to DENY. No model loaded → deny. Low match confidence → deny. Database unreadable → deny. Scheduler down → deny. AI tier unavailable → the door is unaffected and continues denying or allowing per deterministic rules. The door's default resting state is LOCKED.

### P4 — Every decision is auditable

Each access attempt writes an immutable record containing the inputs, the matched identity (or null), the rule that fired, the outcome, and the engine version. A decision that cannot be explained from its stored record is a defect.

### P5 — Swappable externals

The face recogniser, the LLM, the vector store and the notification transport each sit behind a narrow interface with an offline stub. This is what makes the system buildable in the current no-network sandbox (see `PROJECT_AUDIT.md` §6).

---

## 2. Technology Stack

| Layer | Technology | Role | Why |
|---|---|---|---|
| API | **FastAPI** (Python 3.11) | HTTP + WebSocket surface | Async, Pydantic validation at the trust boundary, OpenAPI for the React client |
| ASGI server | Uvicorn | Process host | Standard FastAPI pairing |
| Database | **SQLite** (WAL mode) | Single source of truth | Single-household scale; zero-ops; file-level backup |
| ORM | SQLAlchemy 2.0 | Schema + repositories | Mature; typed; keeps SQL out of business logic |
| Migrations | Alembic | Schema evolution | Versioned, reversible |
| Vision | **OpenCV** | Capture, decode, crop, draw | De-facto standard for frame handling |
| Face recognition | **InsightFace** (ONNX runtime, CPU) | Detection + 512-D embeddings | Strong accuracy; see `PROJECT_AUDIT.md` §5.2 R1 for the unresolved model-weight licence |
| Vector math | NumPy | Cosine similarity | Embedding comparison is a few lines of NumPy, no extra service |
| LLM | **Gemini** (`google-generativeai`) | Narrative summaries, incident explanation | Required by spec; used advisory-only |
| LLM framework | **LangChain** | Prompt/chain/retriever plumbing | Avoids hand-rolling the RAG chain |
| Vector store | **ChromaDB** (local persistent) | Security-knowledge + event-history retrieval | Embedded, no server, matches SQLite's zero-ops posture |
| Workflow | **LangGraph** | Multi-step analyst workflow | Explicit state machine with inspectable transitions |
| Scheduler | **APScheduler** | Recurring + deferred jobs | In-process, SQLite job store, no broker needed |
| Frontend | **React** + Vite | Operator dashboard | Day 14 only |
| Auth | JWT access + refresh, Argon2id hashing | Session security | See `SECURITY_REQUIREMENTS.md` |

### 2.1 Deliberate omissions

- **No Redis / Celery / RabbitMQ.** APScheduler plus an in-process queue covers household-scale load. Adding a broker would add failure modes without benefit.
- **No Postgres.** SQLite is sufficient and keeps deployment to one file. This is a known divergence from the `fastapi-starter` reference (`PROJECT_AUDIT.md` §5.2 R2).
- **No Docker requirement for Day 1–2.** Added later if deployment demands it.
- **No cloud storage.** Evidence stays on local disk, which matters for the privacy rules in `SECURITY_REQUIREMENTS.md` §5.

---

## 3. Tier Model

```
┌──────────────────────────────────────────────────────────────────────────┐
│  TIER 5 — CLIENT                                                         │
│  React SPA (Day 14): live view, roster, access log, incidents, settings  │
└──────────────────────────────────────────────────────────────────────────┘
                   │ HTTPS (JWT)          │ WebSocket (live events)
┌──────────────────────────────────────────────────────────────────────────┐
│  TIER 4 — API                                                            │
│  FastAPI routers · Pydantic validation · authn/authz dependencies ·      │
│  rate limiting · WebSocket broadcaster                                   │
└──────────────────────────────────────────────────────────────────────────┘
                                 │
┌──────────────────────────────────────────────────────────────────────────┐
│  TIER 3 — DETERMINISTIC CORE  ◀── the only tier that can open the door   │
│                                                                          │
│  M03 Capture → M04 Detect → M05 Embed → M06 Match                        │
│                                   │                                      │
│                                   ▼                                      │
│                        ┌────────────────────┐                            │
│                        │  M08 AccessEngine  │  pure Python, no network,  │
│                        │  SOLE AUTHORITY    │  no AI imports             │
│                        └────────────────────┘                            │
│                           │              │                               │
│                   M09 Virtual Door   M07 Permissions                     │
│                                                                          │
│  M01 Auth · M02 Identity · M10 Visitor Monitoring · M11 Event Pipeline   │
│  M13 Security Detection · M14 Incidents · M19 Scheduler · M20 Notify     │
└──────────────────────────────────────────────────────────────────────────┘
                                 │  writes
┌──────────────────────────────────────────────────────────────────────────┐
│  TIER 2 — DATA                                                           │
│  M12 Repositories → SQLite (14 tables + audit_log) · evidence files ·    │
│  ChromaDB persistent collections                                         │
└──────────────────────────────────────────────────────────────────────────┘
                                 │  READ-ONLY  ▲ no write path back
┌──────────────────────────────────────────────────────────────────────────┐
│  TIER 1 — AI / ADVISORY  (cannot affect access decisions)                │
│  M15 Attack Chain Reconstruction · M16 Gemini Gateway ·                  │
│  M17 RAG (LangChain + ChromaDB) · M18 LangGraph Orchestrator             │
│  Output: text, summaries, recommendations — never commands               │
└──────────────────────────────────────────────────────────────────────────┘
```

Note the direction of the arrow between Tier 2 and Tier 1. The AI tier reads. It does not write to any operational table, and it has no reference to M08 or M09.

---

## 4. Runtime Processes

A single Uvicorn process hosts four concurrent concerns:

| Concern | Mechanism | Notes |
|---|---|---|
| HTTP/WS serving | Uvicorn event loop | Request/response and live broadcast |
| Recognition loop | Dedicated worker thread | OpenCV + ONNX are blocking and CPU-bound; keeping them off the event loop prevents API stalls |
| Event pipeline | `asyncio.Queue` consumer task | Decouples recognition from persistence and AI |
| Scheduled jobs | APScheduler background scheduler | SQLite job store so jobs survive restart |

Recognition hands off to the pipeline by enqueueing an already-decided event. **The recognition loop never waits on the AI tier**, which is what keeps P2 true under load.

---

## 5. The Access Decision Path

This is the system's critical path. It is short, synchronous and contains no AI.

```
frame ──▶ M04 detect face ──▶ M05 embed (512-D) ──▶ M06 match vs known embeddings
                                                            │
                                      ┌─────────────────────┴──────────────────┐
                                      │  similarity ≥ threshold?               │
                                      └─────────────────────┬──────────────────┘
                                          yes               │          no
                                           │                │           │
                                           ▼                │           ▼
                              identity = family_member_id   │   identity = UNKNOWN
                                           │                │           │
                                           └────────┬───────┴───────────┘
                                                    ▼
                                   ╔═══════════════════════════════╗
                                   ║  M08 AccessEngine.decide()    ║
                                   ║  ordered deterministic rules  ║
                                   ╚═══════════════════════════════╝
                                                    │
                        ┌───────────────────────────┼───────────────────────────┐
                        ▼                           ▼                           ▼
                   GRANT + reason              DENY + reason           DENY + reason
                        │                           │                   (unknown → visitor)
                        ▼                           ▼                           ▼
              M09 door.unlock(ttl)        door stays LOCKED          M10 Visitor Monitoring
                        │                           │                           │
                        └───────────────────────────┴───────────────────────────┘
                                                    ▼
                                      M11 Event Pipeline (async, fire-and-forget)
                                                    ▼
                            M12 persist → M13 detect → M14 incident → Tier 1 AI
```

### 5.1 AccessEngine rule order

Rules evaluate top-down; the first match decides and short-circuits. Order matters and is part of the security contract.

| # | Rule | Outcome |
|---|---|---|
| 1 | System in lockdown mode | **DENY** — `lockdown_active` |
| 2 | Identity is UNKNOWN / unmatched | **DENY** — `unknown_identity` |
| 3 | Match confidence below configured threshold | **DENY** — `low_confidence` |
| 4 | Family member record inactive or revoked | **DENY** — `member_inactive` |
| 5 | No permission row for this member and door | **DENY** — `no_permission` |
| 6 | Permission expired (`valid_to` in the past) | **DENY** — `permission_expired` |
| 7 | Current time outside permitted window | **DENY** — `outside_time_window` |
| 8 | Attempt rate for identity exceeds limit | **DENY** — `rate_limited` |
| 9 | All checks passed | **GRANT** — `permission_satisfied` |
| — | Any unexpected exception | **DENY** — `engine_error` (fail secure, P3) |

Every outcome carries the rule number, the rule name and the engine version into `access_events`, which is what satisfies P4.

### 5.2 Structural guarantees

- `access_engine.py` imports only the standard library, SQLAlchemy models and project types. A CI check asserts no AI package appears in its import graph.
- `VirtualDoor.unlock()` accepts an `AccessDecision` object that only the AccessEngine can construct, and asserts `decision.granted is True` plus a valid engine signature before acting.
- No HTTP route exposes a direct "unlock" action to the AI tier. Manual override by an authenticated admin is a separate, audited route that is itself recorded as an access event with source `manual_override`.

---

## 6. AI Containment Boundary

This section exists because P1 is the project's defining requirement.

| Control | Implementation |
|---|---|
| No write capability | The AI tier receives a read-only repository facade. No AI module imports a write-capable session. |
| No door reference | M15–M18 have no import of M08 or M09, enforced by a CI import-graph test. |
| No tools / no function calling | The Gemini gateway is configured without tool or function declarations, so the model has no mechanism to invoke anything. |
| Output is text only | Gemini responses are parsed into a constrained Pydantic schema (summary, severity, recommendations). Unparseable output is discarded and logged. |
| Prompt-injection containment | Visitor-supplied or camera-derived content entering a prompt is clearly delimited and treated as data. Even successful injection yields only misleading text, because text cannot open a door. |
| Advisory labelling | Every AI artefact is stored with `is_ai_generated = true` and surfaced in the UI as advisory. |
| Degraded-mode independence | If Gemini, ChromaDB or LangGraph are unavailable, access control continues unchanged. Only narrative enrichment is lost. |

---

## 7. Component Architecture by Technology

### 7.1 FastAPI layer

```
app/
  main.py                 app factory, lifespan (start scheduler, load models, open DB)
  api/v1/
    auth.py               login, refresh, logout
    members.py            family member CRUD + face enrollment
    permissions.py        permission CRUD (admin only)
    door.py               door state, manual override (audited)
    access_events.py      access history, filtering
    visitors.py           visitor events, unknown-visitor review
    incidents.py          incidents, evidence, reconstruction, AI narrative
    automation.py         APScheduler task management
    notifications.py      delivery history, preferences
    insights.py           RAG query + Gemini summary (read-only)
    ws.py                 live event stream
  core/                   config, security, deps, exceptions, logging
  schemas/                Pydantic request/response models
```

Three dependency layers guard every route: `get_current_user` (valid JWT), `require_role` (RBAC), and `require_csrf` where cookies are used. See `SECURITY_REQUIREMENTS.md` §3.

### 7.2 SQLite layer

- One file: `data/smarthome.db`.
- WAL journal mode for concurrent readers alongside the single writer.
- `PRAGMA foreign_keys = ON` enforced on every connection.
- All writes funnel through M12 repositories; no module issues raw SQL.
- Face embeddings stored as `BLOB` (float32 little-endian, 512 dims = 2048 bytes) with the dtype and dimension recorded alongside, so a model change is detectable rather than silently corrupting comparisons.
- Full schema in `DATABASE_DESIGN.md`.

### 7.3 OpenCV + InsightFace layer

```
vision/
  frame_source.py     interface: WebcamSource | FileSource | SyntheticSource
  detector.py         InsightFace detection + 5-point alignment
  embedder.py         512-D embedding extraction
  matcher.py          cosine similarity vs in-memory embedding cache
  recognizer.py       Recognizer protocol + InsightFaceRecognizer + StubRecognizer
  quality.py          blur / size / pose gates — reject bad frames before matching
```

- The embedding cache is loaded at startup and invalidated on enrollment change, so matching is an in-memory NumPy dot product rather than a per-frame database scan.
- `StubRecognizer` returns fixed identities for fixed inputs, making M08 testable with no model weights present — the mitigation for blockers E5/E6 in `PROJECT_AUDIT.md`.
- Quality gating runs **before** matching, so poor frames produce "no decision" rather than a low-confidence guess.

### 7.4 Event pipeline

```
pipeline/
  bus.py          asyncio.Queue + backpressure policy
  stages.py       validate → enrich → persist → detect → correlate → dispatch
  runner.py       consumer task, per-stage timing, error isolation
```

Each stage writes a `pipeline_logs` row with stage name, status and duration. A stage failure is isolated: it is logged and the event continues where safe, so one bad enrichment cannot drop an access record.

### 7.5 AI tier

```
ai/
  gemini/client.py        retry, timeout, token budget, MockGeminiClient
  gemini/prompts.py       versioned templates, delimited untrusted input
  rag/store.py            ChromaDB persistent client, collections
  rag/ingest.py           chunk + embed security knowledge and event history
  rag/retriever.py        LangChain retriever
  graph/state.py          typed workflow state
  graph/nodes.py          triage → retrieve → analyse → reconstruct → recommend
  graph/workflow.py       LangGraph assembly + checkpointing
  reconstruct/chain.py    deterministic attack-chain assembly (M15)
```

**M15 is deliberately deterministic.** Attack-chain reconstruction orders and correlates stored events by time, identity and camera using fixed rules. Gemini is then asked only to *describe* the already-reconstructed chain. The factual chain is reproducible without the LLM; only the prose is model-generated.

ChromaDB collections: `security_knowledge` (policies, threat patterns) and `event_history` (summarised past incidents). Neither is consulted by M08.

### 7.6 Automation (APScheduler)

- `SQLAlchemyJobStore` on the same SQLite file, so jobs survive restart.
- `max_instances=1` and `coalesce=True` to prevent pile-up.
- Job definitions live in `automation_tasks`; each run writes to `workflow_executions`.
- Representative jobs: nightly evidence retention sweep, unknown-visitor privacy purge, daily digest, embedding-cache refresh, database backup, stale-session cleanup.
- **A scheduled job may never grant access.** Jobs can trigger lockdown (a deny-side action, which is safe under P3) but cannot unlock.

### 7.7 React frontend (Day 14 — not started)

Views: Live Monitor, Family Members, Permissions, Access Log, Visitors, Incidents, Automation, Settings. State via TanStack Query over the OpenAPI schema, live updates over WebSocket. AI-generated panels are visually marked advisory. **No frontend work is performed on Day 1.**

---

## 8. Cross-Cutting Concerns

| Concern | Approach |
|---|---|
| Config | Pydantic `BaseSettings` from `.env`; secrets never in code; `.env` git-ignored |
| Logging | Structured JSON, correlation id per event, faces and embeddings never logged |
| Errors | Typed domain exceptions → consistent API error envelope; internals never leaked to clients |
| Time | UTC everywhere in storage; local time only for display and for permission-window evaluation, using an explicit household timezone |
| Testing | Pytest. The AccessEngine rule matrix is the highest-priority suite and is fully offline-testable. **No tests exist yet and none are claimed.** |
| Backup | Scheduled SQLite backup + evidence directory snapshot |

---

## 9. Deployment Topology

Single-host, all-local:

```
Host
├── uvicorn (FastAPI + recognition thread + APScheduler)
├── data/smarthome.db          SQLite (WAL)
├── data/chroma/               ChromaDB persistence
├── data/evidence/             incident snapshots (restricted permissions)
├── models/                    InsightFace ONNX weights (absent — blocker E6)
└── static/                    built React assets
```

Everything except Gemini runs offline. That is intentional: it keeps biometric data on-premise and keeps the access path functional during an internet outage.

---

## 10. Known Architectural Risks

| ID | Risk | Mitigation | Status |
|---|---|---|---|
| A1 | SQLite single-writer contention under burst event load | WAL mode, short transactions, queued single-writer pipeline | Designed |
| A2 | InsightFace model-weight licence unresolved | Recogniser interface allows substitution; licence must be cleared before use | **Open — see `PROJECT_AUDIT.md` §5.2 R1** |
| A3 | CPU-only inference may miss frame-rate targets | Quality gating, frame skipping, downscaling, detect-then-embed | Designed, unmeasured |
| A4 | Biometric data at rest is irreplaceable if leaked | Embeddings not raw images; restricted file permissions; no cloud sync | Designed |
| A5 | Prompt injection via visitor-visible content | AI is advisory-only and tool-less; injection cannot reach the door | Mitigated by P1/P2 |
| A6 | AI tier latency or failure | Fully asynchronous and out-of-band from the decision path | Mitigated by P2 |
| A7 | Gemini cost/quota | Token budget, caching, batching in digest jobs | Designed |
| A8 | No network in current environment | Offline stubs for recogniser, LLM and frame source | Mitigated for Day 1 |

**No performance figure in this document has been measured.** A3's targets are design intent and must be benchmarked on Day 7.
