# AI-Powered Smart Home Security and Automated Access Management System

A smart-home access control system that recognises faces at the door, decides access with a **deterministic Python engine**, and uses AI strictly for after-the-fact investigation and reporting.

> **Current state (2026-11-15): backend foundation and deterministic security
> core written; the application has never been started.**
> 1198 tests pass, 0 fail, 63 are skipped because FastAPI/SQLAlchemy and the
> rest of the approved stack cannot be installed in the development sandbox
> (no PyPI access). Face recognition, the AI tier, notifications, analytics and
> the frontend are not built yet. See `DEVELOPMENT_PROGRESS.md` and
> `docs/TESTING_REPORT.md` for exact status. The virtual door is a software
> simulation and does not secure a real door.

---

## The Central Design Rule

**The deterministic Python `AccessEngine` is the only access decision authority. AI cannot unlock the door.**

The AccessEngine is pure, synchronous Python: nine ordered rules, no network I/O, no AI imports. Gemini, LangChain, ChromaDB and LangGraph sit in a strictly downstream, read-only advisory tier. They receive events *after* decisions are made and recorded, and they produce text — summaries, explanations, recommendations — never commands.

This is enforced structurally, not by instructing a model to behave:

| Control | Mechanism |
|---|---|
| No AI in the engine | `access_engine.py` has no AI package in its import graph (CI test) |
| No path from AI to the door | AI modules have no import of the engine or the door controller (CI test) |
| No write capability | The AI tier receives a read-only database session only |
| No tool use | Gemini is configured with tools and function calling disabled |
| Inert output | Responses are parsed into a strict schema and stored as advisory text |
| Authentic grants | An access decision is constructible only by the engine, and signature-checked by the door |
| No unlock route | No HTTP route, scheduled job or AI path reaches `unlock()` |

The one action AI can influence is **lockdown** — which only makes the system *more* restrictive, and is therefore safe under fail-secure. Releasing lockdown requires an audited admin action.

A successful prompt-injection attack against this system yields a misleading incident narrative. It does not yield an open door.

---

## Documentation

| Document | Contents |
|---|---|
| [Project Audit](docs/PROJECT_AUDIT.md) | Workspace baseline, GitHub access findings, open-source reuse assessment, environment blockers |
| [System Architecture](docs/SYSTEM_ARCHITECTURE.md) | Design principles, technology stack, five-tier model, access decision path, AI containment boundary |
| [Module Design](docs/MODULE_DESIGN.md) | All 20 modules — responsibilities, inputs, outputs, dependencies, integrations, failure modes |
| [Database Design](docs/DATABASE_DESIGN.md) | 15 tables with columns, constraints, indexes, retention, and analysis of rejected duplicate tables |
| [Data Flow](docs/DATA_FLOW.md) | Complete Mermaid diagram plus edge-by-edge containment verification and failure-mode traces |
| [Security Requirements](docs/SECURITY_REQUIREMENTS.md) | Threat model, ~90 numbered requirements, AI boundary controls, verification plan |
| [15-Day Development Plan](docs/15_DAY_DEVELOPMENT_PLAN.md) | Day-by-day roadmap with dependency gates |
| [Development Progress](DEVELOPMENT_PROGRESS.md) | Live status, blockers, Day 2 task list |

---

## Planned Technology Stack

| Layer | Technology |
|---|---|
| API | FastAPI (Python 3.11), Uvicorn |
| Database | SQLite (WAL) via SQLAlchemy 2.0, Alembic migrations |
| Vision | OpenCV |
| Face recognition | InsightFace (ONNX, CPU) — 512-D embeddings |
| LLM | Gemini — advisory only |
| LLM framework | LangChain |
| Vector store | ChromaDB (embedded, persistent) |
| Workflow | LangGraph |
| Scheduling | APScheduler (SQLite job store) |
| Frontend | React + Vite (Day 14) |
| Auth | JWT with refresh rotation, Argon2id password hashing |

---

## Architecture at a Glance

```
React client
     │  HTTPS (JWT) · WebSocket
FastAPI  ── auth · validation · RBAC · rate limiting
     │
DETERMINISTIC CORE  ◀── the only tier that can open the door
     capture → detect → embed → match
                           │
                    ┌──────▼───────┐
                    │ AccessEngine │  pure Python · no network · no AI
                    │ SOLE AUTHORITY│
                    └──────┬───────┘
                   virtual door · permissions
     │
SQLite · evidence files · ChromaDB
     │  READ-ONLY  ▲ no write path back
AI / ADVISORY TIER  (cannot affect access decisions)
     reconstruction · Gemini · RAG · LangGraph
     output: text and recommendations — never commands
```

Note the direction of the last arrow. The AI tier reads. It never writes back into the access path.

---

## The 20 Modules

**Deterministic core:** M01 Auth & Session · M02 Identity Registry · M03 Camera Capture · M04 Face Detection · M05 Face Embedding & Enrollment · M06 Face Matching · M07 Permission & Policy Store · **M08 AccessEngine** · M09 Virtual Door Controller · M10 Visitor Monitoring · M11 Event Pipeline · M12 Persistence Layer · M13 Security Event Detection · M14 Incident Manager · M19 Automation Scheduler · M20 Notification Service

**Advisory tier:** M15 Attack Chain Reconstruction (deterministic) · M16 Gemini Gateway · M17 RAG Knowledge Service · M18 LangGraph Orchestrator

Full specifications in [Module Design](docs/MODULE_DESIGN.md).

---

## Roadmap

Status vocabulary and the detailed tracker are in `DEVELOPMENT_PROGRESS.md`.

| Day | Theme | Status |
|---|---|---|
| 1 | Architecture and audit | Verified |
| 2 | Backend and database | Implemented, partly tested; **blocked** (stack not installable) |
| 3 | Face recognition | Matching core tested; capture/model **blocked** |
| 4 | **Access control — security milestone** | Core tested; API/persistence **blocked** |
| 5 | Visitor monitoring | Event core tested; persistence/API **blocked** |
| 6 | Data pipeline | Core tested; SQLite sink **blocked** |
| 7 | **Security testing — AI gate** | In progress |
| 8 | Attack chain reconstruction | Core tested; API/storage **blocked** |
| 9 | Gemini | Not started (**blocked**: package, key) |
| 10 | RAG | Not started (**blocked**: packages) |
| 11 | LangGraph | Not started (**blocked**: package) |
| 12 | Automation | Not started (**blocked**: package) |
| 13 | **Notifications and backend integration** | Not started (**blocked**: credentials, packages) |
| 14 | Frontend | Not started (**blocked**: npm registry) |
| 15 | Final integration and testing | Not started |

---

## Privacy Position

- Only **embeddings** are stored for recognition, never enrollment photographs. An embedding cannot be turned back into a face.
- **Unknown visitors are never biometrically enrolled.** Their grouping data is transient, carries a retention deadline, and is purged by a scheduled job that records proof of the purge.
- Face images and embeddings are **never** sent to Gemini, indexed into the vector store, included in notifications, or returned by any API.
- Evidence files live outside the web root with restricted permissions, are hashed at capture, and are served only through authenticated, audited routes.
- All biometric processing runs **on-premise**. Gemini is the system's only outbound dependency, and it never receives biometric data.

---

## Known Residual Risks (stated, not hidden)

Three risks are **not** mitigated in v1:

1. **No liveness detection.** A printed photo or phone screen may defeat face matching. This is the most serious open gap in the access path.
2. **No application-level encryption at rest.** Physical theft of the host may expose the embedding database. Full-disk encryption is the recommended compensating control.
3. **No MFA for operator accounts.** Password plus progressive lockout is the only barrier.

Details and threat mapping in [Security Requirements](docs/SECURITY_REQUIREMENTS.md) §8.1.

---

## Current Environment Limitations

This project is being developed in a sandbox with:

- **No outbound internet** — dependencies cannot be installed
- **No GitHub authentication** and no repository configured
- **No webcam**, no InsightFace model weights, no Gemini API key, no GPU

The architecture absorbs these deliberately: the frame source, face recogniser, LLM client and notification channel each sit behind an interface with an offline substitute. The AccessEngine — the single most security-critical component — is pure offline Python and is therefore **fully buildable and testable in this environment today**.

Full list with evidence in [Development Progress](DEVELOPMENT_PROGRESS.md).

---

## Status and Honesty Notes

- **The application has never been started.** FastAPI, SQLAlchemy and the rest of the approved stack are not installed, so no server, migration or API test has run.
- **Test results are real but limited:** 1198 stdlib tests pass, 0 fail, 63 are skipped with stated reasons (`docs/TESTING_REPORT.md`).
- **No performance figure has been measured.** All stated targets are design intent.
- **Face matching is tested on synthetic vectors only.** Recognition accuracy has not been measured; no model has been downloaded.
- **No third-party code has been downloaded or copied.** Reference repositories were assessed from search metadata only; no licence file has been read, so no licence is treated as verified. See [Project Audit](docs/PROJECT_AUDIT.md) §5.
- **Nothing has been committed or pushed.** The workspace is not a git repository.

---

## License

Not yet selected. A licence must be chosen before any third-party code is incorporated, and the InsightFace model-weight terms must be resolved first — see [Project Audit](docs/PROJECT_AUDIT.md) §5.2.
