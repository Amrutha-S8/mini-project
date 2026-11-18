# Complete Testing and Verification Report

**Date:** 2026-11-16. **Environment:** Kiro sandbox, CPython 3.11.15, Node
22.23, Linux x86_64, `INTEGRATIONS_ONLY` network (PyPI and npm refused by the
proxy with `403 ERR_ACCESS_DENIED`), no webcam, no PowerShell, no Git.
**Code under test:** identical to `backup/project-snapshot-20261116-153145Z.zip`.

Skipped tests are never counted as passed.

## 1. Commands run and results

| Command (run from) | Result |
|---|---|
| `python3 -m pytest -q -rs -p no:cacheprovider` (`backend/`) | **1,198 passed, 0 failed, 63 skipped** |
| `python3 -m pytest --collect-only -q` (`backend/`) | 1,261 tests collected |
| `ruff check . ../scripts`, `ruff format --check . ../scripts` (`backend/`) | clean (111 files) |
| `mypy app tests offline --ignore-missing-imports` (`backend/`) | clean (103 source files) |
| `npm run check` (`frontend/`: tsc ×2, interim ESLint, Prettier, `node --test`) | **97 passed, 0 failed, 0 skipped**; 0 type errors; 0 lint problems |
| `scripts/windows_stage1_check.ps1` | **never executed** (no PowerShell here) |
| `scripts/stage1_audit_log_check.py` | executed manually on reference-schema databases (2026-11-16): correct DB 8 PASS; pre-0004 DB 6 FAIL; missing file FAIL; original unchanged |

## 2. Skipped tests and the exact reasons

| Count | Test | Reason printed by pytest |
|---|---|---|
| 62 | every test in `tests/test_app_integration.py` (57 functions, 2 parametrised) | `approved stack not installed: missing fastapi, sqlalchemy, pydantic, pydantic_settings, argon2, jwt (PyPI unreachable - PROJECT_AUDIT.md blocker E1)` |
| 1 | `tests/test_schema_parity.py::test_alembic_models_and_reference_produce_identical_schemas` | `needs SQLAlchemy, alembic to run migrations (PyPI unreachable - PROJECT_AUDIT.md blocker E1)` |

Conditional skips that did **not** trigger here: 9 symbolic-link tests in
`test_evidence_paths.py` skip if the account cannot create symlinks (expected
on Windows without Developer Mode).

## 3. Dependency needs

| Needs | Tests |
|---|---|
| FastAPI, SQLAlchemy, Pydantic, pydantic-settings, argon2-cffi, PyJWT (and httpx for TestClient) | 62 (`test_app_integration.py`) |
| SQLAlchemy + Alembic | 1 (runtime migration parity) |
| OpenCV or a face model | **0 — no such tests exist** |
| Webcam | **0 — no such tests exist** |
| Gemini, LangChain, ChromaDB, LangGraph, embedding model | **0 — no such tests exist** |
| Notification provider | **0 — no such tests exist** |
| Nothing beyond stdlib / Node | all 1,198 backend passes and 97 frontend passes |

## 4. Results by category

| # | Category | Files | Passed | Failed | Skipped |
|---|---|---|---|---|---|
| 1 | Static / source-level | `test_import_boundary.py` 21, `test_route_authorization.py` 23, `test_schema_parity.py` 28 (static parts); frontend `contract.test.ts` 13, `features.test.ts` 7, `source-safety.test.ts` 6 | 72 + 26 | 0 | 1 |
| 2 | Unit | `test_access_engine` 63, `test_virtual_door` 22, `test_face_matching` 18, `test_events_pipeline` 33, `test_failed_login_events` 8, `test_evidence_paths` 195, `test_attack_chain` 12, `test_core_workflows` 3, `test_retention_extensions` 50, `test_ai_*` 335 (7 files), `test_rate_limit` 19, `test_security_headers` 9, `test_validators` 36, `test_logging_redaction` 11, `test_cli` 11, `test_codec` 11, `test_offline_wheelhouse` 42 | 878 | 0 | 0 |
| 3 | Database (real SQLite, **reference DDL**, not a migrated DB) | `test_schema_events` 198, `test_schema_reference` 25, `test_readonly_boundary` 9, `test_audit_log_append_only` 16 (+ DB half of `test_retention_extensions`, counted above) | 248 | 0 | 0 |
| 4 | API integration (FastAPI TestClient) | `test_app_integration.py` | **0** | 0 | **62** |
| 5 | Frontend | 10 files, `node --test` | 97 (incl. the 26 counted in row 1) | 0 | 0 |
| 6 | Security | cross-cutting; see §5 | (included above) | 0 | 62 of the auth/authz ones |
| 7 | End-to-end | none exist | 0 | 0 | 0 |
| 8 | Hardware-dependent (webcam, model) | none exist | 0 | 0 | 0 |

Backend total: 72 + 878 + 248 = **1,198 passed**, 63 skipped.

## 5. Security-relevant tests

| Area | Ran and passed | Written but skipped |
|---|---|---|
| Authentication, sessions, tokens, throttling responses | password policy (36 validators), limiter (19), log redaction (11), CLI (11) | 62 integration tests (login, refresh rotation, reuse revocation, logout, RBAC, identical failure responses, CORS, headers) |
| Authorisation | route guard static analysis (23) | role tests in the 62 |
| AccessEngine / door | 63 + 22 + 3 workflows | — |
| Evidence path traversal (P1) | 195 | — |
| Audit trail completeness (P2) and append-only DB | 8 + 198 + 16 | — |
| Read-only database boundary | 9 + 1 | — |
| AI isolation, privacy, injection, output guards | 21 + 335 | — |
| Frontend token handling, forbidden-field scan, open-redirect, source safety | in the 97 | — |

## 6. Mocks, fakes and synthetic data

| Tests | What is simulated |
|---|---|
| `test_face_matching.py` | **Synthetic vectors**, not faces or a model |
| `test_core_workflows.py` | In-memory event sink; synthetic match results |
| `test_ai_*` | Hand-written model outputs and retrieved chunks; a fake SQLite verifier in `test_ai_access_policy.py`. No LLM, vector store or embeddings |
| `test_cli.py` | Injected fake password prompt and fake admin-creation function |
| `test_security_headers.py` | Small fake ASGI app around the real middleware |
| `test_offline_wheelhouse.py` | Fake wheel files and archives |
| Frontend tests | A scripted fake backend (`test-support/fakeServer.ts`); contract tests read the backend **source** |
| All database tests | Real SQLite, but built from `schema_reference.sql`, not from the Alembic migrations or SQLAlchemy models |

Tests that exercise actual application components with real inputs:
AccessEngine, virtual door, event pipeline, evidence validator, attack chain,
retention policy, rate limiter, validators, log redaction, AI core modules,
and the real SQLite engine with the reference schema and triggers.

## 7. What the results prove

- The deterministic security core (engine, door, matching rules, pipeline,
  evidence validation, attack chain, retention) behaves as specified for the
  inputs tested, including random probes run on 2026-11-15.
- The designed database schema, constraints and triggers work on real
  SQLite, and the migration files and models describe the same schema
  (statically).
- The AI tier has no import path to the engine, door or writer session; the
  privacy, injection and output rules behave as specified on test inputs.
- The frontend client logic agrees with the backend source contracts.

## 8. What the results do NOT prove

- That FastAPI starts, that any endpoint works, or that authentication,
  sessions or roles work in the real application.
- That Alembic can apply migrations 0001–0004, or that the SQLAlchemy models
  create the same schema at runtime.
- Anything about face detection, recognition accuracy, a webcam, a model,
  or Windows behaviour.
- Anything about Gemini, RAG, ChromaDB, LangGraph or notifications (no code).
- Any end-to-end flow. Zero end-to-end tests exist.

## 9. Real-execution milestones

| # | Milestone | Ever achieved? |
|---|---|---|
| 1 | Backend started | No |
| 2 | Migrations applied | No |
| 3 | Frontend connected to backend | No (no UI) |
| 4 | Laptop webcam opened | No |
| 5 | Enrolled member recognised | No |
| 6 | Unknown visitor denied by the running app | No (unit tests only) |
| 7 | Security event stored in SQLite by the app | No |
| 8 | Event displayed in the frontend | No |
| 9 | Real notification sent | No |
| 10 | AI/RAG workflow completed | No |

**0 of 10.**
