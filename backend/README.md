# Backend — Day 2

Operator authentication, identity registry and persistence for the
AI-Powered Smart Home Security and Automated Access Management System.

> **Dependency status: the approved stack is NOT installed.** PyPI is
> unreachable in this sandbox (proxy returns 403 on CONNECT, see
> `../docs/PROJECT_AUDIT.md` blocker E1). The HTTP layer therefore cannot be
> started or tested here. See "What is verified" below for exactly what has
> and has not been executed.

## Approved stack (no substitutions)

FastAPI · SQLAlchemy 2.0 · Alembic · Pydantic v2 · Uvicorn · Argon2id
(`argon2-cffi`) · PyJWT · SQLite

No package was swapped for an alternative. There is no hand-rolled JWT and no
raw-SQL replacement for SQLAlchemy in the application path.

## Layout

```
backend/
├── app/
│   ├── main.py                     FastAPI factory, lifespan, error handlers
│   ├── domain/                     deterministic core, stdlib only (DD-06)
│   │   ├── access_engine.py        sole access authority: ALLOW/DENY/HOLD, signed
│   │   ├── virtual_door.py         door SIMULATION state machine
│   │   ├── face_matching.py        threshold + margin matching on embeddings
│   │   ├── events.py               normalised security events
│   │   ├── evidence.py             evidence_ref validation + containment (P1)
│   │   ├── pipeline.py             validate/dedupe by event_id/persist/dispatch
│   │   ├── attack_chain.py         cross-modal incident reconstruction
│   │   └── retention.py            approved retention extensions (DD-11)
│   ├── ai/core/                    stdlib AI safety core (DD-08, DD-10); AI OFF
│   │   ├── config.py               AI_ENABLED kill switch + gate record
│   │   ├── access_policy.py        role-based retrieval filters, 3 checks
│   │   ├── sensitive.py            secret/personal/biometric detection
│   │   ├── privacy.py              Gemini egress policy, sealed payloads
│   │   ├── prompt_safety.py        templates, delimiting, injection screening
│   │   ├── output_validation.py    strict output schema, decision guard
│   │   ├── citations.py            citation + evidence-ref validation
│   │   ├── routing.py              supervisor routing, action refusals
│   │   ├── reports.py              deterministic reports
│   │   ├── escalation.py           deterministic escalation advice
│   │   └── evaluation.py           retrieval/citation/routing metrics
│   ├── core/
│   │   ├── config.py               pydantic-settings; SECRET_KEY always required
│   │   ├── rate_limit.py           login/refresh throttling (DD-05)
│   │   ├── security_headers.py     ASGI security-headers middleware
│   │   ├── security.py             Argon2id + PyJWT
│   │   ├── errors.py               typed domain errors + API envelope
│   │   ├── logging.py              JSON logging + secret redaction
│   │   └── clock.py                injectable UTC clock
│   ├── database/
│   │   ├── base.py                 DeclarativeBase, UTC datetime type
│   │   ├── session.py              writer engine + READ-ONLY engine
│   │   ├── codec.py                512-D float32 embedding BLOB codec
│   │   ├── append_only.py          canonical append-only trigger SQL (DD-09)
│   │   └── schema_reference.sql    executable reference DDL (see note)
│   ├── models/                     identity tables + events, incidents, workflows
│   ├── schemas/                    Pydantic request/response models
│   ├── api/
│   │   ├── deps.py                 auth + RBAC dependencies
│   │   └── v1/                     health, auth, members routers
│   ├── services/                   auth (M01), identity (M02), audit
│   └── utils/                      validators
├── alembic/                        migration environment + 0001 to 0004
├── tests/
├── requirements.txt
├── pyproject.toml
└── .env.example
```

## Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt        # blocked until PyPI is reachable
pip freeze > requirements.lock.txt     # capture exact pins on first success

cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste as SECRET_KEY
```

## Run

```bash
# SECRET_KEY is required by every command, including alembic and the CLI
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"

# apply migrations
alembic upgrade head

# create the FIRST admin (refuses if an admin exists; password is prompted)
python -m app.cli create-admin --email owner@example.com --full-name "Owner"

# development server
uvicorn app.main:app --reload --port 8000 --no-server-header

# production-style
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1 --no-server-header
```

Single worker is deliberate: SQLite has one writer, and from Day 6 the event
pipeline serialises writes through one consumer.

## Tests and checks

```bash
python3 -m pytest -q                      # full suite
python3 -m pytest tests/test_codec.py -q  # one file
ruff check .                              # lint
ruff format --check .                     # formatting
mypy app tests --ignore-missing-imports   # types
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/health` | none | Liveness |
| GET | `/api/v1/health/ready` | none | Readiness incl. database query |
| POST | `/api/v1/auth/register` | **admin** | Issue an operator account (role chosen by admin, default viewer) |
| POST | `/api/v1/auth/login` | none | Issue token pair |
| POST | `/api/v1/auth/refresh` | none | Rotate refresh token |
| POST | `/api/v1/auth/logout` | bearer | Revoke session server-side |
| GET | `/api/v1/auth/me` | bearer | Current operator |
| GET | `/api/v1/members` | bearer | List family members |
| GET | `/api/v1/members/{id}` | bearer | One family member |
| POST | `/api/v1/members` | **admin** | Create |
| PATCH | `/api/v1/members/{id}` | **admin** | Update |
| POST | `/api/v1/members/{id}/deactivate` | **admin** | Soft deactivate |
| POST | `/api/v1/members/{id}/revoke` | **admin** | Revoke |

There is **no door-control endpoint**. The virtual door and the deterministic
AccessEngine arrive on Day 4, and the engine remains the sole access decision
authority.

## What is verified, and what is not

Full report: `../docs/TESTING_REPORT.md`.

Current result (2026-11-16): **1198 passed, 0 failed, 63 skipped.** `ruff
check`, `ruff format --check` and `mypy` are clean.

- **Passed (1198, stdlib only):** the stdlib AI core in `app/ai/core/` (no
  model, vector store or LLM is involved), retention extensions, the
  deterministic core in `app/domain/`
  (AccessEngine, virtual door, face matching, events, pipeline, attack-chain
  reconstruction, end-to-end core workflows), rate limiting, security headers,
  validators, schema reference and static migration parity, codec, log
  redaction, read-only database boundary, import and route-authorisation
  guards, CLI and offline-installer tooling.
- **Skipped (63), each with a stated reason:**
  - 62 API integration tests: FastAPI, SQLAlchemy, Pydantic, argon2-cffi and
    PyJWT are not installed (PyPI unreachable).
  - 1 runtime migration parity test: needs SQLAlchemy and Alembic.
- **Never run:** the Uvicorn server, `alembic upgrade head`, and anything that
  touches a real database, camera, model or external service.

Defects found and fixed during the Day 2B pre-flight are listed in
`DAY2B_NOTES.md`, each marked VERIFIED or STATIC.

## Note on `schema_reference.sql`

The SQLAlchemy models are canonical and Alembic is the canonical way to apply
them. `schema_reference.sql` mirrors those models so the schema could be
executed and tested with stdlib `sqlite3` while SQLAlchemy and Alembic are
uninstallable. It is a second representation of the same schema, which is a
duplication risk.

**Status:** statically matched against migrations 0001 to 0004 by
`test_schema_parity.py`, and against the models by `test_schema_events.py`
(an `ast` reader of the model classes). The
runtime comparison of all three representations is
`test_alembic_models_and_reference_produce_identical_schemas`, which runs as
soon as SQLAlchemy and Alembic install. If it fails, the models win and this
file is corrected. Once it passes, this file can be deleted and the stdlib
schema tests pointed at a migrated database instead.

## Table scope

Ten of the fifteen designed tables exist, plus one added table:

- Migration 0001: `users` · `sessions` · `family_members` · `audit_log`
- Migration 0002 (DD-09): `access_events` · `visitor_events` ·
  `security_events` · `incidents` · `incident_evidence` ·
  `workflow_executions`, with append-only triggers
  (`app/database/append_only.py`)
- Migration 0003 (DD-11): `retention_extensions`, append-only, validated on
  insert; evidence cannot be purged while an extension runs

The remaining five designed tables arrive with their owning module (Day 3
`face_embeddings`, Day 4 `permissions`, and so on — see
`app/models/__init__.py`). Columns that will point at them are plain integers
until then. Migrations 0002 to 0004 have never been applied: SQLAlchemy and
Alembic are not installed.

## Security properties implemented

Pure-Python parts are executed by tests. Everything that needs FastAPI,
Pydantic or SQLAlchemy is written and statically checked but **not executed**.

- Argon2id password hashing; plaintext never stored or logged
- Refresh-token rotation with replay detection that revokes the session family
- Only an HMAC of each refresh token is persisted
- `SECRET_KEY` required in every environment; weak values rejected and never
  echoed (DD-05)
- Every login failure returns the same 401 after the same Argon2id work
- Per-IP and per-(IP, email) login throttling with 429 + Retry-After; accounts
  are never locked automatically, so an attacker cannot lock out the admin
  (DD-05; limiter executed by tests)
- Security headers on every response (middleware executed by tests)
- CORS without credentials, with validated origins (validator executed)
- Standard error envelope for domain and framework errors
- Default-deny route authorisation (route guard executed); admin-only
  registration; first admin from a CLI that refuses if an admin exists
- Append-only audit log with before/after values
- Read-only database engine as the AI tier's only database handle
- JSON logging with secret redaction (executed by tests)
- AccessEngine as the only access authority; HMAC-signed decisions; a door
  that rejects forged, replayed, stale or wrong-door decisions (DD-06;
  executed by tests)

Not implemented: liveness/anti-spoofing, MFA, application-level encryption at
rest, trusted-proxy client-IP handling.
