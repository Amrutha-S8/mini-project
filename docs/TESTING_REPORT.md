# Testing Report

**Date:** 2026-11-15 · **Environment:** Kiro sandbox, CPython 3.11.15, Linux
x86_64, network mode `INTEGRATIONS_ONLY` (no PyPI, npm or GitHub access).

## 1. Result

```
pytest:          1198 passed, 0 failed, 63 skipped
ruff check:      clean
ruff format:     clean (110 files)
mypy:            clean (103 source files)
```

2026-11-16 addition (finding S4): `test_audit_log_append_only.py`, 16 passed;
`test_schema_parity.py` 28 passed, 1 skipped (+2, migration 0004).

Frontend foundations (Option B), run separately from `frontend/` with
`npm run check`: **97 passed, 0 failed, 0 skipped** (`node --test`), plus
`tsc` (strict, src and tests), interim ESLint on compiled JS, and Prettier,
all clean. The tests use a scripted fake backend, so they prove client logic
and contract agreement with the backend *source*, not the running backend.
There is no UI yet. See `frontend/README.md`.

Phase 1 additions (AI core, DD-10 privacy policy, DD-11 retention). All are
standard-library tests of project logic. None of them calls Gemini, ChromaDB,
LangGraph or an embedding model, and none is evidence of such an
integration.

| File | Tests | What is proven |
|---|---|---|
| `test_ai_config.py` | 24 | AI and Gemini off by default; only an exact `true` plus a complete gate record enables; malformed records stay off |
| `test_ai_access_policy.py` | 55 | Role matrix; vector-store filters per role; forged, malformed, re-owned, purged and stale chunks denied; fail-closed callers |
| `test_ai_privacy.py` | 87 | Every prohibited data class refused before an adapter; sanitised household data still refused; payload seal cannot be forged or edited; exception rules |
| `test_ai_prompt_output.py` | 103 | Injection screening (incl. obfuscation), delimiter forgery, relevance fallback; strict output schema; decision and action claims rejected; citation and evidence-reference checks |
| `test_ai_routing.py` | 29 | Role allowlists; action and decision refusals for every role; routing evaluation set 48/48 (hand-written, not independent) |
| `test_ai_reports_escalation.py` | 29 | Deterministic, audience-redacted reports from real attack-chain output; DST-safe windows; escalation levels; recommendations cannot act |
| `test_ai_evaluation.py` | 8 | Metric formulas against hand-computed values |
| `test_retention_extensions.py` | 50 | Unauthorised, expired and invalid extensions refused in Python and in SQLite; append-only; originals unchanged; no purge during an extension |
| `test_import_boundary.py` | 21 (+14) | AI packages only in adapters; AI core stdlib-only; no transitive path to engine, door or writer; no reverse dependency; 7 negative controls |
| `test_schema_parity.py` | 26 (+2) | Migration 0003 included in static parity |

Earlier additions (P1/P2 fixes, `TEST_RUN_2026-11-15.md` §10, and migration
0002, DD-09). The section 2 table below still describes the 370-test
baseline:

| File | Tests | What is proven |
|---|---|---|
| `test_evidence_paths.py` | 195 | P1: evidence references validated and contained, symlinks included |
| `test_failed_login_events.py` | 8 | P2: every failed login stored, including concurrent attempts |
| `test_events_pipeline.py` | +1 (33) | Duplicates only by `event_id` |
| `test_schema_events.py` | 198 | Migration 0002 tables on real SQLite: constraints, foreign keys, append-only triggers, purge and AI-labelling rules, evidence-ref check, read-only boundary; models match the reference statically; CHECK lists match the domain enums |
| `test_schema_parity.py` | 24 (+7) | Migrations 0001+0002 match the reference statically, including triggers |

Command: `cd backend && python3 -m pytest -q -rs`

Skipped tests are **not** counted as passed.

## 2. What the passing tests cover

All passing tests use the Python standard library only.

| Area | File | Tests | What is proven |
|---|---|---|---|
| AccessEngine | `test_access_engine.py` | 63 | Every rule 1–9 and its boundaries; HOLD cases; engine re-checks the score; policy cannot be configured to ALLOW unknown visitors or out-of-window attempts; fail-secure on naive time, bad timezone and garbage input; signatures; admin review cannot bypass lockdown, revocation, expired or removed permission; forged, resolved, expired, non-HOLD reviews denied; unknown-visitor approval is a single guest entry; manual override; weekday, overnight, timezone and DST windows |
| Virtual door | `test_virtual_door.py` | 22 | Starts locked; ALLOW unlocks for the TTL then relocks; DENY/HOLD stay locked; forged, foreign-signer, wrong-door, replayed, stale and future decisions rejected; lockdown; manual lock; duration bounds; restart is locked; failing listener cannot affect the lock |
| Face matching | `test_face_matching.py` | 18 | Threshold, margin (per member), unknown, ambiguous, no face, multiple faces, poor quality, empty gallery, invalid embeddings; matching never enrolls. **Synthetic vectors, not faces.** |
| Events and pipeline | `test_events_pipeline.py` | 32 | Normalisation, UTC conversion, 14 validation failures, redaction of secrets/embeddings/binary, de-duplication, future-timestamp rejection, quality warnings, persist-before-dispatch, sink failure not dispatched and retryable, listener isolation |
| Attack chain | `test_attack_chain.py` | 12 | Single events ignored; credential attack grouped; cross-modal chain with explained temporal links; allowed-after-suspicious highlighted without judging intent; household IP does not merge normal activity; gaps reported; deterministic ids; evidence refs; module cannot import the engine or door |
| Core workflows | `test_core_workflows.py` | 3 | Workflows A (member enters, door relocks), B (unknown visitor stays anonymous and locked), C (suspicious chain reconstructed; forged unlock refused; lockdown holds at engine and door) — **core only** |
| Rate limiting | `test_rate_limit.py` | 19 | Sliding window, expiry, bounded memory, thread safety, attacker IP blocked while admin IP is not, unknown and known emails throttled identically |
| Security headers | `test_security_headers.py` | 9 | Every header, CSP exemption for `/docs`, HSTS only when enabled, no overriding |
| Validators | `test_validators.py` | 36 | Password policy, email, secret rules (value never echoed), CORS origin rules |
| Containment | `test_import_boundary.py` | 7 | No AI package in the backend; domain core imports only stdlib (negative control executed: injected `socket` and `app.models` imports were caught) |
| Route authorisation | `test_route_authorization.py` | 23 | Every route requires auth unless allowlisted; admin routes require admin |
| Persistence design | `test_schema_reference.py`, `test_schema_parity.py`, `test_readonly_boundary.py`, `test_codec.py` | 25 + 17 + 9 + 11 | Reference schema and constraints in SQLite; migration matches it statically; read-only connection rejects every write; embedding codec |
| Other | `test_logging_redaction.py`, `test_cli.py`, `test_offline_wheelhouse.py` | 11 + 11 + 42 | Log redaction; create-admin CLI; offline installer tooling |

## 3. Skipped (64)

| Count | Reason | Unblocked by |
|---|---|---|
| 62 | `test_app_integration.py`: FastAPI, SQLAlchemy, Pydantic, argon2-cffi, PyJWT not installed | Wheelhouse upload or PyPI access |
| 1 | `test_schema_parity.py`: runtime Alembic vs models vs reference | Same |
| ~~1~~ 0 | `test_import_boundary.py`: AI tier check now runs (Phase 1) | — |

The 62 integration tests cover: startup, health/readiness, tables, admin-only
registration, duplicate rejection, Argon2id storage, login success/failure,
identical responses for unknown/locked/inactive accounts, 429 throttling,
admin not locked out by attacker, refresh rate limit, session auth, token
forgery, refresh rotation and reuse revocation, logout, RBAC, member CRUD,
audit actors, no plaintext in audit, settings secret validation, security
headers on 200/401/404/422, 404/405 envelopes, CORS allow/deny.

## 4. Not tested at all

- The FastAPI server, migrations and every API endpoint (blocked).
- Webcam capture, face detection, embedding extraction, recognition accuracy
  (blocked: packages, model licence, no camera in the sandbox).
- Gemini, RAG, LangGraph, APScheduler, WhatsApp, SMS, analytics (not built;
  blocked by packages and credentials).
- Frontend (not built; npm registry blocked).
- Performance and load.

## 5. Defects found by tests during this stage

- `test_core_workflows.py` initially failed: after lockdown, the test fed an
  ALLOW decision to the door and expected the door to stay in lockdown
  silently. The door correctly *raised* `InvalidUnlockError("lockdown_active")`.
  The test expectation was wrong; it now asserts the rejection and also checks
  that the engine itself denies under a lockdown policy.
- mypy found untyped `**dict` unpacking in `face_matching.py`; rewritten with a
  typed helper.
