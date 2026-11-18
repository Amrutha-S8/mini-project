# Day 2B working notes

## Environment (verified 2026-11-14 14:29 UTC)

- network_mode: INTEGRATIONS_ONLY (NOT Common dependencies)
- Container boot 12:24:48 UTC, same container as every earlier session
- PyPI / files.pythonhosted.org / npm / github.com: HTTP 000, proxy 403 on CONNECT
- `pip download fastapi`: "No matching distribution found"
- GitHub: `gh api user` -> 404 "No user principal found"
- No wheelhouse in the workspace, no pip cache, no approved package in any pyenv Python

Result: install, migrate, uvicorn and the integration tests CANNOT run. Nothing installed.

## What can be done honestly while blocked

A static pre-flight review of code that has never executed. Each fix is labelled
"static, unverified" unless a stdlib test proves it.

## Candidate defects found by reading the code

| ID | File | Defect | Severity | Testable now? |
|----|------|--------|----------|---------------|
| D1 | services/auth_service.py | Failure paths write lockout counter / failure audit / token-reuse revocation, then raise. get_session() rolls back on exception, so these writes are lost. Lockout never triggers; reuse detection never revokes the family. | CRITICAL (security) | No (needs SQLAlchemy+FastAPI) |
| D2 | api/deps.py | Routes read settings from cached get_settings(), not app.state.settings, so create_app(settings) is ignored by request handling. | High | No |
| D3 | alembic/env.py | PRAGMA foreign_keys=ON during migrations. With render_as_batch, a table rebuild DROPs the old table, which fires ON DELETE CASCADE/SET NULL -> data loss. Also autobegins a transaction before configure(), so Alembic may treat it as external and never commit the version stamp. | High | No |
| D4 | alembic/env.py | Unconditionally overwrites sqlalchemy.url, so programmatic upgrades (tests) hit the wrong DB; fileConfig disables existing loggers. | Medium | No |
| D5 | migration 0001 | CHECK names given as full strings; with the target_metadata "ck" naming convention they risk becoming ck_users_ck_users_role_valid. Use op.f(). | Medium | No |
| D6 | migration 0001 vs models | Redundant UniqueConstraint + unique index on users.email and sessions.refresh_token_hash; models create only the unique index. | Medium | Parity test |
| D7 | models | Missing composite index ix_audit_log_entity required by DATABASE_DESIGN 7. | Medium | Parity test |
| D8 | models | server_default present in migration/reference but missing in models (9 columns). | Low | Parity test |
| D9 | schema_reference.sql | AUTOINCREMENT, inline UNIQUE, TEXT timestamps differ from models. Align to models. | Low | Yes (stdlib) |
| D10 | core/logging.py | RedactionFilter redacts record.msg before %-args are applied. `logger.info("password=%s", pw)` -> format error -> logging prints Arguments (the password) to stderr. | High (secret leak) | YES (stdlib) |
| D11 | services/auth_service.py | A logged-out token presented again is reported as "token reuse detected" (false theft alarm). Only rotation-revoked tokens indicate reuse. | Low | No |
| D12 | pyproject.toml | filterwarnings error::DeprecationWarning applies to ALL packages; third-party deprecations would fail our tests. Scope to app./tests. | Medium | Yes (pytest starts) |
| D13 | alembic.ini | ruff post-write hook uses console_scripts entrypoint, absent in the project venv -> `alembic revision` fails. | Low | No |
| D14 | tests/test_app_integration.py | common-password test uses an 11-char value, so it tests the length branch, not the denylist. | Low | No |

## Design issues needing the owner's decision (do NOT change unilaterally)

- /auth/register is unauthenticated. SR-AUTHZ-01 exempts only login, refresh, health.
- No way to create an admin, so all admin member endpoints are unreachable except by direct DB edit.

## Order of work

1. D10 first (stdlib, real failing test -> fix -> pass)
2. D12 (verify pytest still starts)
3. D9 + stdlib schema tests
4. D1, D2, D11 (static)
5. D3, D4, D5, D13 (static)
6. D6, D7, D8 (models/migration) + parity comparator (stdlib-tested) + runtime parity test (skips)
7. D14 + admin-path integration tests (skip now)
8. Re-run pytest, ruff, mypy; update backend/README.md

## Progress log

- D10 DONE, VERIFIED. Reproduced: secret printed to stderr via logging's error path. Added 3 regression tests (2 failed before fix). Fix: merge args before redacting. 74 passed.
- D12 DONE, VERIFIED. Probe test proved own-module deprecation errors and a third-party one only warns. Probe file removed.
- D9 DONE, VERIFIED. 4 new stdlib tests failed against the old reference, all pass after alignment. 79 passed.
- D1 DONE, STATIC. `_commit_then_raise()` used at all 5 write-then-raise sites (4 in authenticate, 1 in refresh reuse).
- D11 DONE, STATIC. Only rotation-revoked tokens trigger reuse detection; other revoked tokens get SessionRevokedError.
- D2 DONE, STATIC. SettingsDep now reads request.app.state.settings. Lockout test reads app settings. New regression test (skips now).
- D14 DONE, STATIC. Integration common-password test now uses a 12-char denylisted value. Logout test also asserts code session_revoked (D11).
- D3 DONE, STATIC. env.py no longer enables foreign_keys and executes nothing before configure().
- D4 DONE, STATIC. env.py honours a pre-set sqlalchemy.url; fileConfig keeps existing loggers.
- D13 DONE, STATIC. Removed the console_scripts ruff post-write hook from alembic.ini.
- Also: ruff isort treats `alembic` as third-party (local alembic/ dir confused it).
- D5/D6 DONE. Migration names wrapped in op.f(); redundant UniqueConstraints removed; is_active CHECK added.
- D7/D8 DONE. Models: composite ix_audit_log_entity, is_active CHECK, server_default on 8 columns.
- Parity: tests/schema_tools.py + tests/test_schema_parity.py. 17 run now and pass, including a STATIC migration-vs-reference
  comparison (AST of migration 0001 vs live reference DB). Proved it catches the original redundant-UniqueConstraint defect.
  The runtime alembic-vs-models-vs-reference test skips (needs SQLAlchemy, alembic).
- NEW finding D15: `find_spec("alembic")` is True even with the library absent: backend/alembic/ is importable
  as a namespace package. The parity skip-gate now checks installed distributions instead. Runtime is safe because
  an installed regular package always beats a namespace portion. mypy hit the same confusion (narrow ignore added).
- Suite: 96 passed, 33 skipped. ruff, ruff format, mypy clean.

## Fresh sandbox, 2026-11-15

- Container booted 03:30:06 UTC (a genuinely new container), but network_mode is still
  INTEGRATIONS_ONLY. PyPI, github.com and raw.githubusercontent.com: HTTP 000. GitHub: no user principal.
- Workspace already held the project. Snapshot checksum matched the recorded value; all 65 files
  identical to the snapshot, so nothing was extracted or overwritten.
- All 4 clones failed again (gateway "No user principal"; direct github.com 403). pip still fails.

## DD-02 implemented (owner decision)

- tests/test_route_authorization.py (stdlib, AST): fails closed if any route lacks CurrentUser/AdminUser
  and is not on the public allowlist. It FAILED on open /auth/register before the fix (2 failures), passes after.
- /auth/register now requires AdminUser; RegisterRequest.role (default viewer); audit actor = issuing admin.
- auth_service.create_first_admin() refuses if any admin exists. app/cli.py `create-admin`:
  password prompted twice or via --password-stdin, never argv. tests/test_cli.py: 11 pass (DB step injected).
- Integration tests now bootstrap the admin with create_first_admin and issue accounts through the admin.
  7 new integration tests (skip until the stack installs).
- DD-01 HOLD recorded in docs/DESIGN_DECISIONS.md for Day 4. Not implemented: Day 4 work.
- Suite: 130 passed, 47 skipped, 0 failed. ruff, ruff format, mypy clean.

## Recheck, 2026-11-15 03:56 UTC

- Same container as the previous session (boot 03:30:07 UTC, uptime 25 min). Not a new sandbox.
- Container environment at provision time: NETWORK_MODE=INTEGRATIONS_ONLY, KAS_POLICY_PRESETS_ENABLED=true.
  All egress goes through an external proxy that returns 403 on CONNECT. The mode is set by Kiro when the
  sandbox is created; nothing inside the container can change it.
- PyPI, files.pythonhosted.org, github.com, api.github.com, raw.githubusercontent.com: unreachable (one attempt each).
- GitHub: no user principal. No clones attempted again (same failure path as before).
- Latest snapshot 20261115-034426Z verified (SHA-256 match, 69/69 identical to workspace). No code changed.
- Day 2 runtime verification: NOT started. Day 3: NOT started.
