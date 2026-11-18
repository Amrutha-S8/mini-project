# Security Findings Status (S1–S14)

**Date:** 2026-11-16. **Reference:** `project-snapshot-20261116-153145Z.zip`.
Each finding from `FINAL_PRODUCT_GAP_ANALYSIS.md` §6 was re-checked against
the source in this audit. Nothing was changed.

"Tests ran" means executed in the Kiro sandbox on 2026-11-16 (standard
library only). The backend application has never run, so **no finding has
runtime evidence from the real application**.

| ID | Severity | Status |
|---|---|---|
| S1 | Critical (real-world use) | Open |
| S2 | High | **Open, confirmed** |
| S3 | High (latent) | Open, by design until wiring |
| S4 | Medium | **Fixed in reference schema**; migration 0004 not applied |
| S5 | Medium | Open, owner decision |
| S6 | Medium | Open |
| S7 | Medium | Open (documented residual risk) |
| S8 | Medium | Open |
| S9 | Medium | Open, acceptable for one laptop |
| S10 | Low | Open, unverified race |
| S11 | Low | Open, acceptable locally |
| S12 | Low | Open |
| S13 | Low | Open |
| S14 | Low | Open, worse than before |

---

### S1 — No liveness / anti-spoofing
- **Description:** a printed photo or a phone screen showing a member could pass face matching. Recognition itself does not exist yet, so this applies once it is built.
- **Files:** none yet (vision layer missing); documented in `docs/SECURITY_REQUIREMENTS.md` §8.1.
- **Fixed:** no. **Regression tests:** none. **Ran:** —.
- **Remaining risk:** anyone with a member's photo may get an ALLOW once recognition exists.
- **Next action:** label every demo as a simulation; plan liveness for any real use (roadmap P10).

### S2 — Access tokens are not bound to sessions (HIGH)
- **Description:** `app/api/deps.py:get_current_user` decodes the JWT, loads the user and checks `is_active`. It never checks a session. `core/security.py:create_access_token` puts `sub`, `role`, `typ`, `iat`, `exp`, `jti` in the token, with no session id. So after logout, admin revocation or refresh-token reuse detection, an already-issued access token keeps working until it expires (`ACCESS_TOKEN_EXPIRE_MINUTES`, default 15).
- **Files:** `app/api/deps.py`, `app/core/security.py`, `app/services/auth_service.py` (`logout`, `_revoke_family`), `app/models/session.py`.
- **Evidence (source):** `tests/test_app_integration.py::test_logout_revokes_session` checks only that the **refresh** token is refused after logout; no test checks the access token.
- **Fixed:** no. **Regression tests:** none. **Ran:** —.
- **Remaining risk:** a stolen access token survives logout and reuse detection for up to 15 minutes.
- **Next action (after the stack runs):** first write failing tests (access token used after logout, after admin revocation, after reuse detection → 401). Then add a session-id claim set at login and refresh, and have `get_current_user` reject tokens whose session is revoked or expired. Re-run all 62 integration tests.

### S3 — AccessEngine trusts caller-supplied facts
- **Description:** `AccessRequest` carries `approver_is_active_admin`, `recent_attempts` and `now` from the caller (`app/domain/access_engine.py`). The engine is correct for the facts it gets; a wrong caller could pass wrong facts (TEST_RUN finding P6 showed user 999 accepted as admin when the caller said so).
- **Files:** `app/domain/access_engine.py`; the service that will build requests does not exist.
- **Fixed:** no (by design; must be enforced in the wiring). **Tests:** engine tests (63, ran) prove the rules, not the wiring.
- **Remaining risk:** high once wiring exists, if the service trusts client input.
- **Next action:** in the recognition/HOLD-review service, derive approver role from SQLite, attempt counts from stored events and time from the server clock; add tests that a client cannot supply them.

### S4 — `audit_log` mutable at the database level
- **Description:** migration 0001 created `audit_log` without triggers.
- **Files:** `alembic/versions/0004_audit_log_append_only.py`, `app/database/append_only.py`, `app/database/schema_reference.sql`, `app/models/audit_log.py`.
- **Fixed:** yes in the reference schema and code; **migration 0004 has never been applied** (Alembic not installed).
- **Evidence:** `tests/test_audit_log_append_only.py` 16 passed (real SQLite, reference DDL): every column edit refused, DELETE refused, user deletion still sets the actor to NULL. `tests/test_schema_parity.py` 28 passed (migration text matches the reference). `scripts/stage1_audit_log_check.py` detected the protection on a correct database and its absence on a pre-0004 database (manual runs, 2026-11-16).
- **Remaining risk:** none in design; runtime confirmation pending.
- **Next action:** Windows guide Step 11 (`alembic upgrade head` on a test database, then the check script).

### S5 — Member records visible to every signed-in role
- **Description:** `GET /members` and `GET /members/{id}` use `CurrentUser` (any active role), returning names and notes to viewers and members. DD-08 rule 5 says viewers see no individual member records.
- **Files:** `app/api/v1/members.py`; frontend `src/access/routes.ts` follows the backend.
- **Fixed:** no. **Tests:** none for viewer/member read restrictions.
- **Next action:** owner decision; then restrict in the backend (not only the UI) with tests per role.

### S6 — Dependencies not locked or scanned
- **Description:** `backend/requirements.txt` has version ranges only; no `requirements.lock.txt`; no `pip-audit` or `npm audit` possible here. `frontend/` has no dependencies yet.
- **Fixed:** no. **Next action:** on Windows after Step 7, generate a hash-pinned lock and run `pip-audit`.

### S7 — No encryption at rest; no MFA
- **Description:** documented residual risks T7 and T4 (`SECURITY_REQUIREMENTS.md` §8.1).
- **Fixed:** no. **Next action:** BitLocker on the laptop for any real data; MFA before public release.

### S8 — Two lockdown states; DENY does not relock an open door
- **Description:** lockdown exists as `Policy.lockdown` in the engine and separately in `VirtualDoor.enter_lockdown`; a DENY arriving while the door is open (from an earlier ALLOW) leaves it open until the TTL (TEST_RUN P3, P4).
- **Files:** `app/domain/access_engine.py`, `app/domain/virtual_door.py`.
- **Fixed:** no. **Tests:** current behaviour is tested; the desired behaviour is not defined yet.
- **Next action:** decide (one lockdown source; whether DENY relocks) before building the door service.

### S9 — In-memory rate limits; proxy IP handling
- **Description:** `app/core/rate_limit.py` keeps counters in process memory (reset on restart); `client_ip` uses the socket peer.
- **Tests:** 19 limiter tests ran and passed; behaviour inside FastAPI not run.
- **Status:** acceptable for a single local laptop; must change for any network deployment.

### S10 — Refresh rotation race (unverified)
- **Description:** `auth_service.refresh_tokens` selects the session by token hash without a row lock or conditional update, so two simultaneous refreshes with the same token might both succeed. Not reproduced (cannot run).
- **Mitigation present:** the frontend sends one refresh at a time (`frontend/src/auth/session.ts`, single-flight test passed).
- **Next action:** add a concurrency test after Stage 1; use a conditional `UPDATE … WHERE revoked_at IS NULL` and check the row count.

### S11 — `/health/ready` reveals database reachability without auth
- **Files:** `app/api/v1/health.py`. **Status:** acceptable locally; restrict for any network deployment.

### S12 — Per-process decision-signing key
- **Description:** `DecisionSigner()` with no key uses `secrets.token_bytes(32)` (`access_engine.py:188`), so pending HOLDs cannot be verified after a restart; they fail closed (DENY).
- **Next action:** load the key from the secret store when HOLD persistence is built.

### S13 — Name detection limits in the AI privacy filter
- **Description:** pattern detection (`app/ai/core/sensitive.py`) cannot recognise names; the policy relies on record kind first and a household-term list that is not filled from the database yet.
- **Tests:** 87 privacy tests ran and passed. **Status:** no runtime exposure, because nothing sends data to Gemini.
- **Next action:** fill the term list from `family_members` and device ids when the Gemini adapter is built.

### S14 — Documentation drift
- **Description (verified 2026-11-16):** `docs/15_DAY_DEVELOPMENT_PLAN.md` still says "Day 1 complete. Day 2 not started"; `SYSTEM_ARCHITECTURE.md` line 49 and `MODULE_DESIGN.md` line 301 name the end-of-life `google-generativeai`; `DATABASE_DESIGN.md` §10 says "Nothing in this document is implemented"; `SECURITY_REQUIREMENTS.md` §4.2 and §9 say none of the V-checks has been written. Each is out of date.
- **Next action:** update these documents (no code impact).

---

## Additional observation from this audit (not a security finding)

- `tests/test_app_integration.py` imports `app.main` inside its fixture
  **before** setting the test environment, and `app/main.py` builds an
  app at import time from the real settings. The integration tests
  therefore depend on a valid `backend/.env`. The Windows guide orders
  Step 8 (`.env`) before Step 10 (tests) for this reason. Fixing the
  fixture should wait until the tests can run.
