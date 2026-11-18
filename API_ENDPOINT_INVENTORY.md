# API Endpoint Inventory

**Date:** 2026-11-16. **Reference:** `backup/project-snapshot-20261116-153145Z.zip`
(workspace identical, 175 files, checksum verified).

**Source:** `backend/app/api/v1/router.py` includes exactly three routers
(`health`, `auth`, `members`), mounted under `/api/v1` in `app/main.py`. The
list below was read from the source and is cross-checked by
`frontend/src/api/contract.test.ts` ("the backend route parser sees all 13
routes", passed).

**Runtime status for every endpoint: NOT RUNTIME-VERIFIED.** The FastAPI
application has never been started. The 62 in-process integration tests in
`backend/tests/test_app_integration.py` that cover these routes were all
**skipped** (FastAPI, SQLAlchemy, Pydantic, pydantic-settings, argon2-cffi
and PyJWT are not installed).

## 1. Existing endpoints (13)

| # | Method | URL | Purpose | Auth | Role | Database operation | Status | Test coverage (written) |
|---|---|---|---|---|---|---|---|---|
| 1 | GET | `/api/v1/health` | Liveness | None | — | None | Implemented, not run | `test_application_starts_and_health_returns_ok` (skipped) |
| 2 | GET | `/api/v1/health/ready` | Readiness incl. database `SELECT 1` | None | — | Read | Implemented, not run | `test_readiness_confirms_database_connection` (skipped) |
| 3 | POST | `/api/v1/auth/register` | Create operator account | Bearer | admin | Insert `users`, `audit_log` | Implemented, not run | 6 tests, e.g. `test_viewer_cannot_register_users` (skipped) |
| 4 | POST | `/api/v1/auth/login` | Credentials → token pair | None | — | Read `users`; insert `sessions`, `audit_log`; update `users` counters | Implemented, not run | 10+ tests incl. throttling and identical failures (skipped) |
| 5 | POST | `/api/v1/auth/refresh` | Rotate refresh token | None (refresh token in body) | — | Read/update `sessions`; insert `sessions`; family revocation on reuse | Implemented, not run | `test_refresh_rotates_token`, `test_refresh_token_reuse_revokes_family`, `test_refresh_is_rate_limited` (skipped) |
| 6 | POST | `/api/v1/auth/logout` | Revoke the session | Bearer | any active | Update `sessions`; insert `audit_log` | Implemented, not run | `test_logout_revokes_session` (skipped). **Does not check the access token after logout (finding S2)** |
| 7 | GET | `/api/v1/auth/me` | Current operator | Bearer | any active | Read `users` | Implemented, not run | `test_authenticated_request_succeeds` (skipped) |
| 8 | GET | `/api/v1/members` | List members (`?include_revoked=`) | Bearer | any active | Read `family_members` | Implemented, not run | `test_revoked_member_hidden_by_default_but_retained` (skipped) |
| 9 | GET | `/api/v1/members/{id}` | One member | Bearer | any active | Read | Implemented, not run | `test_unknown_member_returns_404` (skipped) |
| 10 | POST | `/api/v1/members` | Create member | Bearer | admin | Insert `family_members`, `audit_log` | Implemented, not run | `test_admin_can_create_member_and_it_is_audited`, `test_non_admin_cannot_create_family_member` (skipped) |
| 11 | PATCH | `/api/v1/members/{id}` | Edit (no status changes) | Bearer | admin | Update, audit before/after | Implemented, not run | `test_admin_update_audits_before_and_after`, `test_patch_cannot_un_revoke_a_member` (skipped) |
| 12 | POST | `/api/v1/members/{id}/deactivate` | Soft deactivate | Bearer | admin | Update status, audit | Implemented, not run | `test_deactivate_is_soft_and_keeps_the_row` (skipped) |
| 13 | POST | `/api/v1/members/{id}/revoke` | Revoke access rights | Bearer | admin | Update status, audit | Implemented, not run | `test_viewer_cannot_deactivate_or_revoke` (skipped) |

Also written and statically tested:

- Every route except login, refresh and the two health routes requires
  authentication: `tests/test_route_authorization.py`, 23 tests, **passed**
  (static source analysis, not a running server).
- No route contains `unlock`, `open_door` or `door_open`
  (`test_no_unlock_capability_in_day2_api`, passed, static).
- Unknown routes and wrong methods return the standard error envelope
  (tests written, skipped).
- Not an endpoint: `/docs` and `/openapi.json` (FastAPI built-ins, enabled
  only when `APP_ENV` is not `production`).

Role model in the backend today: **admin** versus **any active signed-in
user**. There is no backend distinction between `viewer` and `member` (see
finding S5).

## 2. Endpoints missing for the seven pages

None of these exists. Router file names come from the plan in
`docs/SYSTEM_ARCHITECTURE.md` §7.1; URLs, request and response shapes are
**not designed yet** and are not invented here.

| Needed capability | Planned router (§7.1) | Needed by | Also requires |
|---|---|---|---|
| Face enrolment for a member | `members.py` (planned extension) | Access Management | `face_embeddings` table, embedding service, model |
| Recognition attempt → AccessEngine decision | not in §7.1 (camera loop was planned in-process) | Live Monitoring | Vision service, engine service, camera architecture decision |
| Door state; admin lock; lockdown enable/release | `door.py` | Dashboard, Live Monitoring, Settings | Single lockdown source (P3/S8) |
| HOLD review (admin approve/reject) | `door.py` or `access_events.py` | Live Monitoring / Security Events | Persisted HOLDs, persistent signing key (S12) |
| Permissions CRUD | `permissions.py` | Access Management | `permissions` table |
| Access history | `access_events.py` | Dashboard, Security Events, Analytics | SQLite event writer |
| Visitor events, review, purge | `visitors.py` | Access Management, Security Events | Visitor service, retention job |
| Security events, incidents, evidence (authenticated, audited) | `incidents.py` | Security Events | M13 rules, incident manager, evidence retrieval with TOCTOU-safe open |
| Retention extension request/approve | not in §7.1 | Settings / Security Events | DD-11 rules already in `domain/retention.py` |
| Aggregated analytics | not in §7.1 | Dashboard, Analytics | Event read model |
| Notifications history and preferences | `notifications.py` | Settings, Dashboard bell | Notification service |
| Scheduled tasks | `automation.py` | Settings | APScheduler |
| AI questions, reports, workflow status | `insights.py` | AI Assistant | Whole AI tier (DD-08); disabled by default |
| Live event stream | `ws.py` | Dashboard, Security Events | Event bus |
| Password change; user list and role change | not in §7.1 | Settings | Auth service extensions |
| Database status / backup info | `/health/ready` covers status only | Settings | Backup procedure |
