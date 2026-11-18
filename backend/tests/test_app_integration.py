"""End-to-end API tests for the Day 2 backend.

These require the approved stack (FastAPI, SQLAlchemy, Pydantic, argon2-cffi,
PyJWT). PyPI is unreachable in the current sandbox, so they SKIP with an
explicit reason rather than being faked or stubbed.

They are written now so that the moment the dependencies install, running
``pytest`` gives a real verdict on every item in the Day 2 test checklist:

  * application startup
  * database connection
  * table creation
  * user registration
  * duplicate user rejection
  * password hashing and verification
  * login with correct credentials
  * login with incorrect credentials
  * session authentication
  * unauthorized request rejection
  * health-check endpoint
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import requires_stack

pytestmark = requires_stack


@pytest.fixture
def app_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """TestClient bound to a temporary database.

    Imports happen inside the fixture so collection does not fail when the
    stack is absent.
    """
    from fastapi.testclient import TestClient

    import app.models  # noqa: F401  (registers tables on Base.metadata)
    from app.core.config import Settings
    from app.database.base import Base
    from app.database.session import create_writer_engine
    from app.main import create_app

    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-at-least-32-characters-long")
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))

    settings = Settings()
    engine = create_writer_engine(settings)
    Base.metadata.create_all(engine)
    from sqlalchemy.orm import Session

    from app.services.auth_service import create_first_admin

    with Session(engine) as db:
        create_first_admin(
            db,
            email=ADMIN_PAYLOAD["email"],
            password=ADMIN_PAYLOAD["password"],
            full_name=ADMIN_PAYLOAD["full_name"],
        )
        db.commit()
    engine.dispose()

    app = create_app(settings)
    with TestClient(app) as client:
        yield client


V1 = "/api/v1"

GOOD_PASSWORD = "Str0ng-Household-Pass"
USER_PAYLOAD = {
    "email": "owner@example.com",
    "password": GOOD_PASSWORD,
    "full_name": "Household Owner",
}


ADMIN_PAYLOAD = {
    "email": "admin@example.com",
    "password": "Adm1n-Household-Pass",
    "full_name": "Household Admin",
}


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _admin_token(client: Any) -> str:
    response = client.post(
        f"{V1}/auth/login",
        json={"email": ADMIN_PAYLOAD["email"], "password": ADMIN_PAYLOAD["password"]},
    )
    assert response.status_code == 200, response.text
    return str(response.json()["tokens"]["access_token"])


def _register(client: Any, payload: dict[str, Any]) -> Any:
    """Registration is admin-only, so every account is issued by the admin."""
    return client.post(
        f"{V1}/auth/register", json=payload, headers=_auth(_admin_token(client))
    )


# --- startup / health --------------------------------------------------------


def test_application_starts_and_health_returns_ok(app_client: Any) -> None:
    response = app_client.get(f"{V1}/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_readiness_confirms_database_connection(app_client: Any) -> None:
    response = app_client.get(f"{V1}/health/ready")
    assert response.status_code == 200
    assert response.json()["database"] == "ok"


def test_tables_were_created(app_client: Any) -> None:
    from sqlalchemy import inspect

    from app.database.session import get_writer_engine

    tables = set(inspect(get_writer_engine()).get_table_names())
    assert {"users", "sessions", "family_members", "audit_log"} <= tables


# --- registration -----------------------------------------------------------


def test_user_registration_succeeds(app_client: Any) -> None:
    response = _register(app_client, USER_PAYLOAD)
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == USER_PAYLOAD["email"]
    assert "password" not in body
    assert "password_hash" not in body


def test_duplicate_registration_rejected(app_client: Any) -> None:
    _register(app_client, USER_PAYLOAD)
    response = _register(app_client, USER_PAYLOAD)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "email_already_registered"


def test_weak_password_rejected(app_client: Any) -> None:
    payload = dict(USER_PAYLOAD, email="weak@example.com", password="short")
    assert _register(app_client, payload).status_code == 422


def test_common_password_rejected(app_client: Any) -> None:
    # 12 characters, so the length rule passes and the denylist is what
    # rejects it. An 11-character value would only test the length branch.
    payload = dict(USER_PAYLOAD, email="common@example.com", password="password1234")
    assert _register(app_client, payload).status_code == 422


# --- password hashing -------------------------------------------------------


def test_password_is_hashed_with_argon2id_not_stored_plaintext(
    app_client: Any,
) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.database.session import get_writer_engine
    from app.models.user import User

    _register(app_client, USER_PAYLOAD)
    with Session(get_writer_engine()) as db:
        stored = db.execute(
            select(User.password_hash).where(User.email == USER_PAYLOAD["email"])
        ).scalar_one()

    assert stored != GOOD_PASSWORD
    assert GOOD_PASSWORD not in stored
    assert stored.startswith("$argon2id$"), "must be Argon2id (SR-AUTH-02)"


def test_password_verification_round_trip() -> None:
    from app.core.security import hash_password, verify_password

    hashed = hash_password(GOOD_PASSWORD)
    assert verify_password(GOOD_PASSWORD, hashed) is True
    assert verify_password("wrong-password", hashed) is False


def test_same_password_produces_different_hashes() -> None:
    """Per-password salts (SR-AUTH-02)."""
    from app.core.security import hash_password

    assert hash_password(GOOD_PASSWORD) != hash_password(GOOD_PASSWORD)


def test_verify_rejects_malformed_hash_without_raising() -> None:
    from app.core.security import verify_password

    assert verify_password(GOOD_PASSWORD, "not-a-hash") is False


# --- login ------------------------------------------------------------------


def _register_and_login(client: Any) -> dict[str, Any]:
    _register(client, USER_PAYLOAD)
    response = client.post(
        f"{V1}/auth/login",
        json={"email": USER_PAYLOAD["email"], "password": GOOD_PASSWORD},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_login_with_correct_credentials(app_client: Any) -> None:
    body = _register_and_login(app_client)
    assert body["tokens"]["access_token"]
    assert body["tokens"]["refresh_token"]
    assert body["user"]["email"] == USER_PAYLOAD["email"]


def test_login_with_wrong_password_rejected(app_client: Any) -> None:
    _register(app_client, USER_PAYLOAD)
    response = app_client.post(
        f"{V1}/auth/login",
        json={"email": USER_PAYLOAD["email"], "password": "definitely-wrong"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_credentials"


def test_login_with_unknown_email_gives_identical_error(app_client: Any) -> None:
    """No user enumeration (SR-AUTH-12)."""
    _register(app_client, USER_PAYLOAD)
    wrong_pw = app_client.post(
        f"{V1}/auth/login",
        json={"email": USER_PAYLOAD["email"], "password": "definitely-wrong"},
    )
    unknown = app_client.post(
        f"{V1}/auth/login",
        json={"email": "nobody@example.com", "password": "definitely-wrong"},
    )
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.json() == unknown.json()


def test_repeated_failures_throttled_per_ip_and_email(app_client: Any) -> None:
    """SR-AUTH-11/13, DD-05: 429 with Retry-After, even for the right password."""
    _register(app_client, USER_PAYLOAD)
    limit = app_client.app.state.settings.login_failure_limit
    for _ in range(limit):
        app_client.post(
            f"{V1}/auth/login",
            json={"email": USER_PAYLOAD["email"], "password": "wrong-password!"},
        )
    response = app_client.post(
        f"{V1}/auth/login",
        json={"email": USER_PAYLOAD["email"], "password": GOOD_PASSWORD},
    )
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "rate_limited"
    assert int(response.headers["retry-after"]) >= 1


def test_failed_login_count_is_still_recorded(app_client: Any) -> None:
    """Regression for defect D1: failure state is committed before the raise."""
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.database.session import get_writer_engine
    from app.models.user import User

    _register(app_client, USER_PAYLOAD)
    for _ in range(3):
        app_client.post(
            f"{V1}/auth/login",
            json={"email": USER_PAYLOAD["email"], "password": "wrong-password!"},
        )
    with Session(get_writer_engine()) as db:
        user = db.execute(
            select(User).where(User.email == USER_PAYLOAD["email"])
        ).scalar_one()
    assert user.failed_login_count == 3
    assert user.locked_until is None, "accounts are never locked automatically"


# --- session authentication -------------------------------------------------


def test_authenticated_request_succeeds(app_client: Any) -> None:
    tokens = _register_and_login(app_client)["tokens"]
    response = app_client.get(
        f"{V1}/auth/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert response.status_code == 200
    assert response.json()["email"] == USER_PAYLOAD["email"]


def test_unauthorized_request_rejected(app_client: Any) -> None:
    assert app_client.get(f"{V1}/auth/me").status_code == 401


def test_malformed_token_rejected(app_client: Any) -> None:
    response = app_client.get(
        f"{V1}/auth/me", headers={"Authorization": "Bearer not.a.jwt"}
    )
    assert response.status_code == 401


def test_token_signed_with_wrong_secret_rejected(app_client: Any) -> None:
    import jwt

    forged = jwt.encode(
        {"sub": "1", "role": "admin", "typ": "access", "iat": 0, "exp": 9999999999},
        "attacker-secret",
        algorithm="HS256",
    )
    response = app_client.get(
        f"{V1}/auth/me", headers={"Authorization": f"Bearer {forged}"}
    )
    assert response.status_code == 401


def test_refresh_token_cannot_be_used_as_access_token(app_client: Any) -> None:
    tokens = _register_and_login(app_client)["tokens"]
    response = app_client.get(
        f"{V1}/auth/me",
        headers={"Authorization": f"Bearer {tokens['refresh_token']}"},
    )
    assert response.status_code == 401


def test_refresh_rotates_token(app_client: Any) -> None:
    tokens = _register_and_login(app_client)["tokens"]
    response = app_client.post(
        f"{V1}/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert response.status_code == 200
    assert response.json()["refresh_token"] != tokens["refresh_token"]


def test_refresh_token_reuse_revokes_family(app_client: Any) -> None:
    """SR-AUTH-08: replay is treated as theft."""
    tokens = _register_and_login(app_client)["tokens"]
    original = tokens["refresh_token"]
    rotated = app_client.post(
        f"{V1}/auth/refresh", json={"refresh_token": original}
    ).json()["refresh_token"]

    replay = app_client.post(f"{V1}/auth/refresh", json={"refresh_token": original})
    assert replay.status_code == 401

    after = app_client.post(f"{V1}/auth/refresh", json={"refresh_token": rotated})
    assert after.status_code == 401, "whole session family must be revoked"


def test_logout_revokes_session(app_client: Any) -> None:
    body = _register_and_login(app_client)
    tokens = body["tokens"]
    logout = app_client.post(
        f"{V1}/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert logout.status_code == 204
    reuse = app_client.post(
        f"{V1}/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert reuse.status_code == 401
    # A logged-out token is refused, but is not reported as theft (D11).
    assert reuse.json()["error"]["code"] == "session_revoked"


# --- RBAC -------------------------------------------------------------------


def test_non_admin_cannot_create_family_member(app_client: Any) -> None:
    """Registration defaults to 'viewer', so this must be forbidden."""
    tokens = _register_and_login(app_client)["tokens"]
    response = app_client.post(
        f"{V1}/members",
        json={"full_name": "New Person", "member_type": "family"},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert response.status_code == 403


def test_members_endpoint_requires_authentication(app_client: Any) -> None:
    assert app_client.get(f"{V1}/members").status_code == 401


# --- audit ------------------------------------------------------------------


def test_login_writes_audit_entry(app_client: Any) -> None:
    from sqlalchemy import func, select
    from sqlalchemy.orm import Session

    from app.database.session import get_writer_engine
    from app.models.audit_log import AuditLog

    user_id = str(_register_and_login(app_client)["user"]["id"])
    with Session(get_writer_engine()) as db:
        count = db.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == "login.success")
            .where(AuditLog.entity_id == user_id)
        ).scalar_one()
    # The admin's login (used to issue the account) is a separate entry.
    assert count == 1


def test_failed_login_writes_failure_audit_entry(app_client: Any) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.database.session import get_writer_engine
    from app.models.audit_log import AuditLog

    _register(app_client, USER_PAYLOAD)
    app_client.post(
        f"{V1}/auth/login",
        json={"email": USER_PAYLOAD["email"], "password": "wrong"},
    )
    with Session(get_writer_engine()) as db:
        rows = (
            db.execute(select(AuditLog).where(AuditLog.action == "login.failure"))
            .scalars()
            .all()
        )
    assert len(rows) == 1
    assert rows[0].outcome == "failure"


def test_audit_entries_never_contain_plaintext_password(app_client: Any) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.database.session import get_writer_engine
    from app.models.audit_log import AuditLog

    _register_and_login(app_client)
    with Session(get_writer_engine()) as db:
        blobs = db.execute(select(AuditLog.before_value, AuditLog.after_value)).all()
    joined = " ".join(str(v) for row in blobs for v in row if v)
    assert GOOD_PASSWORD not in joined


# --- configuration wiring (regression for defect D2) ------------------------


def test_app_uses_the_settings_it_was_created_with(app_client: Any) -> None:
    """Routes must use ``app.state.settings``, not the process-wide cache.

    The fixture builds the app with its own secret. A token signed with that
    secret must be accepted, and one signed with the cached process settings
    must be rejected.
    """
    from app.core.config import get_settings
    from app.core.security import create_access_token

    app_settings = app_client.app.state.settings
    process_settings = get_settings()
    if app_settings.secret_key == process_settings.secret_key:
        pytest.skip("app and process settings share a secret; cannot distinguish")

    user_id = str(_register_and_login(app_client)["user"]["id"])

    good = create_access_token(subject=user_id, role="viewer", settings=app_settings)
    stale = create_access_token(
        subject=user_id, role="viewer", settings=process_settings
    )
    assert (
        app_client.get(
            f"{V1}/auth/me", headers={"Authorization": f"Bearer {good}"}
        ).status_code
        == 200
    )
    assert (
        app_client.get(
            f"{V1}/auth/me", headers={"Authorization": f"Bearer {stale}"}
        ).status_code
        == 401
    )


# --- admin paths of the family-member registry (M02) ------------------------
#
# The first admin is created in the fixture through create_first_admin, the
# same function the create-admin CLI uses.


def _create_member(client: Any, token: str, **overrides: Any) -> dict[str, Any]:
    payload = {"full_name": "Asha Rao", "member_type": "family", **overrides}
    response = client.post(f"{V1}/members", json=payload, headers=_auth(token))
    assert response.status_code == 201, response.text
    return dict(response.json())


def _audit_rows(action: str) -> list[Any]:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.database.session import get_writer_engine
    from app.models.audit_log import AuditLog

    with Session(get_writer_engine()) as db:
        return list(
            db.execute(select(AuditLog).where(AuditLog.action == action)).scalars()
        )


def test_admin_can_create_member_and_it_is_audited(app_client: Any) -> None:
    token = _admin_token(app_client)
    member = _create_member(app_client, token)
    assert member["status"] == "active"
    assert member["enrollment_status"] == "not_enrolled"
    rows = _audit_rows("member.create")
    assert len(rows) == 1
    assert rows[0].entity_id == str(member["id"])


def test_admin_update_audits_before_and_after(app_client: Any) -> None:
    token = _admin_token(app_client)
    member = _create_member(app_client, token, notes="old note")
    response = app_client.patch(
        f"{V1}/members/{member['id']}",
        json={"notes": "new note"},
        headers=_auth(token),
    )
    assert response.status_code == 200
    assert response.json()["notes"] == "new note"
    (row,) = _audit_rows("member.update")
    assert "old note" in (row.before_value or "")
    assert "new note" in (row.after_value or "")


def test_deactivate_is_soft_and_keeps_the_row(app_client: Any) -> None:
    token = _admin_token(app_client)
    member = _create_member(app_client, token)
    response = app_client.post(
        f"{V1}/members/{member['id']}/deactivate", headers=_auth(token)
    )
    assert response.status_code == 200
    assert response.json()["status"] == "inactive"
    again = app_client.get(f"{V1}/members/{member['id']}", headers=_auth(token))
    assert again.status_code == 200, "deactivation must not delete the row"


def test_revoked_member_hidden_by_default_but_retained(app_client: Any) -> None:
    token = _admin_token(app_client)
    member = _create_member(app_client, token)
    app_client.post(f"{V1}/members/{member['id']}/revoke", headers=_auth(token))

    default_ids = {
        m["id"] for m in app_client.get(f"{V1}/members", headers=_auth(token)).json()
    }
    all_ids = {
        m["id"]
        for m in app_client.get(
            f"{V1}/members", params={"include_revoked": "true"}, headers=_auth(token)
        ).json()
    }
    assert member["id"] not in default_ids
    assert member["id"] in all_ids


def test_patch_cannot_un_revoke_a_member(app_client: Any) -> None:
    """Status changes only through the audited deactivate/revoke endpoints."""
    token = _admin_token(app_client)
    member = _create_member(app_client, token)
    app_client.post(f"{V1}/members/{member['id']}/revoke", headers=_auth(token))
    response = app_client.patch(
        f"{V1}/members/{member['id']}",
        json={"status": "active", "notes": "attempted un-revoke"},
        headers=_auth(token),
    )
    assert response.status_code == 200
    assert response.json()["status"] == "revoked"


def test_unknown_member_returns_404(app_client: Any) -> None:
    token = _admin_token(app_client)
    response = app_client.get(f"{V1}/members/99999", headers=_auth(token))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_viewer_cannot_deactivate_or_revoke(app_client: Any) -> None:
    admin = _admin_token(app_client)
    member = _create_member(app_client, admin)
    viewer = _register_and_login(app_client)["tokens"]["access_token"]
    for action in ("deactivate", "revoke"):
        response = app_client.post(
            f"{V1}/members/{member['id']}/{action}", headers=_auth(viewer)
        )
        assert response.status_code == 403, action


# --- admin-only registration and first-admin bootstrap ----------------------


def test_registration_requires_authentication(app_client: Any) -> None:
    response = app_client.post(f"{V1}/auth/register", json=USER_PAYLOAD)
    assert response.status_code == 401


def test_viewer_cannot_register_users(app_client: Any) -> None:
    viewer = _register_and_login(app_client)["tokens"]["access_token"]
    payload = dict(USER_PAYLOAD, email="second@example.com")
    response = app_client.post(
        f"{V1}/auth/register", json=payload, headers=_auth(viewer)
    )
    assert response.status_code == 403


def test_admin_registration_sets_role_and_audits_the_admin(app_client: Any) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.database.session import get_writer_engine
    from app.models.audit_log import AuditLog
    from app.models.user import User

    response = _register(app_client, dict(USER_PAYLOAD, role="member"))
    assert response.status_code == 201
    assert response.json()["role"] == "member"

    with Session(get_writer_engine()) as db:
        admin_id = db.execute(
            select(User.id).where(User.email == ADMIN_PAYLOAD["email"])
        ).scalar_one()
        entry = db.execute(
            select(AuditLog)
            .where(AuditLog.action == "user.create")
            .where(AuditLog.entity_id == str(response.json()["id"]))
        ).scalar_one()
    assert entry.actor_user_id == admin_id, "issuing admin must be the actor"


def test_registration_defaults_to_viewer(app_client: Any) -> None:
    response = _register(app_client, USER_PAYLOAD)
    assert response.json()["role"] == "viewer"


def test_registration_rejects_unknown_role(app_client: Any) -> None:
    response = _register(app_client, dict(USER_PAYLOAD, role="superuser"))
    assert response.status_code == 422


def test_first_admin_bootstrap_refuses_second_admin(app_client: Any) -> None:
    from sqlalchemy.orm import Session

    from app.database.session import get_writer_engine
    from app.services.auth_service import AdminAlreadyExistsError, create_first_admin

    with Session(get_writer_engine()) as db, pytest.raises(AdminAlreadyExistsError):
        create_first_admin(
            db,
            email="another-admin@example.com",
            password="Another-Admin-Pass-1",
            full_name="Another",
        )


def test_bootstrap_admin_audit_actor_is_system(app_client: Any) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.database.session import get_writer_engine
    from app.models.audit_log import AuditLog

    with Session(get_writer_engine()) as db:
        entry = db.execute(
            select(AuditLog).where(AuditLog.action == "user.create").limit(1)
        ).scalar_one()
    assert entry.actor_user_id is None
    assert entry.actor_label == "system"


# --- security hardening (DD-05) ------------------------------------------------


def test_settings_require_a_secret_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from pydantic import ValidationError as PydanticValidationError

    from app.core.config import Settings

    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(PydanticValidationError, match="SECRET_KEY is not set"):
        Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "value", ["CHANGE_ME_INSECURE_PLACEHOLDER", "TooShortSecret!", "z" * 40]
)
def test_weak_secret_rejected_in_development_and_not_echoed(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    from pydantic import ValidationError as PydanticValidationError

    from app.core.config import Settings

    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("SECRET_KEY", value)
    with pytest.raises(PydanticValidationError) as exc:
        Settings(_env_file=None)  # type: ignore[call-arg]
    assert value not in str(exc.value)


def test_settings_repr_hides_secret(app_client: Any) -> None:
    settings = app_client.app.state.settings
    assert settings.secret_key not in repr(settings)


def _login_body(client: Any, email: str, password: str) -> tuple[int, Any]:
    response = client.post(
        f"{V1}/auth/login", json={"email": email, "password": password}
    )
    return response.status_code, response.json()


def _set_user(email: str, **values: Any) -> None:
    from sqlalchemy import update
    from sqlalchemy.orm import Session

    from app.database.session import get_writer_engine
    from app.models.user import User

    with Session(get_writer_engine()) as db:
        db.execute(update(User).where(User.email == email).values(**values))
        db.commit()


def test_locked_account_indistinguishable_from_wrong_password(
    app_client: Any,
) -> None:
    from datetime import UTC, datetime, timedelta

    _register(app_client, USER_PAYLOAD)
    wrong = _login_body(app_client, USER_PAYLOAD["email"], "wrong-password!")
    _set_user(
        USER_PAYLOAD["email"], locked_until=datetime.now(UTC) + timedelta(hours=1)
    )
    locked_right_password = _login_body(
        app_client, USER_PAYLOAD["email"], GOOD_PASSWORD
    )
    assert locked_right_password == wrong
    assert wrong[0] == 401


def test_inactive_account_indistinguishable_from_wrong_password(
    app_client: Any,
) -> None:
    _register(app_client, USER_PAYLOAD)
    wrong = _login_body(app_client, USER_PAYLOAD["email"], "wrong-password!")
    _set_user(USER_PAYLOAD["email"], is_active=0)
    inactive = _login_body(app_client, USER_PAYLOAD["email"], GOOD_PASSWORD)
    assert inactive == wrong


def test_throttled_response_identical_for_unknown_email(app_client: Any) -> None:
    _register(app_client, USER_PAYLOAD)
    limit = app_client.app.state.settings.login_failure_limit
    results = []
    for email in (USER_PAYLOAD["email"], "nobody@example.com"):
        for _ in range(limit):
            _login_body(app_client, email, "wrong-password!")
        results.append(_login_body(app_client, email, "wrong-password!"))
    assert results[0] == results[1]
    assert results[0][0] == 429


def test_attacker_failures_do_not_lock_out_admin(app_client: Any) -> None:
    """Failures recorded for another client IP must not block the admin."""
    throttle = app_client.app.state.login_throttle
    for _ in range(50):
        throttle.login_failed("203.0.113.9", ADMIN_PAYLOAD["email"])
    status, _body = _login_body(
        app_client, ADMIN_PAYLOAD["email"], ADMIN_PAYLOAD["password"]
    )
    assert status == 200


def test_refresh_is_rate_limited(app_client: Any) -> None:
    limit = app_client.app.state.settings.refresh_ip_limit
    codes = [
        app_client.post(
            f"{V1}/auth/refresh", json={"refresh_token": "not-a-real-token"}
        ).status_code
        for _ in range(limit + 1)
    ]
    assert set(codes[:limit]) == {401}
    assert codes[-1] == 429


@pytest.mark.parametrize(
    "method,path,payload,expected",
    [
        ("get", "/health", None, 200),
        ("get", "/auth/me", None, 401),
        ("get", "/does-not-exist", None, 404),
        ("post", "/auth/login", {"email": "bad"}, 422),
    ],
)
def test_security_headers_on_success_and_errors(
    app_client: Any, method: str, path: str, payload: Any, expected: int
) -> None:
    response = getattr(app_client, method)(f"{V1}{path}", json=payload)
    assert response.status_code == expected
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert "strict-transport-security" not in response.headers


def test_unknown_route_uses_error_envelope(app_client: Any) -> None:
    response = app_client.get(f"{V1}/does-not-exist")
    assert response.json() == {"error": {"code": "not_found", "message": "Not Found"}}


def test_wrong_method_uses_error_envelope(app_client: Any) -> None:
    response = app_client.get(f"{V1}/auth/login")
    assert response.status_code == 405
    assert response.json()["error"]["code"] == "method_not_allowed"
    assert "POST" in response.headers["allow"]


def test_cors_allowed_origin_without_credentials(app_client: Any) -> None:
    response = app_client.options(
        f"{V1}/auth/login",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-credentials" not in response.headers


def test_cors_disallowed_origin_gets_no_cors_headers(app_client: Any) -> None:
    response = app_client.get(
        f"{V1}/health", headers={"Origin": "https://evil.example"}
    )
    assert "access-control-allow-origin" not in response.headers
