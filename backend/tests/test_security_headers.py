"""Security-headers ASGI middleware. Stdlib only (asyncio)."""

from __future__ import annotations

import asyncio
from typing import Any

from app.core.security_headers import BASE_HEADERS, SecurityHeadersMiddleware


def _run(
    path: str,
    *,
    app_headers: list[tuple[bytes, bytes]] | None = None,
    scope_type: str = "http",
    **kwargs: Any,
) -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            sent.append({"type": "passthrough", "scope": scope["type"]})
            return
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": list(app_headers or []),
            }
        )
        await send({"type": "http.response.body", "body": b"{}"})

    async def receive() -> dict[str, Any]:
        return {"type": "http.request"}

    async def send(message: Any) -> None:
        sent.append(message)

    middleware = SecurityHeadersMiddleware(app, **kwargs)
    asyncio.run(middleware({"type": scope_type, "path": path}, receive, send))
    return sent


def _headers(path: str, **kwargs: Any) -> dict[bytes, bytes]:
    return dict(_run(path, **kwargs)[0]["headers"])


def test_base_headers_present() -> None:
    headers = _headers("/api/v1/health")
    for name, value in BASE_HEADERS:
        assert headers[name] == value


def test_csp_on_api_responses() -> None:
    csp = _headers("/api/v1/health")[b"content-security-policy"]
    assert csp.startswith(b"default-src 'none'")
    assert b"frame-ancestors 'none'" in csp


def test_csp_skipped_on_swagger_ui() -> None:
    assert b"content-security-policy" not in _headers("/docs")


def test_no_store_only_under_api_prefix() -> None:
    assert _headers("/api/v1/auth/login")[b"cache-control"] == b"no-store"
    assert b"cache-control" not in _headers("/openapi.json")


def test_hsts_only_when_enabled() -> None:
    assert b"strict-transport-security" not in _headers("/api/v1/health")
    assert b"strict-transport-security" in _headers("/api/v1/health", hsts=True)


def test_existing_header_is_not_overridden() -> None:
    headers = _headers("/api/x", app_headers=[(b"cache-control", b"max-age=5")])
    assert headers[b"cache-control"] == b"max-age=5"


def test_existing_header_override_is_case_insensitive() -> None:
    sent = _run("/api/x", app_headers=[(b"X-Frame-Options", b"SAMEORIGIN")])
    names = [k.lower() for k, _ in sent[0]["headers"]]
    assert names.count(b"x-frame-options") == 1


def test_body_passes_through_unchanged() -> None:
    sent = _run("/api/x")
    assert sent[1] == {"type": "http.response.body", "body": b"{}"}


def test_non_http_scope_passes_through() -> None:
    assert _run("", scope_type="lifespan") == [
        {"type": "passthrough", "scope": "lifespan"}
    ]
