"""Security response headers as plain ASGI middleware (stdlib only).

Headers the application already set are never overridden. The deny-all CSP
is skipped on the Swagger UI page, which needs its own scripts; that page is
only served outside production.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

BASE_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
)
CSP_HEADER = (
    b"content-security-policy",
    b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
)
HSTS_HEADER = (b"strict-transport-security", b"max-age=31536000; includeSubDomains")
NO_STORE_HEADER = (b"cache-control", b"no-store")
DEFAULT_CSP_EXEMPT = frozenset({"/docs", "/docs/oauth2-redirect"})


class SecurityHeadersMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        hsts: bool = False,
        csp_exempt_paths: frozenset[str] = DEFAULT_CSP_EXEMPT,
        no_store_prefix: str = "/api/",
    ) -> None:
        self.app = app
        self.hsts = hsts
        self.csp_exempt_paths = csp_exempt_paths
        self.no_store_prefix = no_store_prefix

    def headers_for(self, path: str) -> list[tuple[bytes, bytes]]:
        headers = list(BASE_HEADERS)
        if path not in self.csp_exempt_paths:
            headers.append(CSP_HEADER)
        if path.startswith(self.no_store_prefix):
            headers.append(NO_STORE_HEADER)
        if self.hsts:
            headers.append(HSTS_HEADER)
        return headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        extra = self.headers_for(str(scope.get("path", "")))

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                headers.extend((k, v) for k, v in extra if k not in present)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)
