"""Minimal HTTPS transport over ``urllib`` (no third-party dependency)."""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

_MAX_BODY = 64 * 1024


class TransportError(Exception):
    """The request could not be completed (DNS, TLS, timeout, connection)."""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes


class HttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> HttpResponse: ...


class UrllibTransport:
    """Real transport. Only ``https://`` URLs are allowed."""

    def __init__(self, timeout_seconds: float = 10.0) -> None:
        self._timeout = timeout_seconds

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> HttpResponse:
        if not url.startswith("https://"):
            raise TransportError("only https URLs are allowed")
        req = urllib.request.Request(  # noqa: S310 - scheme checked above
            url, data=body, headers=dict(headers), method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                return HttpResponse(resp.status, resp.read(_MAX_BODY))
        except urllib.error.HTTPError as exc:
            # The provider answered with an error status: report it, do not raise.
            payload = exc.read(_MAX_BODY) if exc.fp is not None else b""
            return HttpResponse(exc.code, payload)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError(type(exc).__name__) from exc
