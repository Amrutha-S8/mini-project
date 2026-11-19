"""Run work after the request without blocking it (notifications).

``ThreadTaskRunner`` starts a daemon thread per job, so a slow or failing
provider never delays a login response or an ingestion call, and it also
works when the request ends in an error response (FastAPI background tasks
only run after a normal return). Tests use ``InlineTaskRunner``.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any, Protocol

from app.core.logging import get_logger

logger = get_logger(__name__)


class TaskRunner(Protocol):
    def submit(self, fn: Callable[..., Any], *args: Any) -> None: ...


def _guarded(fn: Callable[..., Any], *args: Any) -> None:
    try:
        fn(*args)
    except Exception:  # noqa: BLE001 - a background job must not die silently
        logger.error("background job failed", exc_info=True)


class ThreadTaskRunner:
    def submit(self, fn: Callable[..., Any], *args: Any) -> None:
        threading.Thread(target=_guarded, args=(fn, *args), daemon=True).start()


class InlineTaskRunner:
    """Runs the job immediately, in the caller's thread."""

    def submit(self, fn: Callable[..., Any], *args: Any) -> None:
        _guarded(fn, *args)
