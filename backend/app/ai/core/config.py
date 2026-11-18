"""AI kill switch and gate record (DD-08 decision 7).

The AI tier is OFF unless both of these hold:

1. ``AI_ENABLED`` is exactly ``true`` (case-insensitive). Any other value,
   including ``1``, ``yes`` or a typo, keeps it off and is reported.
2. The gate record named by ``AI_GATE_RECORD`` exists and marks every
   required check as passed with a timestamp and evidence.

Gemini additionally needs ``GEMINI_ENABLED=true`` and its own gate checks.
Phase 1 records no checks, so the AI tier and Gemini are off everywhere.

The gate record is a safety interlock against accidental enabling, not an
authentication mechanism: anyone who can write the file and the environment
already controls the host.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

#: Checks that must be recorded as passed before the AI tier may run.
REQUIRED_AI_CHECKS: tuple[str, ...] = (
    "V2",  # no AI package reachable from the AccessEngine
    "V3",  # AI tier cannot reach the AccessEngine or the door
    "V4",  # forged AccessDecision rejected by the door
    "V5",  # no route, job or AI path reaches unlock without an engine grant
    "privacy_policy",  # Gemini privacy policy implemented and tested
    "live_local_embeddings",  # local embedding model run for real
)
#: Extra checks before Gemini may be called.
REQUIRED_GEMINI_CHECKS: tuple[str, ...] = ("live_gemini",)

MAX_GATE_RECORD_BYTES = 64_000


class AIDisabledError(RuntimeError):
    """Raised when AI functionality is requested while the tier is off."""


@dataclass(frozen=True)
class AIStatus:
    ai_enabled: bool
    gemini_enabled: bool
    reasons: tuple[str, ...]


def _flag(environ: Mapping[str, str], name: str) -> tuple[bool, str | None]:
    raw = environ.get(name)
    if raw is None or raw.strip() == "":
        return False, f"{name} is not set (default false)"
    value = raw.strip().lower()
    if value == "true":
        return True, None
    if value == "false":
        return False, f"{name}=false"
    return False, f"{name} has an invalid value; only 'true' or 'false' are accepted"


def _passed_checks(
    environ: Mapping[str, str], read_text: Callable[[Path], str]
) -> tuple[frozenset[str], list[str]]:
    path_text = environ.get("AI_GATE_RECORD", "").strip()
    if not path_text:
        return frozenset(), ["AI_GATE_RECORD is not set; no gate checks recorded"]
    try:
        raw = read_text(Path(path_text))
    except OSError:
        return frozenset(), ["gate record could not be read"]
    if len(raw.encode()) > MAX_GATE_RECORD_BYTES:
        return frozenset(), ["gate record is too large"]
    try:
        data = json.loads(raw)
    except ValueError:
        return frozenset(), ["gate record is not valid JSON"]
    checks = data.get("checks") if isinstance(data, dict) else None
    if not isinstance(checks, dict):
        return frozenset(), ["gate record has no 'checks' object"]
    passed = set()
    for name, entry in checks.items():
        if (
            isinstance(entry, dict)
            and entry.get("passed") is True
            and isinstance(entry.get("recorded_at"), str)
            and entry["recorded_at"].strip()
            and isinstance(entry.get("evidence"), str)
            and entry["evidence"].strip()
        ):
            passed.add(str(name))
    return frozenset(passed), []


def load_ai_status(
    environ: Mapping[str, str],
    read_text: Callable[[Path], str] = lambda p: p.read_text(encoding="utf-8"),
) -> AIStatus:
    """Evaluate the kill switch. Pass ``os.environ`` in production."""
    reasons: list[str] = []
    ai_flag, why = _flag(environ, "AI_ENABLED")
    if why:
        reasons.append(why)
    gemini_flag, why = _flag(environ, "GEMINI_ENABLED")
    if why:
        reasons.append(why)

    passed, problems = _passed_checks(environ, read_text)
    reasons.extend(problems)
    missing_ai = [c for c in REQUIRED_AI_CHECKS if c not in passed]
    if missing_ai:
        reasons.append("gate checks not passed: " + ", ".join(missing_ai))
    missing_gemini = [c for c in REQUIRED_GEMINI_CHECKS if c not in passed]
    if missing_gemini:
        reasons.append("Gemini gate checks not passed: " + ", ".join(missing_gemini))

    ai_enabled = ai_flag and not missing_ai and not problems
    gemini_enabled = ai_enabled and gemini_flag and not missing_gemini
    return AIStatus(ai_enabled, gemini_enabled, tuple(reasons))


def require_ai_enabled(status: AIStatus) -> None:
    if not status.ai_enabled:
        raise AIDisabledError("AI tier is disabled")


def require_gemini_enabled(status: AIStatus) -> None:
    if not status.gemini_enabled:
        raise AIDisabledError("Gemini is disabled")
