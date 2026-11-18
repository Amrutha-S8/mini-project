"""AI kill switch: off by default, and only an explicit, gated 'true' turns it on."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.ai.core.config import (
    REQUIRED_AI_CHECKS,
    REQUIRED_GEMINI_CHECKS,
    AIDisabledError,
    load_ai_status,
    require_ai_enabled,
    require_gemini_enabled,
)

ROOT = Path(__file__).resolve().parents[1]


def gate_file(tmp_path: Path, checks: list[str], **override: object) -> Path:
    entry = {"passed": True, "recorded_at": "2026-11-16T10:00:00Z", "evidence": "x"}
    entry.update(override)
    path = tmp_path / "gate.json"
    path.write_text(json.dumps({"checks": dict.fromkeys(checks, entry)}))
    return path


ALL = [*REQUIRED_AI_CHECKS, *REQUIRED_GEMINI_CHECKS]


def test_disabled_with_empty_environment() -> None:
    status = load_ai_status({})
    assert not status.ai_enabled and not status.gemini_enabled
    assert any("AI_ENABLED is not set" in r for r in status.reasons)
    with pytest.raises(AIDisabledError):
        require_ai_enabled(status)
    with pytest.raises(AIDisabledError):
        require_gemini_enabled(status)


def test_this_repository_ships_with_ai_disabled() -> None:
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "AI_ENABLED=false" in example and "GEMINI_ENABLED=false" in example
    assert not (ROOT / "ai_gate.json").exists()


@pytest.mark.parametrize(
    "value", ["1", "yes", "on", "True ", "tru", "enabled", "TRUE1"]
)
def test_only_the_word_true_enables(tmp_path: Path, value: str) -> None:
    env = {"AI_ENABLED": value, "AI_GATE_RECORD": str(gate_file(tmp_path, ALL))}
    status = load_ai_status(env)
    if value.strip().lower() == "true":
        assert status.ai_enabled
    else:
        assert not status.ai_enabled
        assert any("invalid value" in r for r in status.reasons)


def test_flag_without_gate_record_stays_off() -> None:
    status = load_ai_status({"AI_ENABLED": "true", "GEMINI_ENABLED": "true"})
    assert not status.ai_enabled and not status.gemini_enabled


def test_partial_gate_record_stays_off(tmp_path: Path) -> None:
    path = gate_file(tmp_path, ["V2", "V3"])
    status = load_ai_status({"AI_ENABLED": "true", "AI_GATE_RECORD": str(path)})
    assert not status.ai_enabled
    assert any("V4" in r and "V5" in r for r in status.reasons)


@pytest.mark.parametrize(
    "override",
    [{"passed": "true"}, {"passed": False}, {"recorded_at": ""}, {"evidence": " "}],
)
def test_gate_entries_must_be_complete(tmp_path: Path, override: dict) -> None:
    path = gate_file(tmp_path, ALL, **override)
    assert not load_ai_status(
        {"AI_ENABLED": "true", "AI_GATE_RECORD": str(path)}
    ).ai_enabled


@pytest.mark.parametrize("content", ["not json", "[]", '{"checks": []}', "x" * 70_000])
def test_malformed_gate_record_stays_off(tmp_path: Path, content: str) -> None:
    path = tmp_path / "gate.json"
    path.write_text(content)
    assert not load_ai_status(
        {"AI_ENABLED": "true", "AI_GATE_RECORD": str(path)}
    ).ai_enabled


def test_unreadable_gate_record_stays_off(tmp_path: Path) -> None:
    env = {"AI_ENABLED": "true", "AI_GATE_RECORD": str(tmp_path / "missing.json")}
    status = load_ai_status(env)
    assert not status.ai_enabled and "gate record could not be read" in status.reasons


def test_full_gate_enables_ai_but_not_gemini_without_its_flag(tmp_path: Path) -> None:
    path = gate_file(tmp_path, ALL)
    status = load_ai_status({"AI_ENABLED": "true", "AI_GATE_RECORD": str(path)})
    assert status.ai_enabled and not status.gemini_enabled


def test_gemini_needs_its_own_check(tmp_path: Path) -> None:
    path = gate_file(tmp_path, list(REQUIRED_AI_CHECKS))
    env = {"AI_ENABLED": "true", "GEMINI_ENABLED": "true", "AI_GATE_RECORD": str(path)}
    status = load_ai_status(env)
    assert status.ai_enabled and not status.gemini_enabled


def test_gemini_cannot_be_on_while_ai_is_off(tmp_path: Path) -> None:
    path = gate_file(tmp_path, ALL)
    env = {"AI_ENABLED": "false", "GEMINI_ENABLED": "true", "AI_GATE_RECORD": str(path)}
    status = load_ai_status(env)
    assert not status.ai_enabled and not status.gemini_enabled


def test_fully_gated_configuration(tmp_path: Path) -> None:
    path = gate_file(tmp_path, ALL)
    env = {"AI_ENABLED": "true", "GEMINI_ENABLED": "true", "AI_GATE_RECORD": str(path)}
    status = load_ai_status(env)
    assert status.ai_enabled and status.gemini_enabled
    require_ai_enabled(status)
    require_gemini_enabled(status)
