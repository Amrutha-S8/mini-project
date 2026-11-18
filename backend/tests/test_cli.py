"""Tests for the create-admin CLI argument and password handling (stdlib).

The database step is injected, so these run without SQLAlchemy. The real
end-to-end bootstrap is covered in test_app_integration.py once the stack runs.
"""

from __future__ import annotations

import io
from collections.abc import Iterator

import pytest

from app.cli import EXIT_OK, EXIT_REFUSED, EXIT_USAGE, CliError, main

GOOD = "Owner-Household-Pass-1"


def _prompt(*answers: str):
    it: Iterator[str] = iter(answers)
    return lambda _label: next(it)


def _run(argv: list[str], *, stdin: str = "", prompt=None, create=None):
    out, err = io.StringIO(), io.StringIO()
    calls: list[tuple[str, str, str]] = []

    def fake_create(email: str, password: str, full_name: str) -> int:
        calls.append((email, password, full_name))
        return 7

    code = main(
        argv,
        stdin=io.StringIO(stdin),
        stdout=out,
        stderr=err,
        prompt=prompt or _prompt(GOOD, GOOD),
        create=create or fake_create,
    )
    return code, out.getvalue(), err.getvalue(), calls


BASE = ["create-admin", "--email", "Owner@Example.com", "--full-name", " Owner "]


def test_interactive_success_normalises_inputs() -> None:
    code, out, err, calls = _run(BASE)
    assert code == EXIT_OK
    assert calls == [("owner@example.com", GOOD, "Owner")]
    assert "id=7" in out
    assert err == ""


def test_password_never_printed() -> None:
    _code, out, err, _ = _run(BASE)
    assert GOOD not in out
    assert GOOD not in err


def test_mismatched_confirmation_rejected() -> None:
    code, _out, err, calls = _run(BASE, prompt=_prompt(GOOD, GOOD + "x"))
    assert code == EXIT_USAGE
    assert "do not match" in err
    assert calls == []


def test_weak_password_rejected_before_database() -> None:
    code, _out, err, calls = _run(BASE, prompt=_prompt("short", "short"))
    assert code == EXIT_USAGE
    assert "at least" in err
    assert calls == []


def test_common_password_rejected() -> None:
    weak = "password1234"
    code, _o, err, calls = _run(BASE, prompt=_prompt(weak, weak))
    assert code == EXIT_USAGE
    assert "too common" in err
    assert calls == []


def test_password_stdin_mode() -> None:
    code, _o, _e, calls = _run(BASE + ["--password-stdin"], stdin=GOOD + "\n")
    assert code == EXIT_OK
    assert calls[0][1] == GOOD


def test_empty_stdin_password_rejected() -> None:
    code, _o, err, calls = _run(BASE + ["--password-stdin"], stdin="\n")
    assert code == EXIT_USAGE
    assert "empty" in err
    assert calls == []


def test_invalid_email_rejected() -> None:
    argv = ["create-admin", "--email", "not-an-email", "--full-name", "X"]
    code, _o, err, calls = _run(argv)
    assert code == EXIT_USAGE
    assert "email" in err
    assert calls == []


def test_blank_full_name_rejected() -> None:
    argv = ["create-admin", "--email", "a@example.com", "--full-name", "   "]
    code, _o, _e, calls = _run(argv)
    assert code == EXIT_USAGE
    assert calls == []


def test_existing_admin_refusal_is_reported() -> None:
    def refuse(_e: str, _p: str, _n: str) -> int:
        raise CliError("an admin account already exists", EXIT_REFUSED)

    code, _o, err, _ = _run(BASE, create=refuse)
    assert code == EXIT_REFUSED
    assert "already exists" in err


def test_password_is_not_a_cli_argument() -> None:
    """Passwords in argv leak via the process list and shell history."""
    with pytest.raises(SystemExit):
        main(BASE + ["--password", GOOD], stderr=io.StringIO())
