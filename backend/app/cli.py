"""Administrative command line.

    python -m app.cli create-admin --email owner@example.com --full-name "Owner"

Creates the FIRST administrator only. It refuses if any admin already exists;
further accounts are issued by an admin through ``POST /api/v1/auth/register``.

The password is never taken from a command-line argument, which would expose
it in the process list and shell history. It is read interactively (entered
twice, not echoed) or from standard input with ``--password-stdin`` for
automated provisioning, e.g. ``printf '%s' "$PW" | python -m app.cli ...``.

Argument handling and password collection are stdlib-only and import nothing
from the database layer until the account is actually created.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Callable, Sequence
from typing import TextIO

from app.utils.validators import (
    PasswordPolicyError,
    is_valid_email,
    normalise_email,
    validate_password_policy,
)

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_REFUSED = 3


class CliError(Exception):
    """User-facing failure with an exit code. Never carries a password."""

    def __init__(self, message: str, code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.code = code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create-admin", help="create the first administrator")
    create.add_argument("--email", required=True)
    create.add_argument("--full-name", required=True)
    create.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password from standard input instead of prompting",
    )
    return parser


def read_password(
    *,
    from_stdin: bool,
    stdin: TextIO,
    prompt: Callable[[str], str] = getpass.getpass,
) -> str:
    """Collect and policy-check a password without echoing or logging it."""
    if from_stdin:
        password = stdin.readline().rstrip("\r\n")
    else:
        password = prompt("Password: ")
        if prompt("Repeat password: ") != password:
            raise CliError("passwords do not match")
    if not password:
        raise CliError("password must not be empty")
    try:
        validate_password_policy(password)
    except PasswordPolicyError as exc:
        raise CliError(str(exc)) from None
    return password


def _create_admin(email: str, password: str, full_name: str) -> int:
    """Open the database and create the account. Returns the new user id."""
    from app.core.config import get_settings
    from app.database.session import get_writer_engine, init_engines
    from app.services import auth_service

    init_engines(get_settings())
    from sqlalchemy.orm import Session

    with Session(get_writer_engine()) as db:
        try:
            user = auth_service.create_first_admin(
                db, email=email, password=password, full_name=full_name
            )
        except auth_service.AdminAlreadyExistsError as exc:
            raise CliError(str(exc), EXIT_REFUSED) from None
        db.commit()
        return user.id


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    prompt: Callable[[str], str] = getpass.getpass,
    create: Callable[[str, str, str], int] = _create_admin,
) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_parser().parse_args(argv)

    try:
        email = normalise_email(args.email)
        if not is_valid_email(email):
            raise CliError("invalid email address")
        full_name = args.full_name.strip()
        if not full_name:
            raise CliError("full name must not be empty")
        password = read_password(
            from_stdin=args.password_stdin, stdin=stdin, prompt=prompt
        )
        user_id = create(email, password, full_name)
    except CliError as exc:
        print(f"error: {exc}", file=stderr)
        return exc.code

    print(f"admin created: id={user_id} email={email}", file=stdout)
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
