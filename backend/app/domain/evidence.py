"""Evidence reference validation and containment (finding P1, stdlib only).

An ``evidence_ref`` names a file (snapshot, clip) inside the approved evidence
directory. It is stored with security events and will later be used to locate
evidence. This module only validates and resolves references. It does not
open, read or serve files.

Two layers:

``validate_evidence_ref``
    Syntax only, no filesystem access. Accepts a short relative POSIX path
    made of ASCII components such as ``snap/2026-11-15/cam1-0001.jpg``.
    Anything non-canonical is rejected rather than rewritten: absolute paths,
    ``..`` and ``.`` components, empty components (``a//b``, trailing ``/``),
    backslashes, drive letters and other colons, ``~``, NUL and control
    characters, whitespace, non-ASCII text, leading dots or dashes, trailing
    dots, and Windows device names (the camera host runs Windows).

``resolve_evidence_path``
    Validates, joins the reference to the approved root, resolves symbolic
    links and requires the result to stay inside the resolved root. A symlink
    inside the root that points outside it is therefore rejected, including
    dangling ones.

Limits a future evidence server must still handle:

* Resolution is a check at one moment. A symlink swapped in afterwards
  (time-of-check to time-of-use) is not caught here, so a reader must open
  files with ``O_NOFOLLOW`` and re-verify the opened file, or keep the
  evidence directory writable only by the backend.
* Hard links cannot be told apart from ordinary files by path. The evidence
  directory must not be writable by other users.
* The approved root is passed in by the caller. It is not yet read from
  settings, because ``app/core/config.py`` needs pydantic, which cannot be
  installed in this environment.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

MAX_REF_LENGTH = 255
MAX_COMPONENTS = 8
MAX_COMPONENT_LENGTH = 100

# Starts with a letter or digit, then letters, digits, '.', '_' or '-'.
_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_WINDOWS_DEVICES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)


class InvalidEvidenceRef(ValueError):
    """The reference is malformed or would leave the evidence directory."""


def validate_evidence_ref(ref: object) -> str:
    """Return ``ref`` unchanged if it is a safe relative reference, else raise."""
    if not isinstance(ref, str):
        raise InvalidEvidenceRef("evidence_ref must be a string")
    if not 1 <= len(ref) <= MAX_REF_LENGTH:
        raise InvalidEvidenceRef(
            f"evidence_ref must be 1 to {MAX_REF_LENGTH} characters"
        )
    if not ref.isascii():
        raise InvalidEvidenceRef("evidence_ref must be ASCII")
    if ref.startswith("/"):
        raise InvalidEvidenceRef("evidence_ref must be relative, not absolute")
    parts = ref.split("/")
    if len(parts) > MAX_COMPONENTS:
        raise InvalidEvidenceRef(
            f"evidence_ref may have at most {MAX_COMPONENTS} components"
        )
    for part in parts:
        if part in {"", ".", ".."}:
            raise InvalidEvidenceRef("evidence_ref has an empty, '.' or '..' component")
        if len(part) > MAX_COMPONENT_LENGTH:
            raise InvalidEvidenceRef(
                f"evidence_ref component longer than {MAX_COMPONENT_LENGTH}"
            )
        if not _COMPONENT.fullmatch(part):
            raise InvalidEvidenceRef("evidence_ref component has invalid characters")
        if part.endswith("."):
            raise InvalidEvidenceRef("evidence_ref component may not end with '.'")
        if part.split(".")[0].lower() in _WINDOWS_DEVICES:
            raise InvalidEvidenceRef("evidence_ref uses a reserved device name")
    # Defence in depth: the checks above should make these impossible.
    pure = PurePosixPath(ref)
    if pure.is_absolute() or ".." in pure.parts or str(pure) != ref:
        raise InvalidEvidenceRef("evidence_ref is not a canonical relative path")
    return ref


def resolve_evidence_path(root: str | Path, ref: object) -> Path:
    """Absolute, symlink-resolved path for ``ref`` inside ``root``.

    ``root`` must be an absolute path to an existing directory. The target
    file does not need to exist. Nothing is opened or read.
    """
    safe = validate_evidence_ref(ref)
    root_path = Path(root)
    if not root_path.is_absolute():
        raise InvalidEvidenceRef("evidence root must be an absolute path")
    try:
        real_root = root_path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise InvalidEvidenceRef("evidence root does not exist") from exc
    if not real_root.is_dir():
        raise InvalidEvidenceRef("evidence root is not a directory")
    try:
        candidate = (real_root / safe).resolve(strict=False)
    except (OSError, RuntimeError) as exc:  # e.g. a symlink loop
        raise InvalidEvidenceRef("evidence_ref could not be resolved") from exc
    if candidate == real_root or not candidate.is_relative_to(real_root):
        raise InvalidEvidenceRef("evidence_ref resolves outside the evidence root")
    return candidate
