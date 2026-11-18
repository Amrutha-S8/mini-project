"""Finding P1: evidence references must stay inside the evidence directory.

Stdlib only. Symlink cases use pytest's ``tmp_path``; nothing is read or
served, only validated and resolved.
"""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app.domain.events import EventValidationError, normalise_event
from app.domain.evidence import (
    MAX_COMPONENT_LENGTH,
    MAX_COMPONENTS,
    MAX_REF_LENGTH,
    InvalidEvidenceRef,
    resolve_evidence_path,
    validate_evidence_ref,
)
from app.domain.pipeline import EventPipeline, MemorySink, Status

NOW = datetime(2026, 11, 16, 10, 0, tzinfo=UTC)


def _can_create_symlinks() -> bool:
    """Windows allows symlinks only with Developer Mode or admin rights."""
    with tempfile.TemporaryDirectory() as tmp:
        try:
            (Path(tmp) / "link").symlink_to(Path(tmp) / "target")
        except (OSError, NotImplementedError):
            return False
    return True


#: Applied only to tests that must create a symbolic link. They still run on
#: Linux, macOS and Windows with Developer Mode; elsewhere they are reported as
#: skipped (never as passed) with this reason.
needs_symlinks = pytest.mark.skipif(
    not _can_create_symlinks(),
    reason=(
        "this account cannot create symbolic links; on Windows enable "
        "Settings > System > For developers > Developer Mode, then re-run"
    ),
)

VALID = [
    "snap/1.jpg",
    "1.jpg",
    "snap/2026-11-15/cam1_0001.jpg",
    "clips/front-door/2026/11/15/visitor-v4.mp4",
    "a.b.c",
    "x" * MAX_COMPONENT_LENGTH,
    "/".join(["d"] * MAX_COMPONENTS),
    "auxiliary/console.jpg",  # contains device-like text but is not one
]

MALICIOUS = [
    # traversal
    "..",
    "../x.jpg",
    "../../etc/passwd",
    "snap/../../x.jpg",
    "snap/..",
    "snap/../x.jpg",
    # absolute
    "/etc/shadow",
    "/",
    "//server/share/x.jpg",
    # Windows forms
    "C:/Windows/win.ini",
    "C:x.jpg",
    "snap\\..\\..\\x.jpg",
    "\\\\server\\share\\x.jpg",
    "snap/file.jpg:hidden",  # NTFS alternate data stream
    "snap/x.jpg.",  # Windows strips the trailing dot
    "CON",
    "snap/nul.txt",
    "lpt1/x.jpg",
    "Com9.jpg",
    # home and hidden
    "~",
    "~/x.jpg",
    "~root/x.jpg",
    ".hidden",
    "snap/.ssh",
    # non-canonical
    ".",
    "./x.jpg",
    "snap/./x.jpg",
    "snap//x.jpg",
    "snap/",
    "-rf",
    "snap/-x.jpg",
    # control characters and whitespace
    "snap/x.jpg\x00.png",
    "snap/x\n.jpg",
    "snap/x\t.jpg",
    " snap/x.jpg",
    "snap/x.jpg ",
    "snap/my file.jpg",
    # other punctuation that has meaning to shells or URLs
    "snap/x.jpg?raw=1",
    "snap/x.jpg#frag",
    "snap/%2e%2e/x.jpg",
    "snap/$HOME",
    "snap/x;rm.jpg",
    "user@host/x.jpg",
    # non-ASCII, including look-alikes of '.' and '/'
    "snap/caf\u00e9.jpg",
    "snap\u2215x.jpg",  # division slash
    "\uff0e\uff0e/x.jpg",  # fullwidth full stops
    "snap/\u0661.jpg",  # Arabic-Indic digit one
    # limits
    "x" * (MAX_COMPONENT_LENGTH + 1),
    "/".join(["d"] * (MAX_COMPONENTS + 1)),
    "a/" * 127 + "aa",  # 256 characters
    "",
]


def event(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "event_type": "face.unknown_visitor",
        "source_module": "face_service",
        "occurred_at": "2026-11-16T09:59:58Z",
        "camera_id": "cam1",
    }
    base.update(overrides)
    return base


# --- syntax ------------------------------------------------------------------


@pytest.mark.parametrize("ref", VALID)
def test_valid_refs_accepted_unchanged(ref: str) -> None:
    assert validate_evidence_ref(ref) == ref


@pytest.mark.parametrize("ref", MALICIOUS)
def test_malicious_and_malformed_refs_rejected(ref: str) -> None:
    with pytest.raises(InvalidEvidenceRef):
        validate_evidence_ref(ref)


@pytest.mark.parametrize("ref", [None, 7, b"snap/1.jpg", Path("snap/1.jpg")])
def test_non_string_refs_rejected(ref: object) -> None:
    with pytest.raises(InvalidEvidenceRef, match="string"):
        validate_evidence_ref(ref)


def test_length_limit_is_exact() -> None:
    longest = "/".join(["a" * 63] * 4)  # 4*63 + 3 = 255
    assert len(longest) == MAX_REF_LENGTH
    assert validate_evidence_ref(longest) == longest
    with pytest.raises(InvalidEvidenceRef, match="characters"):
        validate_evidence_ref(longest + "a")


# --- event normalisation -----------------------------------------------------


@pytest.mark.parametrize("ref", ["../../etc/passwd", "/etc/shadow", "snap/../../x.jpg"])
def test_probe_refs_from_finding_p1_now_rejected(ref: str) -> None:
    with pytest.raises(EventValidationError, match="evidence_ref"):
        normalise_event(event(evidence_ref=ref), received_at=NOW)


@pytest.mark.parametrize("ref", MALICIOUS[:-1])  # "" means "no evidence"
def test_events_with_unsafe_refs_rejected_by_pipeline(ref: str) -> None:
    sink = MemorySink()
    pipeline = EventPipeline(sink, clock=lambda: NOW)
    result = pipeline.ingest(event(evidence_ref=ref))
    assert result.status is Status.REJECTED and sink.events == []
    assert pipeline.stats.rejection_reasons["evidence_ref"] == 1


@pytest.mark.parametrize("ref", VALID)
def test_events_with_valid_refs_keep_them(ref: str) -> None:
    e = normalise_event(event(evidence_ref=ref), received_at=NOW)
    assert e.evidence_ref == ref


@pytest.mark.parametrize("ref", [None, ""])
def test_missing_ref_means_no_evidence(ref: str | None) -> None:
    assert (
        normalise_event(event(evidence_ref=ref), received_at=NOW).evidence_ref is None
    )


def test_ref_is_not_silently_rewritten() -> None:
    """Other identifiers are stripped; evidence refs must already be exact."""
    with pytest.raises(EventValidationError, match="evidence_ref"):
        normalise_event(event(evidence_ref=" snap/1.jpg "), received_at=NOW)


# --- containment on a real filesystem ----------------------------------------


@pytest.fixture
def root(tmp_path: Path) -> Path:
    evidence = tmp_path / "evidence"
    (evidence / "snap").mkdir(parents=True)
    (evidence / "snap" / "1.jpg").write_bytes(b"jpg")
    return evidence


def test_resolves_inside_root(root: Path) -> None:
    path = resolve_evidence_path(root, "snap/1.jpg")
    assert path == (root / "snap" / "1.jpg").resolve()
    assert path.is_relative_to(root.resolve())


def test_target_need_not_exist_and_is_not_created(root: Path) -> None:
    path = resolve_evidence_path(root, "snap/2026/missing.jpg")
    assert path == root.resolve() / "snap" / "2026" / "missing.jpg"
    assert not path.exists() and not path.parent.exists()


def test_resolution_opens_no_file(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolution only inspects paths; it is not evidence retrieval."""
    expected = (root / "snap" / "1.jpg").resolve()

    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("resolve_evidence_path must not open files")

    monkeypatch.setattr(os, "open", refuse)
    monkeypatch.setattr("builtins.open", refuse)
    monkeypatch.setattr(Path, "open", refuse)
    assert resolve_evidence_path(root, "snap/1.jpg") == expected


@pytest.mark.parametrize("ref", MALICIOUS[:-1])
def test_resolver_rejects_malicious_refs(root: Path, ref: str) -> None:
    with pytest.raises(InvalidEvidenceRef):
        resolve_evidence_path(root, ref)


@needs_symlinks
def test_symlinked_file_pointing_outside_rejected(root: Path, tmp_path: Path) -> None:
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    (root / "snap" / "leak.jpg").symlink_to(outside)
    with pytest.raises(InvalidEvidenceRef, match="outside"):
        resolve_evidence_path(root, "snap/leak.jpg")


@needs_symlinks
def test_symlinked_directory_pointing_outside_rejected(root: Path) -> None:
    (root / "etc").symlink_to("/etc", target_is_directory=True)
    with pytest.raises(InvalidEvidenceRef, match="outside"):
        resolve_evidence_path(root, "etc/passwd")


@needs_symlinks
def test_relative_symlink_climbing_out_rejected(root: Path, tmp_path: Path) -> None:
    (tmp_path / "other").mkdir()
    (root / "snap" / "up").symlink_to("../../other", target_is_directory=True)
    with pytest.raises(InvalidEvidenceRef, match="outside"):
        resolve_evidence_path(root, "snap/up/x.jpg")


@needs_symlinks
def test_dangling_symlink_pointing_outside_rejected(root: Path) -> None:
    (root / "snap" / "later.jpg").symlink_to("/nonexistent-dir/later.jpg")
    with pytest.raises(InvalidEvidenceRef, match="outside"):
        resolve_evidence_path(root, "snap/later.jpg")


@needs_symlinks
def test_symlink_to_root_itself_rejected(root: Path) -> None:
    (root / "self").symlink_to(root, target_is_directory=True)
    with pytest.raises(InvalidEvidenceRef, match="outside"):
        resolve_evidence_path(root, "self")


@needs_symlinks
def test_symlink_loop_rejected(root: Path) -> None:
    (root / "loop_a").symlink_to(root / "loop_b")
    (root / "loop_b").symlink_to(root / "loop_a")
    with pytest.raises(InvalidEvidenceRef):
        resolve_evidence_path(root, "loop_a")


@needs_symlinks
def test_symlink_staying_inside_root_allowed(root: Path) -> None:
    (root / "latest.jpg").symlink_to(root / "snap" / "1.jpg")
    assert (
        resolve_evidence_path(root, "latest.jpg") == (root / "snap" / "1.jpg").resolve()
    )


@needs_symlinks
def test_symlinked_root_is_followed_once(root: Path, tmp_path: Path) -> None:
    """A root that is itself a symlink (e.g. to another disk) still works."""
    alias = tmp_path / "evidence-link"
    alias.symlink_to(root, target_is_directory=True)
    path = resolve_evidence_path(alias, "snap/1.jpg")
    assert path == (root / "snap" / "1.jpg").resolve()


@needs_symlinks
def test_sibling_with_shared_prefix_is_outside(tmp_path: Path) -> None:
    """'/x/evidence2' must not count as inside '/x/evidence'."""
    root = tmp_path / "evidence"
    root.mkdir()
    sibling = tmp_path / "evidence2"
    sibling.mkdir()
    (root / "s").symlink_to(sibling, target_is_directory=True)
    with pytest.raises(InvalidEvidenceRef, match="outside"):
        resolve_evidence_path(root, "s/x.jpg")


@pytest.mark.parametrize("bad_root", ["evidence", "relative/dir", ""])
def test_relative_root_rejected(bad_root: str) -> None:
    with pytest.raises(InvalidEvidenceRef, match="absolute"):
        resolve_evidence_path(bad_root, "snap/1.jpg")


def test_missing_root_rejected(tmp_path: Path) -> None:
    with pytest.raises(InvalidEvidenceRef, match="does not exist"):
        resolve_evidence_path(tmp_path / "nope", "snap/1.jpg")


def test_file_as_root_rejected(root: Path) -> None:
    with pytest.raises(InvalidEvidenceRef, match="not a directory"):
        resolve_evidence_path(root / "snap" / "1.jpg", "x.jpg")
