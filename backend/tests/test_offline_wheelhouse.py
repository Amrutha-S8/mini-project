"""Regression tests for the offline wheelhouse tooling (stdlib only).

Uses tiny fake ``kirotest-*`` wheels in pytest's tmp_path. Nothing is
installed. Covers the defects found in the 2026-11-15 review.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

OFFLINE = Path(__file__).resolve().parent.parent / "offline"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, OFFLINE / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = _load("wheelhouse_tool")
tags = _load("check_wheel_tags")


def _wheel(dest: Path, name: str, version: str, tag: str) -> Path:
    dist = name.replace("-", "_")
    info = f"{dist}-{version}.dist-info"
    files = {
        f"{dist}/__init__.py": b"",
        f"{info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
        ).encode(),
        f"{info}/WHEEL": (
            f"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: {tag}\n"
        ).encode(),
    }
    rec = [
        f"{p},sha256={base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b'=').decode()},{len(d)}"
        for p, d in files.items()
    ]
    files[f"{info}/RECORD"] = ("\n".join([*rec, f"{info}/RECORD,,"]) + "\n").encode()
    out = dest / f"{dist}-{version}-{tag}.whl"
    with zipfile.ZipFile(out, "w") as z:
        for p, d in files.items():
            z.writestr(p, d)
    return out


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture
def house(tmp_path: Path) -> Path:
    wh = tmp_path / "wh"
    wh.mkdir()
    a = _wheel(wh, "kirotest-alpha", "1.0", "py3-none-any")
    b = _wheel(wh, "kirotest-beta", "2.0", "cp311-cp311-manylinux_2_17_x86_64")
    (wh / "requirements.resolved.txt").write_text(
        f"kirotest-alpha==1.0 \\\n    --hash=sha256:{_sha(a)}\n    # via -r req\n"
        f"kirotest-beta==2.0 \\\n    --hash=sha256:{_sha(b)}\n"
    )
    return wh


def _evil(path: Path, members: list[tuple[str, str, str]]) -> str:
    with tarfile.open(path, "w:gz") as t:
        for kind, name, target in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = 1
                t.addfile(info, io.BytesIO(b"x"))
            else:
                info.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
                info.linkname = target
                t.addfile(info)
    return _sha(path)


# --- requirements.resolved.txt ----------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "--find-links http://127.0.0.1:8765/",  # made pip contact the network
        "--index-url https://evil.example/simple",
        "-r other.txt",
        "-e .",
        "x @ https://evil.example/x.whl",
        "x==1.0",  # no hash
        "x==1.0 --hash=md5:abcd",
        'x==1.0 ; sys_platform == "win32" --hash=sha256:' + "a" * 64,
        "x[extra]==1.0 --hash=sha256:" + "a" * 64,
        "x>=1.0 --hash=sha256:" + "a" * 64,
    ],
)
def test_resolved_file_rejects_anything_but_hashed_pins(line: str) -> None:
    with pytest.raises(tool.WheelhouseError):
        tool.parse_resolved(line + "\n")


def test_resolved_file_accepts_uv_output_with_comments() -> None:
    text = "a-b==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n    # via c\n"
    assert tool.parse_resolved(text) == {"a-b": ("1.0", {"a" * 64})}


def test_resolved_file_rejects_duplicate_pin() -> None:
    line = "a==1.0 --hash=sha256:" + "a" * 64 + "\n"
    with pytest.raises(tool.WheelhouseError, match="twice"):
        tool.parse_resolved(line + line.replace("a==1.0", "A==1.0"))


# --- check ---------------------------------------------------------------------


def test_check_accepts_consistent_wheelhouse(house: Path) -> None:
    assert tool.check(house) == 2


def test_check_rejects_missing_wheel(house: Path) -> None:
    next(house.glob("kirotest_beta*")).unlink()
    with pytest.raises(tool.WheelhouseError, match="missing wheel"):
        tool.check(house)


def test_check_rejects_duplicate_wheel(house: Path) -> None:
    _wheel(house, "kirotest-beta", "1.9", "py3-none-any")
    with pytest.raises(tool.WheelhouseError, match="duplicate"):
        tool.check(house)


def test_check_rejects_unpinned_wheel(house: Path) -> None:
    _wheel(house, "kirotest-gamma", "1.0", "py3-none-any")
    with pytest.raises(tool.WheelhouseError, match="without a pin"):
        tool.check(house)


def test_check_rejects_tampered_wheel(house: Path) -> None:
    w = next(house.glob("kirotest_alpha*"))
    w.write_bytes(w.read_bytes() + b"\0")
    with pytest.raises(tool.WheelhouseError, match="hash"):
        tool.check(house)


@pytest.mark.parametrize(
    "tag",
    [
        "cp312-cp312-manylinux_2_17_x86_64",
        "cp311-cp311-manylinux_2_17_aarch64",
        "cp311-cp311-manylinux_2_35_x86_64",
        "cp311-cp311-musllinux_1_1_x86_64",
        "cp311-cp311-win_amd64",
    ],
)
def test_check_rejects_incompatible_wheel(house: Path, tag: str) -> None:
    _wheel(house, "kirotest-gamma", "1.0", tag)
    with pytest.raises(tool.WheelhouseError, match="incompatible"):
        tool.check(house)


def test_check_rejects_invalid_filename_and_stray_files(house: Path) -> None:
    (house / "evil.whl").write_bytes(b"x")
    with pytest.raises(tool.WheelhouseError, match="invalid wheel filename"):
        tool.check(house)
    (house / "evil.whl").unlink()
    (house / "notes.txt").write_text("x")
    with pytest.raises(tool.WheelhouseError, match="unexpected file"):
        tool.check(house)


@pytest.mark.parametrize(
    "name,ok",
    [
        ("a-1-py311-none-any.whl", True),
        ("a-1-py312-none-any.whl", False),
        ("a-1-cp39-abi3-manylinux_2_24_x86_64.whl", True),
        ("a-1-cp312-abi3-manylinux_2_17_x86_64.whl", False),
        ("a-1-cp311-cp311-linux_x86_64.whl", False),
        ("a-1-1build-py3-none-any.whl", True),
        ("a-1-py3-none.whl", False),
    ],
)
def test_tag_rules(name: str, ok: bool) -> None:
    assert tags.wheel_compatible(name) is ok


# --- pack / unpack --------------------------------------------------------------


def test_pack_unpack_round_trip_and_determinism(house: Path, tmp_path: Path) -> None:
    digest = tool.pack(house, tmp_path / "a.tar.gz")
    (house / "SHA256SUMS").unlink()
    assert tool.pack(house, tmp_path / "b.tar.gz") == digest
    out = tmp_path / "out"
    out.mkdir()
    tool.unpack(tmp_path / "a.tar.gz", digest, out)
    assert tool.check(out / "wheelhouse") == 2


def test_pack_refuses_to_overwrite(house: Path, tmp_path: Path) -> None:
    tool.pack(house, tmp_path / "a.tar.gz")
    with pytest.raises(tool.WheelhouseError, match="overwrite"):
        tool.pack(house, tmp_path / "a.tar.gz")


def test_unpack_rejects_wrong_hash_before_extracting(
    house: Path, tmp_path: Path
) -> None:
    tool.pack(house, tmp_path / "a.tar.gz")
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(tool.WheelhouseError, match="sha256"):
        tool.unpack(tmp_path / "a.tar.gz", "0" * 64, out)
    assert list(out.iterdir()) == []


def test_unpack_rejects_corrupted_archive(tmp_path: Path) -> None:
    bad = tmp_path / "bad.tar.gz"
    bad.write_bytes(b"not gzip" * 20)
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(tool.WheelhouseError, match="unreadable"):
        tool.unpack(bad, _sha(bad), out)
    assert list(out.iterdir()) == []


@pytest.mark.parametrize(
    "members",
    [
        [("file", "wheelhouse/../../escape.txt", "")],
        [("file", "/abs/escape.txt", "")],
        [("sym", "wheelhouse/link", "/etc")],
        [("hard", "wheelhouse/hl", "/etc/os-release")],
        [("file", "wheelhouse/sub/x.whl", "")],
        [("file", "elsewhere/x.whl", "")],
    ],
)
def test_unpack_rejects_unsafe_members_without_writing(
    tmp_path: Path, members: list[tuple[str, str, str]]
) -> None:
    archive = tmp_path / "evil.tar.gz"
    digest = _evil(archive, members)
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(tool.WheelhouseError, match="unsafe|not a regular file"):
        tool.unpack(archive, digest, out)
    assert list(out.iterdir()) == [], "nothing may be extracted"


def test_unpack_refuses_existing_destination(house: Path, tmp_path: Path) -> None:
    digest = tool.pack(house, tmp_path / "a.tar.gz")
    out = tmp_path / "out"
    (out / "wheelhouse").mkdir(parents=True)
    with pytest.raises(tool.WheelhouseError, match="already exists"):
        tool.unpack(tmp_path / "a.tar.gz", digest, out)


# --- compare-freeze ------------------------------------------------------------


def test_compare_freeze(house: Path, tmp_path: Path) -> None:
    req = house / "requirements.resolved.txt"
    ok = tmp_path / "ok.txt"
    ok.write_text("kirotest-alpha==1.0\nkirotest_beta==2.0\npip==24.0\n")
    tool.compare_freeze(req, ok)
    bad = tmp_path / "bad.txt"
    bad.write_text("kirotest-alpha==1.0\nkirotest-beta==2.1\nrequests==2.0\n")
    with pytest.raises(tool.WheelhouseError, match="differs"):
        tool.compare_freeze(req, bad)
