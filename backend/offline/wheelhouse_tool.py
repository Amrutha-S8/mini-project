"""Validate, pack and safely unpack the offline wheelhouse (stdlib, Python 3.8+).

Subcommands
-----------
check   <wheelhouse-dir>
        Strict consistency check of a wheelhouse directory (both machines).
pack    <wheelhouse-dir> <archive.tar.gz>
        Run ``check``, write SHA256SUMS, build a deterministic archive and its
        .sha256 file. Used on the internet-connected computer.
unpack  <archive.tar.gz> <expected-sha256> <dest-parent>
        Hash the archive bytes, validate every member, extract with the
        ``data`` filter into <dest-parent>/wheelhouse, then verify SHA256SUMS
        and run ``check``. Used in the sandbox. Needs Python 3.8.17+/3.11.4+.
compare-freeze <requirements.resolved.txt> <pip-freeze.txt>
        Fail unless the installed set equals the resolved set exactly.

Every failure prints ``FAIL: ...`` to stderr and exits non-zero.

What ``check`` enforces
-----------------------
* requirements.resolved.txt contains ONLY ``name==version`` lines with one or
  more ``--hash=sha256:<64 hex>`` and comments. Any option (``--find-links``,
  ``--index-url``, ``-r``, ``-e``), URL, marker or extra is rejected: pip honours
  options inside requirement files, and a ``--find-links http://...`` line makes
  pip contact the network even with ``--no-index``.
* Only ``*.whl``, ``requirements.resolved.txt`` and ``SHA256SUMS`` may exist.
* Every wheel filename is well formed and compatible with the sandbox.
* Exactly one wheel per pinned project, with the pinned version, whose SHA-256
  is one of that pin's hashes. No wheel without a pin (no duplicates/extras).
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import os
import re
import shutil
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESOLVED = "requirements.resolved.txt"
SUMS = "SHA256SUMS"
TOP = "wheelhouse"
MAX_MEMBER_BYTES = 200 * 1024 * 1024
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
_HEX64 = re.compile(r"[0-9a-f]{64}")
_PIN = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"==(?P<version>[A-Za-z0-9.!+_-]+)"
    r"(?P<hashes>(?:\s+--hash=sha256:[0-9a-f]{64})+)$"
)
_SAFE_BASENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")


def _load_tags():
    """Import check_wheel_tags from THIS directory, independent of sys.path."""
    spec = importlib.util.spec_from_file_location(
        "check_wheel_tags", HERE / "check_wheel_tags.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError("cannot load check_wheel_tags.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TAGS = _load_tags()


class WheelhouseError(Exception):
    pass


def normalise(name: str) -> str:
    """PEP 503 project-name normalisation."""
    return re.sub(r"[-_.]+", "-", name).lower()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --- requirements.resolved.txt ------------------------------------------------


def parse_resolved(text: str) -> dict[str, tuple[str, set[str]]]:
    """{normalised name: (version, {sha256, ...})}. Rejects anything else."""
    logical: list[str] = []
    buf = ""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        if buf.strip():
            logical.append(" ".join(buf.split()))
        buf = ""
    if buf.strip():
        raise WheelhouseError("resolved file ends with a line continuation")

    pins: dict[str, tuple[str, set[str]]] = {}
    for entry in logical:
        m = _PIN.match(entry)
        if not m:
            raise WheelhouseError(
                f"{RESOLVED}: only 'name==version --hash=sha256:...' lines are "
                f"allowed, got: {entry[:120]!r}"
            )
        key = normalise(m.group("name"))
        if key in pins:
            raise WheelhouseError(f"{RESOLVED}: {key} pinned twice")
        hashes = set(re.findall(r"sha256:([0-9a-f]{64})", m.group("hashes")))
        pins[key] = (m.group("version"), hashes)
    if not pins:
        raise WheelhouseError(f"{RESOLVED} contains no requirements")
    return pins


def _versions_equal(a: str, b: str) -> bool:
    try:
        from packaging.version import Version  # optional; exact string fallback

        return Version(a) == Version(b)
    except Exception:
        return a.lower() == b.lower()


# --- check -------------------------------------------------------------------


def check(wheelhouse: Path) -> int:
    if not wheelhouse.is_dir():
        raise WheelhouseError(f"{wheelhouse} is not a directory")
    entries = sorted(wheelhouse.iterdir())
    for p in entries:
        if p.is_symlink() or not p.is_file():
            raise WheelhouseError(f"not a regular file: {p.name}")
        if not (p.name.endswith(".whl") or p.name in (RESOLVED, SUMS)):
            raise WheelhouseError(f"unexpected file in wheelhouse: {p.name}")

    resolved = wheelhouse / RESOLVED
    if not resolved.is_file():
        raise WheelhouseError(f"{RESOLVED} missing")
    pins = parse_resolved(resolved.read_text(encoding="utf-8"))

    wheels = [p for p in entries if p.name.endswith(".whl")]
    if not wheels:
        raise WheelhouseError("no wheels found")

    by_project: dict[str, list[Path]] = {}
    for w in wheels:
        parsed = TAGS.parse_wheel_filename(w.name)
        if parsed is None:
            raise WheelhouseError(f"invalid wheel filename: {w.name}")
        if not TAGS.wheel_compatible(w.name):
            raise WheelhouseError(
                f"incompatible wheel (needs cp311 / linux x86_64 / glibc <= 2.34): "
                f"{w.name}"
            )
        by_project.setdefault(normalise(parsed[0]), []).append(w)

    for project, files in sorted(by_project.items()):
        if len(files) > 1:
            names = ", ".join(f.name for f in files)
            raise WheelhouseError(f"duplicate wheels for {project}: {names}")
        if project not in pins:
            raise WheelhouseError(f"wheel without a pin: {files[0].name}")

    for project, (version, hashes) in sorted(pins.items()):
        matches = by_project.get(project)
        if not matches:
            raise WheelhouseError(f"missing wheel for {project}=={version}")
        wheel = matches[0]
        wheel_version = TAGS.parse_wheel_filename(wheel.name)[1]
        if not _versions_equal(wheel_version, version):
            raise WheelhouseError(
                f"{wheel.name} is version {wheel_version}, pin is {version}"
            )
        if sha256_file(wheel) not in hashes:
            raise WheelhouseError(f"{wheel.name} hash is not among the pinned hashes")
    return len(wheels)


# --- SHA256SUMS ---------------------------------------------------------------


def write_sums(wheelhouse: Path) -> None:
    files = sorted(
        p.name for p in wheelhouse.iterdir() if p.is_file() and p.name != SUMS
    )
    lines = [f"{sha256_file(wheelhouse / n)}  {n}" for n in files]
    (wheelhouse / SUMS).write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_sums(wheelhouse: Path) -> None:
    sums = wheelhouse / SUMS
    if not sums.is_file():
        raise WheelhouseError(f"{SUMS} missing")
    listed: dict[str, str] = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or not _HEX64.fullmatch(parts[0]):
            raise WheelhouseError(f"malformed {SUMS} line: {line[:120]!r}")
        name = parts[1].strip().lstrip("*")
        if name.startswith("./"):
            name = name[2:]
        if "/" in name or name in listed:
            raise WheelhouseError(f"bad or repeated {SUMS} entry: {name!r}")
        listed[name] = parts[0]
    present = {p.name for p in wheelhouse.iterdir() if p.name != SUMS}
    if set(listed) != present:
        extra = sorted(present - set(listed))
        missing = sorted(set(listed) - present)
        raise WheelhouseError(
            f"{SUMS} does not match the files present "
            f"(unlisted: {extra}, listed but absent: {missing})"
        )
    for name, digest in sorted(listed.items()):
        if sha256_file(wheelhouse / name) != digest:
            raise WheelhouseError(f"checksum mismatch: {name}")


# --- pack ---------------------------------------------------------------------


def pack(wheelhouse: Path, archive: Path) -> str:
    if archive.exists() or Path(str(archive) + ".sha256").exists():
        raise WheelhouseError(f"refusing to overwrite {archive}")
    count = check(wheelhouse)
    write_sums(wheelhouse)
    verify_sums(wheelhouse)

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        top = tarfile.TarInfo(TOP)
        top.type, top.mode, top.mtime = tarfile.DIRTYPE, 0o755, 0
        tar.addfile(top)
        for name in sorted(p.name for p in wheelhouse.iterdir()):
            data = (wheelhouse / name).read_bytes()
            info = tarfile.TarInfo(f"{TOP}/{name}")
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    gz = io.BytesIO()
    with gzip.GzipFile(fileobj=gz, mode="wb", mtime=0, filename="") as fh:
        fh.write(raw.getvalue())
    payload = gz.getvalue()
    archive.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    Path(str(archive) + ".sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="utf-8"
    )
    print(f"      packed {count} wheels")
    return digest


# --- unpack -------------------------------------------------------------------


def _validate_members(members: list[tarfile.TarInfo]) -> None:
    seen: set[str] = set()
    for m in members:
        name = m.name
        if name in seen:
            raise WheelhouseError(f"archive member repeated: {name!r}")
        seen.add(name)
        if name == TOP and m.isdir():
            continue
        prefix = TOP + "/"
        base = name[len(prefix) :] if name.startswith(prefix) else ""
        if not base or "/" in base or not _SAFE_BASENAME.fullmatch(base):
            raise WheelhouseError(f"unsafe or unexpected archive member: {name!r}")
        if not m.isreg():
            raise WheelhouseError(f"archive member is not a regular file: {name!r}")
        if m.size > MAX_MEMBER_BYTES:
            raise WheelhouseError(f"archive member too large: {name!r}")


def unpack(archive: Path, expected: str, dest_parent: Path) -> Path:
    expected = expected.strip().lower()
    if not _HEX64.fullmatch(expected):
        raise WheelhouseError("expected SHA-256 must be 64 lowercase hex characters")
    if archive.is_symlink() or not archive.is_file():
        raise WheelhouseError(f"{archive} is not a regular file")
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise WheelhouseError("archive larger than 1 GiB")
    dest = dest_parent / TOP
    if os.path.lexists(dest):
        raise WheelhouseError(f"{dest} already exists")
    if not hasattr(tarfile, "data_filter"):
        raise WheelhouseError("this Python lacks tarfile extraction filters")

    # Read once and hash those exact bytes, then extract from the same bytes:
    # nothing can swap the file between the check and the extraction.
    payload = archive.read_bytes()
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected:
        raise WheelhouseError(f"archive sha256 {actual} != expected {expected}")
    print(f"      archive sha256 OK {actual}")

    staging = dest_parent / f".{TOP}.partial-{os.getpid()}"
    if os.path.lexists(staging):
        raise WheelhouseError(f"{staging} already exists")
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
            members = tar.getmembers()
            _validate_members(members)  # before anything touches the disk
            staging.mkdir(mode=0o755)
            tar.extractall(staging, members=members, filter="data")
        (staging / TOP).rename(dest)
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise WheelhouseError(f"archive unreadable or unsafe: {exc}") from None
    finally:
        # The staging directory was created above by this process; removing it
        # cannot touch anything else.
        if staging.exists():
            shutil.rmtree(staging)

    verify_sums(dest)
    count = check(dest)
    print(f"      unpacked and verified {count} wheels (SHA256SUMS + pins + tags)")
    return dest


# --- compare-freeze -------------------------------------------------------------

BOOTSTRAP = {"pip", "setuptools", "wheel"}


def compare_freeze(resolved: Path, freeze: Path) -> None:
    pins = parse_resolved(resolved.read_text(encoding="utf-8"))
    installed: dict[str, str] = {}
    for line in freeze.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            raise WheelhouseError(f"unexpected freeze line: {line!r}")
        name, version = line.split("==", 1)
        installed[normalise(name)] = version
    wanted = {k: v for k, (v, _h) in pins.items()}
    extra = sorted(set(installed) - set(wanted) - BOOTSTRAP)
    missing = sorted(set(wanted) - set(installed))
    wrong = sorted(
        k
        for k in set(wanted) & set(installed)
        if not _versions_equal(installed[k], wanted[k])
    )
    if extra or missing or wrong:
        raise WheelhouseError(
            f"installed set differs from lock: extra={extra} missing={missing} "
            f"wrong_version={wrong}"
        )
    print(f"      installed set matches the lock exactly ({len(wanted)} packages)")


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 3 and argv[1] == "check":
            print(f"      OK: {check(Path(argv[2]))} wheels consistent with pins")
        elif len(argv) == 4 and argv[1] == "pack":
            print(pack(Path(argv[2]), Path(argv[3])))
        elif len(argv) == 5 and argv[1] == "unpack":
            unpack(Path(argv[2]), argv[3], Path(argv[4]))
        elif len(argv) == 4 and argv[1] == "compare-freeze":
            compare_freeze(Path(argv[2]), Path(argv[3]))
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except WheelhouseError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
