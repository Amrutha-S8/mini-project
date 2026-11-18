"""Wheel-tag compatibility for the sandbox target (stdlib only, Python 3.8+).

Target (measured 2026-11-15): CPython 3.11, linux x86_64, glibc 2.34.

A wheel is accepted if at least one of its compressed tag triples fits:
  * python: py3, py30..py311, cp311, or cp32..cp311 together with abi3
  * abi:    none, abi3 or cp311
  * platform: any, or manylinux1/2010/2014/_2_N for x86_64 with N <= 34

This mirrors ``pip debug --verbose`` on the sandbox, except that the plain
``linux_x86_64`` tag (locally built, never on PyPI) is deliberately rejected.

Usage: python check_wheel_tags.py <wheel-dir>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

MAX_GLIBC = (2, 34)
LEGACY = {"manylinux1": (2, 5), "manylinux2010": (2, 12), "manylinux2014": (2, 17)}
ABIS = {"none", "abi3", "cp311"}


def _glibc(platform_tag: str) -> tuple[int, int] | None:
    if not platform_tag.endswith("_x86_64"):
        return None
    base = platform_tag[: -len("_x86_64")]
    if base in LEGACY:
        return LEGACY[base]
    m = re.fullmatch(r"manylinux_(\d+)_(\d+)", base)
    return (int(m.group(1)), int(m.group(2))) if m else None


def _python_ok(py: str, abi: str) -> bool:
    if py in {"py3", "cp311"}:
        return True
    m = re.fullmatch(r"py3(\d+)", py)
    if m:
        return int(m.group(1)) <= 11
    m = re.fullmatch(r"cp3(\d+)", py)
    return abi == "abi3" and m is not None and 2 <= int(m.group(1)) <= 11


def _platform_ok(plat: str) -> bool:
    if plat == "any":
        return True
    glibc = _glibc(plat)
    return glibc is not None and glibc <= MAX_GLIBC


def parse_wheel_filename(filename: str) -> tuple[str, str, str, str, str] | None:
    """(distribution, version, python, abi, platform) or None if malformed."""
    if not filename.endswith(".whl"):
        return None
    parts = filename[: -len(".whl")].split("-")
    if len(parts) not in (5, 6):  # 6 = optional build tag
        return None
    if not all(parts) or not re.fullmatch(r"[A-Za-z0-9._]+", parts[0]):
        return None
    return parts[0], parts[1], parts[-3], parts[-2], parts[-1]


def wheel_compatible(filename: str) -> bool:
    parsed = parse_wheel_filename(filename)
    if parsed is None:
        return False
    _dist, _ver, pys, abis, plats = parsed
    return any(
        abi in ABIS and _python_ok(py, abi) and _platform_ok(pl)
        for py in pys.split(".")
        for abi in abis.split(".")
        for pl in plats.split(".")
    )


def main(argv: list) -> int:
    if len(argv) != 2:
        print("usage: check_wheel_tags.py <wheel-dir>", file=sys.stderr)
        return 2
    wheels = sorted(Path(argv[1]).glob("*.whl"))
    if not wheels:
        print("no wheels found", file=sys.stderr)
        return 1
    bad = [w.name for w in wheels if not wheel_compatible(w.name)]
    for name in bad:
        print(f"      incompatible: {name}", file=sys.stderr)
    if bad:
        return 1
    print(f"      OK: {len(wheels)} wheels fit cp311 / linux x86_64 / glibc <= 2.34")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
