#!/usr/bin/env bash
# Build an offline wheelhouse for the Smart Home Security backend.
#
# RUN ON AN INTERNET-CONNECTED COMPUTER (Linux, macOS, or Windows via WSL /
# Git Bash):
#
#     cd backend
#     bash offline/build_wheelhouse.sh
#
# Target platform (measured in the Kiro sandbox, 2026-11-15):
#     CPython 3.11.15, linux x86_64, glibc 2.34 (Amazon Linux 2023)
#
# Needs: bash, python3 >= 3.8, pip, and a uv release that supports
#        --python-platform x86_64-manylinux_2_34 (the sandbox has uv 0.13.5).
#
# Output (refuses to overwrite any of these):
#     wheelhouse/                                     wheels + resolved pins + SHA256SUMS
#     wheelhouse-cp311-manylinux_2_34_x86_64.tar.gz   the single file to transfer
#     wheelhouse-cp311-manylinux_2_34_x86_64.tar.gz.sha256

set -euo pipefail

cd "$(dirname "$0")/.."            # always run from backend/
OUT="wheelhouse"
ARCHIVE="wheelhouse-cp311-manylinux_2_34_x86_64.tar.gz"
INDEX="https://pypi.org/simple"    # the ONLY package source (no mirrors, no extras)

fail() { echo "FAIL: $*" >&2; exit 1; }

[ -f requirements.txt ] || fail "requirements.txt not found"
command -v uv >/dev/null || fail "uv not found: python3 -m pip install --upgrade uv"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || fail "python3 >= 3.8 required"
for p in "$OUT" "$ARCHIVE" "$ARCHIVE.sha256"; do
    [ -e "$p" ] && fail "$p already exists; move it away first"
done
uv pip compile --help 2>/dev/null | grep -q 'x86_64-manylinux_2_34' \
    || fail "this uv is too old for --python-platform x86_64-manylinux_2_34; upgrade uv"

# Dependency-confusion guard: ignore every pip/uv configuration file and
# environment variable that could add or replace a package index.
for v in $(compgen -e | grep -E '^(PIP|UV)_' || true); do unset "$v"; done
export PIP_CONFIG_FILE=/dev/null

mkdir "$OUT"

echo "[1/3] Resolving for CPython 3.11.15 on x86_64-manylinux_2_34 (binary wheels only) ..."
uv --no-config pip compile requirements.txt \
    --python-version 3.11.15 \
    --python-platform x86_64-manylinux_2_34 \
    --only-binary :all: \
    --default-index "$INDEX" \
    --generate-hashes \
    --no-header \
    --no-annotate \
    --output-file "$OUT/requirements.resolved.txt"

echo "[2/3] Downloading exactly those wheels, hash-checked against the pins ..."
# Every manylinux tag the sandbox's pip accepts (verified with `pip debug`),
# i.e. glibc 2.5 .. 2.34. Listing only a few would miss wheels tagged, for
# example, manylinux_2_24 only.
PLATFORMS=(--platform manylinux1_x86_64 --platform manylinux2010_x86_64 --platform manylinux2014_x86_64)
for minor in $(seq 5 34); do PLATFORMS+=(--platform "manylinux_2_${minor}_x86_64"); done

python3 -m pip --isolated download \
    --disable-pip-version-check \
    --index-url "$INDEX" \
    --requirement "$OUT/requirements.resolved.txt" \
    --require-hashes \
    --no-deps \
    --only-binary=:all: \
    --dest "$OUT" \
    --implementation cp \
    --python-version 3.11 \
    --abi cp311 --abi abi3 --abi none \
    "${PLATFORMS[@]}"

echo "[3/3] Checking, writing SHA256SUMS and packing ..."
python3 offline/wheelhouse_tool.py pack "$OUT" "$ARCHIVE" >/dev/null

echo
echo "wheels : $(find "$OUT" -name '*.whl' | wc -l | tr -d ' ')"
echo "archive: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"
echo "sha256 : $(cut -d' ' -f1 "$ARCHIVE.sha256")"
echo
echo "Upload $ARCHIVE and $ARCHIVE.sha256. Send the sha256 value separately."
