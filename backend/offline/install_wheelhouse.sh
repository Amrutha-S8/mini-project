#!/usr/bin/env bash
# Verify and install the backend dependencies from an uploaded wheelhouse.
#
# RUN INSIDE THE SANDBOX:
#
#     bash backend/offline/install_wheelhouse.sh --verify-only <archive-sha256>
#     bash backend/offline/install_wheelhouse.sh <archive-sha256>
#
# --verify-only checks the upload (hash, members, wheels, pins, offline
# resolution) in a temporary directory and creates NOTHING else.
#
# Expects: backend/wheels/wheelhouse-cp311-manylinux_2_34_x86_64.tar.gz
#
# Guarantees:
#   * Stops at the first failed check (set -e, every check exits non-zero).
#   * Never overwrites .venv/, requirements.lock.txt or wheels/wheelhouse/.
#   * pip runs inside `unshare -n` (no network interface at all) with
#     --no-index, --isolated and PIP_CONFIG_FILE=/dev/null, so neither a
#     requirements-file option, an environment variable nor a pip.conf can
#     add a package source.

set -euo pipefail

cd "$(dirname "$0")/.."            # always run from backend/

VERIFY_ONLY=0
if [ "${1:-}" = "--verify-only" ]; then VERIFY_ONLY=1; shift; fi
EXPECTED_SHA="${1:-}"

ARCHIVE="wheels/wheelhouse-cp311-manylinux_2_34_x86_64.tar.gz"
VENV=".venv"
LOCK="requirements.lock.txt"
PY="/root/.pyenv/versions/3.11.15/bin/python3"
TOOL="offline/wheelhouse_tool.py"
PIP_FLAGS=(--isolated --disable-pip-version-check --no-cache-dir --no-input)
INSTALL_FLAGS=(--no-index --require-hashes --only-binary=:all:)

fail() { echo "FAIL: $*" >&2; exit 1; }

# --- preconditions: nothing is written before all of these pass --------------
[ -n "$EXPECTED_SHA" ] || fail "usage: $0 [--verify-only] <archive-sha256>"
[ -f requirements.txt ] || fail "backend/requirements.txt not found"
[ -x "$PY" ] || fail "Python not found at $PY"
"$PY" -c 'import sys; sys.exit(sys.version_info[:2] != (3, 11))' || fail "$PY is not Python 3.11"
command -v unshare >/dev/null || fail "unshare not available; cannot guarantee no network"
unshare -n true 2>/dev/null || fail "unshare -n not permitted; cannot guarantee no network"
if [ "$VERIFY_ONLY" -eq 0 ]; then
    [ -e "$VENV" ] && fail "$VENV already exists; remove it deliberately before reinstalling"
    [ -e "$LOCK" ] && fail "$LOCK already exists; remove it deliberately before regenerating"
    [ -e wheels/wheelhouse ] && fail "wheels/wheelhouse already exists; remove it first"
fi

for v in $(compgen -e | grep -E '^PIP_' || true); do unset "$v"; done
export PIP_CONFIG_FILE=/dev/null
offline() { unshare -n "$@"; }    # no network namespace for everything pip does

# --- 1. archive hash, members, SHA256SUMS, pins, tags ------------------------
if [ "$VERIFY_ONLY" -eq 1 ]; then
    [ -d wheels ] || fail "wheels/ not found"
    DEST="$(mktemp -d wheels/.verify-XXXXXX)"
    trap 'rm -rf -- "$DEST"' EXIT   # only the temp dir created on the line above
else
    DEST="wheels"
fi
echo "[1/6] Verifying archive and wheels ..."
"$PY" -I "$TOOL" unpack "$ARCHIVE" "$EXPECTED_SHA" "$DEST"
WH="$DEST/wheelhouse"
REQ="$WH/requirements.resolved.txt"

# --- 2. offline resolution, as if into an empty environment ------------------
echo "[2/6] Resolving offline (dry run, nothing installed) ..."
offline "$PY" -I -m pip "${PIP_FLAGS[@]}" install --dry-run --ignore-installed \
    "${INSTALL_FLAGS[@]}" --find-links "$WH" --requirement "$REQ" >/dev/null \
    || fail "offline resolution failed: the wheelhouse is incomplete or inconsistent"
echo "      OK"

if [ "$VERIFY_ONLY" -eq 1 ]; then
    echo
    echo "Verification passed. Nothing was installed or kept."
    echo "Install with: bash offline/install_wheelhouse.sh $EXPECTED_SHA"
    exit 0
fi

# --- 3. venv -----------------------------------------------------------------
echo "[3/6] Creating $VENV with $("$PY" -V) ..."
trap 'echo "Installation did not complete. Inspect, then remove $VENV and wheels/wheelhouse to retry." >&2' ERR
"$PY" -m venv "$VENV"

# --- 4. install --------------------------------------------------------------
echo "[4/6] Installing offline with hash checking ..."
offline "$VENV/bin/python" -I -m pip "${PIP_FLAGS[@]}" install \
    "${INSTALL_FLAGS[@]}" --find-links "$WH" --requirement "$REQ"
offline "$VENV/bin/python" -I -m pip "${PIP_FLAGS[@]}" check

# --- 5. imports + exact installed set ----------------------------------------
echo "[5/6] Import smoke test and installed-set check ..."
"$VENV/bin/python" -I - <<'PY'
import importlib
import importlib.metadata as md

for module, dist in [
    ("fastapi", "fastapi"), ("starlette", "starlette"), ("uvicorn", "uvicorn"),
    ("sqlalchemy", "SQLAlchemy"), ("alembic", "alembic"),
    ("pydantic", "pydantic"), ("pydantic_settings", "pydantic-settings"),
    ("email_validator", "email-validator"), ("argon2", "argon2-cffi"),
    ("jwt", "PyJWT"), ("httpx", "httpx"), ("pytest", "pytest"),
]:
    importlib.import_module(module)
    print(f"      {dist:20s} {md.version(dist)}")
from argon2 import PasswordHasher

assert PasswordHasher().hash("smoke-test-only").startswith("$argon2id$")
print("      argon2id hash OK")
PY
offline "$VENV/bin/python" -I -m pip "${PIP_FLAGS[@]}" freeze --all > wheels/pip-freeze-after-install.txt
"$PY" -I "$TOOL" compare-freeze "$REQ" wheels/pip-freeze-after-install.txt

# --- 6. lock file (only after everything above passed) -----------------------
echo "[6/6] Writing $LOCK ..."
set -o noclobber                   # refuse to overwrite, even if created meanwhile
cat "$REQ" > "$LOCK"
echo "      $LOCK: exact versions + PyPI SHA-256 hashes"

echo
echo "Offline installation verified. Next: docs/OFFLINE_INSTALL.md section 6."
