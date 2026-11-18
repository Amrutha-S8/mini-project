# Offline Installation Scripts — Review Record

**Date:** 2026-11-15. **Scope:** `backend/offline/build_wheelhouse.sh`,
`install_wheelhouse.sh`, `check_wheel_tags.py`, `docs/OFFLINE_INSTALL.md`.
**Method:** reading the code, then executing it against harmless fake
`kirotest-*` wheels in a scratch directory (since deleted). Nothing was
installed. Venv creation was blocked by a test stub in every install-mode run.

## 1. Defects found in the first version

| # | Severity | File | Defect | Evidence |
|---|---|---|---|---|
| 1 | **High** | install | Options inside `requirements.resolved.txt` are honoured by pip. A `--find-links http://…` line made pip contact the network **despite `--no-index`** | Local test server received 2 requests; the original accepted the file |
| 2 | **High** | install | `PIP_FIND_LINKS` and a user `pip.conf` added a remote source | 4 requests each. `--isolated` blocks both, but **not** `PIP_CONFIG_FILE` (still 4 requests) |
| 3 | **High** | build | Only 6 of the 33 manylinux tags the sandbox accepts were requested; a wheel tagged only `manylinux_2_24` could not be downloaded | Old flags: exit 1, 0 files. New flags: exit 0, 1 file. Tag set now equals `pip debug` on the sandbox (0 missing, 0 extra) |
| 4 | Medium | build | The connected computer's pip/uv config or `PIP_*`/`UV_*` variables could substitute another index (dependency confusion) | By reading; flags verified to parse |
| 5 | Medium | build | `uv pip compile` without `--only-binary` could pick a version with no compatible wheel, failing late | By reading |
| 6 | Medium | install | Archive extracted with GNU tar. Traversal, symlink and hard-link members ended with exit 2 and **no message**; a symlink pointing outside was left on disk; an absolute-path member was written under `wheels/projects/…` | Executed. No file escaped (GNU tar's own checks), but the behaviour was unsafe and silent |
| 7 | Medium | install | Missing, duplicate and unpinned wheels and URL requirements passed all pre-install checks | Executed: the original reached the venv step for `missing`, `duplicate`, `remote_links`, `url_req` |
| 8 | Low | install | Archive hashed with one read, extracted with another (time-of-check/time-of-use gap) | By reading |
| 9 | Low | install | Import smoke test ran with the current directory on `sys.path`, so the local `alembic/` folder could shadow the library | By reading |
| 10 | Low | install | Lock file written with `cp` after an earlier existence check | By reading |
| 11 | Low | install | No verify-only mode, no Python-version check, pip self-version check enabled, depended on the working directory | By reading |
| 12 | Low | install | Installed set never compared with the pins | By reading |
| 13 | Low | tags | Valid `py311-none-any` rejected; malformed names not fully rejected; crash without an argument | By reading and unit test |
| 14 | Low | doc | Secret-leak grep searched the literal word `SECRET_KEY`, not its value; interactive `create-admin`; `kill %1`; mypy not pointed at the venv | By reading |
| 15 | Low | build | macOS `tar` can add `._*` metadata files to the archive | Inference; not tested on macOS |

Correct from the start: the archive SHA-256 was checked before extraction;
existing `.venv` and lock file were protected; `set -euo pipefail` stopped on
failures.

## 2. Corrections made

- New `offline/wheelhouse_tool.py` (stdlib, Python 3.8+ syntax):
  `check`, `pack`, `unpack`, `compare-freeze`.
  - `requirements.resolved.txt` may contain only `name==version` plus
    `--hash=sha256:` lines and comments.
  - Only wheels, the pins file and `SHA256SUMS` may exist; `SHA256SUMS` must
    list exactly the files present.
  - Exactly one compatible wheel per pin, with matching version and a pinned
    hash; nothing unpinned.
  - Unpack: one read, hash, validate every member, then extract the same bytes
    with Python's `data` filter through a staging directory.
  - Pack: deterministic archive (same input gives the same SHA-256).
- `install_wheelhouse.sh`: `--verify-only`; preconditions before any write;
  pip always under `unshare -n` with `--isolated`, `--no-index`,
  `PIP_CONFIG_FILE=/dev/null` and `PIP_*` unset; offline dry-run resolution;
  `python -I`; freeze compared with pins; lock written with `noclobber`.
- `build_wheelhouse.sh`: PyPI only, `uv --no-config`, `pip --isolated`,
  variables unset, `--only-binary :all:` at resolve time, all 33 platform tags,
  packing through the tool.
- `check_wheel_tags.py`: `py30`–`py311`, filename validation, usage check.
- `tests/test_offline_wheelhouse.py`: 42 regression tests.

## 3. Tests executed on the corrected version

`--verify-only`, real script, fake fixtures:

| Case | Result |
|---|---|
| Correct archive hash | Accepted |
| Correct hash, uv-style `# via` comments | Accepted |
| Wrong archive hash | Rejected: `archive sha256 … != expected` |
| Corrupted archive (one byte flipped, original hash) | Rejected: hash mismatch |
| Not a gzip file (correct hash) | Rejected: `archive unreadable or unsafe` |
| Invalid wheel filename `evil.whl` | Rejected |
| cp312 wheel | Rejected: incompatible |
| aarch64 wheel | Rejected: incompatible |
| Missing wheel | Rejected: `missing wheel for kirotest-beta==2.0` |
| Duplicate wheel (two versions) | Rejected: `duplicate wheels` |
| Incomplete dependency set (pin and wheel both absent) | Rejected at offline dry-run |
| `--find-links http://…` in pins | Rejected |
| URL requirement in pins | Rejected |
| `..` traversal / absolute path / nested path | Rejected: unsafe member |
| Symlink / hard link | Rejected: not a regular file |

Install mode (venv creation blocked by a stub):

| Case | Result |
|---|---|
| Correct hash | Passed all checks, stopped at venv creation by the stub |
| Wrong hash | Rejected |
| Existing `.venv` | Rejected before any write |
| Existing `requirements.lock.txt` | Rejected; file unchanged |
| Existing `wheels/wheelhouse` | Rejected |
| Remote `--find-links` in pins | Rejected |

Other executed checks:

- Hostile environment (`PIP_FIND_LINKS`, `PIP_INDEX_URL`, `PIP_CONFIG_FILE`,
  user `pip.conf`, all pointing at a listening local server): verification
  passed and the server received **0 requests**.
- `noclobber`: a lock file created after the precheck was not overwritten.
- Pack is deterministic: two packs of identical input gave identical SHA-256.
- `compare-freeze` accepts an exact match and reports extra, missing and
  wrong-version packages.
- uv with the build flags, against fake wheels: for `x86_64-manylinux_2_34` it
  chose the glibc-2.17 cp311 version, skipped glibc-2.35 and cp312-only
  versions, and kept a Linux-only dependency.
- pip with `--require-hashes` rejects a wheel whose hash differs from the pin.
- Backend suite: 172 passed, 0 failed, 47 skipped. Ruff, Ruff format and mypy
  clean.

## 4. Not tested

- Resolving and downloading the real packages from PyPI (no network here).
- A real venv installation (would install packages).
- Running the build script on macOS or Windows.
