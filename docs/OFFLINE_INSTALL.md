# Offline Dependency Installation (Day 2)

**Status (2026-11-15):** prepared and reviewed, **not executed**. The sandbox is
`INTEGRATIONS_ONLY`, so PyPI is unreachable. No package has been installed,
no lock file exists, and no version below has been resolved yet.

Files for this procedure (no application code was changed). Reviewed and
corrected on 2026-11-15; see `docs/OFFLINE_SCRIPTS_REVIEW.md`.

| File | Runs on | Purpose |
|---|---|---|
| `backend/offline/build_wheelhouse.sh` | Internet-connected computer | Resolve, download, check and pack every wheel |
| `backend/offline/install_wheelhouse.sh` | Sandbox | Verify (`--verify-only`) or install offline, then write the lock file |
| `backend/offline/wheelhouse_tool.py` | Both | Strict checks, deterministic packing, safe unpacking, installed-set check |
| `backend/offline/check_wheel_tags.py` | Both (imported) | Wheel-tag rules for cp311 / linux x86_64 / glibc <= 2.34 |
| `backend/tests/test_offline_wheelhouse.py` | Sandbox | 42 regression tests for the tooling (stdlib, fake wheels) |

---

## 1. Target platform (measured in the sandbox)

| Property | Value |
|---|---|
| Python | **CPython 3.11.15**, `/root/.pyenv/versions/3.11.15/bin/python3` |
| ABI tag | `cp311` |
| OS | Amazon Linux 2023, `linux-x86_64` |
| Architecture | `x86_64` |
| C library | **glibc 2.34** |
| Most specific wheel tag | `cp311-cp311-manylinux_2_34_x86_64` |
| Oldest accepted | `manylinux1` / `manylinux2014` / `manylinux_2_17` (x86_64) |
| Not accepted | `musllinux`, `aarch64`, `win_*`, `macosx_*`, `manylinux_2_35` or newer |
| Tooling present | pip 26.2.2, uv 0.13.5, `venv` + `ensurepip` |

Any wheel whose tag needs glibc newer than 2.34 will not install here. The
build script restricts downloads to compatible tags, and the install script
checks them again before pip runs.

---

## 2. Dependency inventory

### 2.1 Direct dependencies (from `backend/requirements.txt`)

Versions are the declared ranges. **Exact versions are decided by the resolver
in step 1 of the build script** and recorded in `requirements.resolved.txt`.

| Package | Declared range | Purpose | Used by | Platform wheel |
|---|---|---|---|---|
| fastapi | `>=0.115,<1.0` | Web framework | `app/`, `tests/` | No (pure) |
| uvicorn[standard] | `>=0.30,<1.0` | ASGI server (CLI, not imported) | Run command | No (extras are) |
| sqlalchemy | `>=2.0,<3.0` | ORM, sync engine | `app/`, `alembic/`, `tests/` | **Yes** |
| alembic | `>=1.13,<2.0` | Migrations | `alembic/`, `tests/` | No |
| pydantic | `>=2.7,<3.0` | Validation | `app/` | No (core is) |
| pydantic-settings | `>=2.3,<3.0` | `.env` settings | `app/core/config.py` | No |
| email-validator | `>=2.1,<3.0` | Backs `EmailStr` (not imported directly) | `app/schemas/auth.py` | No |
| argon2-cffi | `>=23.1,<26.0` | Argon2id hashing | `app/core/security.py` | No (bindings are) |
| pyjwt | `>=2.8,<3.0` | JWT HS256 | `app/core/security.py`, `tests/` | No |
| pytest | `>=8.0` | Test runner | `tests/` | No |
| httpx | `>=0.27,<1.0` | Required by `fastapi.testclient` | `tests/` | No |

The AST scan of `app/`, `alembic/` and `tests/` found eight third-party import
roots: `alembic`, `argon2`, `fastapi`, `jwt`, `pydantic`, `pydantic_settings`,
`pytest`, `sqlalchemy`. All are covered by the table. Nothing is imported that
is not declared.

### 2.2 Expected transitive dependencies

These are **expected** from each package's published metadata. They are not
pinned or verified here; `requirements.resolved.txt` is the authoritative list
and may contain more (for example a new dependency added in a recent release).

| Package | Pulled in by | Purpose | Platform wheel |
|---|---|---|---|
| starlette | fastapi | ASGI toolkit | No |
| anyio | starlette, httpx, watchfiles | Async I/O | No |
| idna | anyio, httpx, email-validator | Hostnames | No |
| sniffio | anyio (older versions), httpx | Async library detection | No |
| typing-extensions | fastapi, pydantic, sqlalchemy, alembic | Typing backports | No |
| pydantic-core | pydantic | Validation engine | **Yes** |
| annotated-types | pydantic | Constraint types | No |
| typing-inspection | pydantic, pydantic-settings | Type introspection | No |
| python-dotenv | pydantic-settings, uvicorn[standard] | `.env` loading | No |
| dnspython | email-validator | Email domain checks | No |
| greenlet | sqlalchemy (required on x86_64 in 2.0.x) | Async bridge | **Yes** |
| Mako | alembic | Migration templates | No |
| MarkupSafe | Mako | Escaping | **Yes** |
| argon2-cffi-bindings | argon2-cffi | Native Argon2 | **Yes** (abi3) |
| cffi | argon2-cffi-bindings | C FFI | **Yes** |
| pycparser | cffi | C parser | No |
| click | uvicorn | CLI | No |
| h11 | uvicorn, httpcore | HTTP/1.1 | No |
| httptools | uvicorn[standard] | Fast HTTP parser | **Yes** |
| uvloop | uvicorn[standard] (non-Windows only) | Event loop | **Yes** |
| watchfiles | uvicorn[standard] | `--reload` | **Yes** |
| websockets | uvicorn[standard] | WebSocket protocol | **Yes** |
| PyYAML | uvicorn[standard] | Log config | **Yes** |
| httpcore | httpx | HTTP transport | No |
| certifi | httpx, httpcore | CA bundle | No |
| iniconfig | pytest | Config parsing | No |
| pluggy | pytest | Plugins | No |
| packaging | pytest | Version parsing | No |
| Pygments | pytest | Output colouring | No |

Not expected on this target: `tomli`, `exceptiongroup` (Python < 3.11 only),
`colorama` (Windows only).

### 2.3 Installed vs missing (checked in the sandbox's system Python)

| Status | Packages |
|---|---|
| **Installed** (dev tooling) | click 8.5.0, typing-extensions 4.16.0, pytest 9.1.1, iniconfig 2.3.1, pluggy 1.7.0, packaging 26.3, Pygments 2.21.0 |
| **Missing** | fastapi, starlette, pydantic, pydantic-core, pydantic-settings, email-validator, dnspython, SQLAlchemy, greenlet, alembic, Mako, MarkupSafe, argon2-cffi, argon2-cffi-bindings, cffi, pycparser, PyJWT, uvicorn, h11, httptools, uvloop, watchfiles, websockets, python-dotenv, PyYAML, httpx, httpcore, anyio, sniffio, idna, certifi, annotated-types, typing-inspection |

The installed packages are in the **system** Python. The project venv is
isolated from them, so **every package must be in the wheelhouse**, including
those already installed system-wide.

### 2.4 Conflicts and issues

Checked statically (the resolver gives the final answer):

- **No duplicate requirements and no empty version ranges.**
- **No conflict between declared ranges.** pydantic-settings 2.x needs
  pydantic v2, and the file allows `>=2.7,<3`. alembic 1.13+ supports
  SQLAlchemy 2.x.
- **`pytest-asyncio` was removed** (2026-11-15, approved): nothing used it.
- **`pytest` has no upper bound.** The resolver will take
  the newest release. That is acceptable once the lock file pins it.
- **`backend/.gitignore` used to ignore `requirements.lock.txt`.** A lock file is
  normally committed so installs are reproducible. The ignore rule was removed
  (approved 2026-11-15).
- **`aiosqlite` is not in `requirements.txt`.** That is correct: the project
  uses the synchronous engine.

---

## 3. Building the wheelhouse on a connected computer

Any OS works (Windows through WSL or Git Bash). The script resolves for the
**sandbox's** platform, not the computer it runs on.

```bash
# 1. Unzip the latest project snapshot and enter backend/
cd backend

# 2. Tools: python3 >= 3.8, pip, and a uv that supports x86_64-manylinux_2_34
python3 -m pip install --upgrade pip uv

# 3. Build
bash offline/build_wheelhouse.sh
```

What it does:

1. Unsets every `PIP_*` / `UV_*` variable, ignores pip and uv config files and
   uses **only** `https://pypi.org/simple`. This prevents a mirror or extra index
   on your computer from supplying a different package (dependency confusion).
2. `uv pip compile --python-version 3.11.15 --python-platform x86_64-manylinux_2_34
   --only-binary :all: --generate-hashes`: exact pins plus PyPI SHA-256 hashes,
   choosing only versions that have a compatible binary wheel. uv evaluates
   environment markers for the target. Tested here with fake wheels: a
   glibc-2.35 wheel and a cp312-only version were skipped, and a Linux-only
   dependency was kept even though plain pip on macOS/Windows would drop it.
3. `pip --isolated download --no-deps --require-hashes --only-binary=:all:` with
   **all 33** manylinux tags the sandbox accepts (glibc 2.5 to 2.34). pip refuses
   any file whose hash differs from the pin.
4. `wheelhouse_tool.py pack`: strict check, `SHA256SUMS`, and a deterministic
   archive (regular files only, fixed timestamps and owners; no macOS `._*`
   files) plus its `.sha256`.

**Keep the printed SHA-256 and send it separately from the upload.** It is the
root of trust: the installer rejects anything that does not match it.

The script refuses to overwrite `wheelhouse/` or the archive. If resolution
fails, it stops at step 2 and prints the conflict.

## 4. Transferring it into the sandbox

**Upload location:** `/projects/sandbox/backend/wheels/`
(already listed in `backend/.gitignore`). Two files go there:

```
backend/wheels/wheelhouse-cp311-manylinux_2_34_x86_64.tar.gz
backend/wheels/wheelhouse-cp311-manylinux_2_34_x86_64.tar.gz.sha256
```

Kiro Web documents **no direct file-upload into the sandbox filesystem**. Prompt
attachments are documented for images and documents only. Two routes, in order
of reliability:

**Route A (recommended): through a connected GitHub repository.** This uses the
documented integration, which works under `INTEGRATIONS_ONLY`.

1. Connect GitHub: Settings → Integrations → Connect GitHub, and grant the Kiro
   app access to a repository.
2. On the connected computer, commit the two files to that repository, for
   example under `wheels/` on a branch named `wheelhouse`, and push.
   GitHub rejects files over 100 MB; check the archive size the script prints.
3. In the sandbox, tell me the `owner/repo` and branch. I clone it through the
   Kiro gateway and copy the two files into `backend/wheels/`.

**Route B (undocumented, try only if A is not possible):** attach the archive to
a chat message. Whether a `.tar.gz` attachment reaches the sandbox filesystem is
not documented. If it doesn't, use Route A.

---

## 5. Installing in the sandbox (offline)

```bash
cd /projects/sandbox/backend
bash offline/install_wheelhouse.sh --verify-only <archive-sha256>   # creates nothing
bash offline/install_wheelhouse.sh <archive-sha256>                 # installs
```

Before writing anything it checks the expected hash is given, Python is 3.11,
`unshare -n` works, and `.venv/`, `requirements.lock.txt` and
`wheels/wheelhouse/` do not exist. Then:

| Step | Check | Stops on |
|---|---|---|
| 1 | Reads the archive once, hashes those bytes, compares with your SHA-256; validates every member (only regular files directly under `wheelhouse/`, no `..`, absolute paths, links or devices); extracts the same bytes with Python's `data` filter; verifies `SHA256SUMS` lists exactly the files present; strict pin check | Any mismatch, unsafe member, missing, duplicate, unpinned, incompatible or tampered wheel; any option, URL or marker in the pins file |
| 2 | `pip install --dry-run --ignore-installed` offline | Incomplete dependency set |
| 3 | Creates `.venv` with Python 3.11.15 | |
| 4 | `pip install --no-index --require-hashes --only-binary=:all:`, then `pip check` | Hash or dependency error |
| 5 | Imports every direct dependency, checks an `$argon2id$` hash, compares `pip freeze` with the pins | Any extra, missing or different version |
| 6 | Writes `requirements.lock.txt` with `noclobber` | Lock appeared meanwhile |

Every pip call runs under `unshare -n` (no network interface) with
`--isolated`, `--no-index`, `PIP_CONFIG_FILE=/dev/null` and all `PIP_*`
variables unset. `--verify-only` extracts into a temporary directory and removes
it on exit.

If steps 3 to 6 fail, the script leaves `.venv/` and `wheels/wheelhouse/` for
inspection and prints how to retry; it never deletes them itself.

## 6. Day 2 runtime verification (after a successful install)

Run in order. **None of this has been executed yet.**

```bash
cd /projects/sandbox/backend
source .venv/bin/activate
mkdir -p /tmp/day2_verify
export APP_ENV=development
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export DATABASE_PATH=/tmp/day2_verify/smarthome.db
ADMIN_PW="$(python -c 'import secrets; print(secrets.token_urlsafe(18))')"

# Migrate a fresh database and confirm the tables
alembic upgrade head
alembic current                       # expect: 0001_initial_identity (head)
python -c "import sqlite3,os; c=sqlite3.connect(os.environ['DATABASE_PATH']); print(sorted(r[0] for r in c.execute(\"select name from sqlite_master where type='table'\")))"

# First admin (password from stdin, never an argument)
printf '%s\n' "$ADMIN_PW" | python -m app.cli create-admin \
    --email owner@example.com --full-name "Owner" --password-stdin

# Server + health checks
uvicorn app.main:app --port 8000 > /tmp/day2_verify/uvicorn.log 2>&1 &
UVICORN_PID=$!
sleep 3
curl -s http://127.0.0.1:8000/api/v1/health
curl -s http://127.0.0.1:8000/api/v1/health/ready
kill "$UVICORN_PID"

# Full suite and static checks
python -m pytest -rs
ruff check . && ruff format --check .
mypy --python-executable .venv/bin/python app tests offline   # type-check against the installed stack

# The real secret values must not appear in the server log
for secret in "$SECRET_KEY" "$ADMIN_PW"; do
    grep -qF -- "$secret" /tmp/day2_verify/uvicorn.log && echo "LEAK FOUND" || echo "not in log"
done
grep -nE 'eyJ[A-Za-z0-9_-]{8,}\.|\$argon2id\$' /tmp/day2_verify/uvicorn.log || echo "no tokens or hashes in log"
```

The `pytest` run includes the 43 integration tests and the runtime
schema-parity test that currently skip. Expect some first-run failures: much
of the Day 2B code has only been checked statically.
