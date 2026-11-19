# Windows Setup Guide — Phase 1 (backend only)

This guide gets the backend running on your Windows laptop from the GitHub
repository. It does **not** cover the webcam, face recognition, the frontend
or AI; those come in later phases.

**Status of these instructions:** checked against the repository files on
2026-11-19 (`backend/requirements.txt`, `pyproject.toml`, `alembic.ini`,
`alembic/env.py`, `app/core/config.py`, `.env.example`, `.gitignore`,
`scripts/windows_stage1_check.ps1`). They have **not been run on Windows
yet**. Run them one step at a time and send me the output of each step.

Every command is for **PowerShell**. Lines starting with `#` are comments; do
not type them.

**Phase 1 never creates or changes your real database.** Migrations and the
server run against a separate test file, `backend\data\phase1_test.db`. The
real database (`backend\data\smarthome.db`) is created in Phase 2.

---

## Overview: which folder each command runs in

| Folder | Path used in this guide | Used for |
|---|---|---|
| Project folder | `C:\SmartHome` | Git commands, the check script |
| Backend folder | `C:\SmartHome\backend` | everything else: venv, pip, tests, Alembic, the server |

Alembic and the server **must** run from the backend folder, because
`alembic.ini`, the `alembic\` migrations folder, `.env`, the `data\` folder
and the `app` package are all found relative to it.

Use a short path outside OneDrive. OneDrive can lock the SQLite file while it
syncs.

---

## Part A — Get the code

### Step 1 — Check Python 3.11

```powershell
py -3.11 --version
```

Expected: `Python 3.11.x`. The project targets Python 3.11
(`pyproject.toml`: `requires-python = ">=3.11"`); newer versions are
untested.

If you see `No suitable Python runtime found` or `'py' is not recognized`:
install Python 3.11 (64-bit) from <https://www.python.org/downloads/windows/>.
The last 3.11 release with a Windows installer is **3.11.9**. In the
installer keep **"py launcher"** ticked. Then close and reopen PowerShell.

### Step 2 — Check Git

```powershell
git --version
```

Expected: `git version 2.x`. If Git is missing, install it from
<https://git-scm.com/download/win> and reopen PowerShell.

### Step 3 — Check that the target folder is free

```powershell
Test-Path C:\SmartHome
```

Expected: `False`. If it prints `True`, the folder already exists. Do **not**
delete it; tell me, and we will pick a different folder name.

### Step 4 — Clone the repository

```powershell
git clone https://github.com/Amrutha-S8/mini-project.git C:\SmartHome
```

The repository is public, so no login is needed. Git prints its progress
(`Cloning into 'C:\SmartHome'...`) in red in some PowerShell versions; that
is normal, not an error. The last lines should mention `Resolving deltas:
100%`.

### Step 5 — Open the project folder

```powershell
cd C:\SmartHome
```

### Step 6 — Switch to the branch you are testing

Work that is not yet merged lives on a branch. While the Phase 1 pull request
is open, the updated guide and tools are on `phase-1-windows-setup`:

```powershell
git switch phase-1-windows-setup
```

Then confirm where you are:

```powershell
git status
```

Expected: `On branch phase-1-windows-setup`, `nothing to commit, working tree
clean`. After the pull request is merged, use `git switch main` and
`git pull` instead.

### Step 7 — Run the check script (first time)

Folder: **project folder** (`C:\SmartHome`).

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_stage1_check.ps1
```

It only reads; it changes nothing. `-ExecutionPolicy Bypass` applies to this
one command only. On a fresh clone you should see PASS for the project
structure and Python, and BLOCKED for the steps not done yet.

---

## Part B — Python environment and dependencies

### Step 8 — Go to the backend folder

```powershell
cd C:\SmartHome\backend
```

### Step 9 — Create the virtual environment

```powershell
py -3.11 -m venv .venv
```

This creates `backend\.venv`. It is listed in `.gitignore` and is never
committed.

### Step 10 — Activate it

```powershell
.\.venv\Scripts\Activate.ps1
```

The prompt now starts with `(.venv)`. If you get *"running scripts is
disabled on this system"*, allow scripts **for this window only**, then
activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

Activate again every time you open a new PowerShell window.

### Step 11 — Confirm the venv's Python is in use

```powershell
python -c "import sys; print(sys.version); print(sys.prefix)"
```

Expected: a `3.11.x` version on the first line, and a path ending in
`C:\SmartHome\backend\.venv` on the second. If the path is anything else, the
venv is not active; repeat Step 10.

### Step 12 — Upgrade pip inside the venv

```powershell
python -m pip install --upgrade pip
```

### Step 13 — Install the backend packages

There are two dependency files in `backend\`:

| File | What it contains | When to use it |
|---|---|---|
| `requirements.txt` | version **ranges** (for example `fastapi>=0.115,<1.0`) | the very first install, before a lock file exists |
| `requirements.lock.txt` | **exact** versions recorded from a working install | every install after the lock file has been committed |

Check whether the lock file exists:

```powershell
Test-Path requirements.lock.txt
```

If it prints `False` (first install), install from the ranges:

```powershell
python -m pip install -r requirements.txt
```

If it prints `True`, install the exact recorded versions instead:

```powershell
python -m pip install -r requirements.lock.txt
```

### Step 14 — Check for dependency conflicts

```powershell
python -m pip check
```

Expected: `No broken requirements found.` Any other output is a conflict;
send it to me.

### Step 15 — Record the installed versions

```powershell
python -m pip freeze
```

Send me the whole output. On the first install I turn it into
`backend\requirements.lock.txt` and commit it, so every later install gets
exactly the same versions. The lock file is recorded on Windows with Python
3.11, which is the platform this project targets.

Do not create the lock file with `python -m pip freeze > requirements.lock.txt`
in Windows PowerShell 5.1: `>` writes UTF-16, which pip cannot read back.

---

## Part C — Configuration

### Step 16 — Create the configuration file

Folder: **backend**.

```powershell
Copy-Item .env.example .env
```

`.env` holds your local settings and secrets. It is listed in `.gitignore`
and must never be committed, uploaded or pasted into a chat.

### Step 17 — Generate a secret key

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

This prints a random 64-character value. **Do not send it to me.**

### Step 18 — Put the secret key in `.env`

```powershell
notepad .env
```

In Notepad, find the line `SECRET_KEY=` and paste the value right after the
`=` (no spaces, no quotes). Save and close.

- The application, Alembic and the tests refuse to start without a
  `SECRET_KEY` of at least 32 characters.
- Leave `DATABASE_PATH=./data/smarthome.db` as it is. Phase 1 overrides it
  for one window only (Step 21).
- Leave `AI_ENABLED=false` and `GEMINI_ENABLED=false`.

### Step 19 — Run the check script again

Folder: **backend** (the script path is relative to it here).

```powershell
powershell -ExecutionPolicy Bypass -File ..\scripts\windows_stage1_check.ps1
```

Every check should now be PASS except "Database file" and "Health
endpoints" (BLOCKED, done in later steps). The script reports the length of
`SECRET_KEY`, never its value.

---

## Part D — Tests

### Step 20 — Run the backend tests

Folder: **backend**, `(.venv)` active.

```powershell
python -m pytest -q -rs
```

There are **1,261 tests**. Each API test creates its own temporary database,
so this does not touch `backend\data`. Expected on Windows: **1,261 passed,
0 skipped**, or **1,252 passed, 9 skipped** if your account cannot create
symbolic links (the skip reason says so). To run those 9 too, turn on
**Settings → System → For developers → Developer Mode** and run the tests
again.

Send me the last 30 lines of output, including the summary line and any
failures.

---

## Part E — Migrations on a test database

Keep this window open from Step 21 to Step 27: the `$env:` setting below
lasts only for this window, and the server in Step 27 must see it too.

### Step 21 — Point this window at the test database

Folder: **backend**.

```powershell
$env:DATABASE_PATH = "data\phase1_test.db"
```

### Step 22 — Check the migration target before migrating

```powershell
python -c "from pathlib import Path; from app.core.config import get_settings; p = Path(get_settings().database_path).resolve(); print(p); print('EXISTS - STOP' if p.exists() else 'new file')"
```

Expected: `C:\SmartHome\backend\data\phase1_test.db` and then `new file`.

- If the path is `...\smarthome.db`, Step 21 did not take effect. Stop and
  repeat Step 21 in this window.
- If it prints `EXISTS - STOP`, a test database from an earlier attempt is
  there. Stop and tell me; do not delete anything yet.

### Step 23 — Check the migration chain

```powershell
python -m alembic history
```

Expected: four revisions, newest first, ending with the head:

```
0003_retention_extensions -> 0004_audit_log_append_only (head), ...
0002_events_incidents_workflows -> 0003_retention_extensions, ...
0001_initial_identity -> 0002_events_incidents_workflows, ...
<base> -> 0001_initial_identity, ...
```

This only reads the migration files; it does not touch any database.

### Step 24 — Apply the migrations to the test database

```powershell
python -m alembic upgrade head
```

Expected: four `Running upgrade` lines in this order:
`-> 0001_initial_identity`,
`0001_initial_identity -> 0002_events_incidents_workflows`,
`0002_events_incidents_workflows -> 0003_retention_extensions`,
`0003_retention_extensions -> 0004_audit_log_append_only`.

### Step 25 — Confirm the database version

```powershell
python -m alembic current
```

Expected: `0004_audit_log_append_only (head)`.

### Step 26 — Check the audit-log protection

```powershell
python ..\scripts\stage1_audit_log_check.py data\phase1_test.db
```

Expected: PASS on every line. The script tests a **copy** of the database
and never changes the original.

---

## Part F — Start the backend and check health

### Step 27 — Start the server (same window as Step 21)

```powershell
python -m uvicorn app.main:app --port 8000 --no-server-header
```

Expected: `Uvicorn running on http://127.0.0.1:8000`. The server uses the
test database because this window still has `DATABASE_PATH` set. It listens
on this laptop only. Leave this window open; press `Ctrl+C` to stop it.

### Step 28 — Check the liveness endpoint

Open a **second** PowerShell window (the server keeps running in the first).

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health
```

Expected: `status` = `ok`, `database` = `not_checked`. This endpoint only
shows that the process answers.

### Step 29 — Check the readiness endpoint

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health/ready
```

Expected: `status` = `ok`, `database` = `ok`. This one runs a query against
the database.

The API documentation is at <http://127.0.0.1:8000/docs> while
`APP_ENV=development`.

### Step 30 — Stop the server and clear the test setting

In the **first** window press `Ctrl+C`, then:

```powershell
Remove-Item Env:DATABASE_PATH
```

The test database stays in `backend\data\phase1_test.db`. It is ignored by
Git. Keep it until I confirm Phase 1.

Phase 1 is complete only when Steps 14, 20, 24–26 and 28–29 have all given
the expected results on your laptop.

---

## Later: getting updates from GitHub

From the project folder, with no local changes:

```powershell
cd C:\SmartHome
git status
git fetch origin
git switch <branch-name>
git pull
```

Then reinstall dependencies from the lock file (Step 13) if
`requirements.lock.txt` changed.

---

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `'py' is not recognized` | Python not installed, or installed without the launcher. Reinstall Python 3.11 with "py launcher" ticked |
| `'git' is not recognized` | Git not installed, or PowerShell opened before installing. Install Git, then open a new window |
| `fatal: destination path 'C:\SmartHome' already exists` | The folder exists. Do not delete it; tell me |
| `fatal: invalid reference: phase-1-windows-setup` | The branch was merged or renamed. Run `git fetch origin` and `git branch -r`, and send me the output |
| Typing `python` opens the Microsoft Store | The venv is not active. Repeat Step 10 |
| `running scripts is disabled on this system` | See Step 10 (`Set-ExecutionPolicy -Scope Process ...`, this window only) |
| `Microsoft Visual C++ 14.0 or greater is required` during pip install | pip found no ready-made package for your Python and tried to compile. Check Step 11 shows 64-bit Python 3.11 |
| `ModuleNotFoundError: No module named 'app'` | You are not in the backend folder. `cd C:\SmartHome\backend` |
| `No config file 'alembic.ini' found` | Same: run Alembic from the backend folder |
| `ValidationError ... secret_key` | `.env` missing, `SECRET_KEY` empty or shorter than 32 characters. Redo Steps 16–18 |
| `database is locked` | Another program (a database viewer, OneDrive) has the file open. Close it |
| `[Errno 10048]` or "address already in use" | Port 8000 is taken. Use `--port 8001` (and the same port in Steps 28–29) |
| 9 tests skipped about symbolic links | Turn on Developer Mode (Step 20) and re-run |
| `UnicodeDecodeError` | Run `$env:PYTHONUTF8 = "1"` in this window, then retry, and send me the message |
| Windows Firewall asks about Python | The server only listens on 127.0.0.1; you can cancel |

## Known risks not yet tested on Windows

- The read-only database connection (for the future AI tier) opens SQLite
  with a `file:` URI. Paths with `#` or `?` in a folder name would break it;
  `C:\SmartHome` is safe. Nothing uses this connection yet.
- The symbolic-link tests depend on how Windows resolves links; they pass on
  Linux. If any of them fail on Windows, send me the output.
- Git for Windows converts line endings to CRLF on checkout. No test reads
  source files as raw bytes, so this should not matter; report any failure
  that mentions `\r`.
- `scripts\windows_stage1_check.ps1` has never been executed: PowerShell is
  not available in the Kiro sandbox.
- `requirements.txt` gives ranges, so the first install picks the newest
  versions inside them. Newer FastAPI, Starlette or Pydantic releases could
  raise deprecation warnings in our code, which `pyproject.toml` turns into
  test failures. Step 20 will show this; the lock file then fixes the
  versions.
