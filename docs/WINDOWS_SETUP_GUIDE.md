# Windows Setup Guide — Stage 1 (backend only)

This guide gets the existing backend running on your Windows laptop. It does
**not** cover the webcam, face recognition, the frontend or AI; those come
after Stage 1 is verified.

**Status of these instructions:** checked against the project files on
2026-11-16 (folder layout, `requirements.txt`, `alembic.ini`,
`alembic/env.py`, `app/core/config.py`, `.env.example`, `pyproject.toml`).
They have **not been run on Windows yet**, and the backend has never been
started anywhere. Please run them one step at a time and send me the output.

Every command is for **PowerShell**. Lines starting with `#` are comments; do
not type them.

---

## Overview: which folder each command runs in

| Folder | Example path | Used for |
|---|---|---|
| Project folder | `C:\SmartHome` | the check script |
| Backend folder | `C:\SmartHome\backend` | everything else: venv, pip, tests, Alembic, the server |

Alembic and the server **must** run from the backend folder, because
`alembic.ini`, the `alembic\` migrations folder, `.env` and the `app` package
are all found relative to it.

---

## Step 1 — Check Python 3.11

The project is written and tested for **Python 3.11** (`pyproject.toml`:
`requires-python = ">=3.11"`; every test so far ran on 3.11.15). Newer
versions are untested.

```powershell
py -3.11 --version
```

Expected: `Python 3.11.x`.

If you see `No suitable Python runtime found` or `'py' is not recognized`:
install Python 3.11 (64-bit) from <https://www.python.org/downloads/windows/>.
The last 3.11 release with a Windows installer is **3.11.9**. In the
installer tick **"Add python.exe to PATH"** and keep **"py launcher"**
ticked. Then close and reopen PowerShell and run the command again.

Git is **not** needed: the project comes as a zip backup, not a Git
repository.

## Step 2 — Extract the project

1. Download the newest `backup/project-snapshot-*.zip` from the Kiro file
   explorer (the one named in my last message). Older snapshots, including
   `20261116-150957Z`, do not contain the `scripts` folder or this guide.
2. Right-click the zip → **Extract All…** → choose `C:\SmartHome` → Extract.
3. Open `C:\SmartHome`. You should see `backend`, `docs`, `frontend`,
   `scripts`, `README.md`.

Use a short path without OneDrive (OneDrive can lock the SQLite file while
syncing).

## Step 3 — Open PowerShell in the project folder

In File Explorer, open `C:\SmartHome`, click the address bar, type
`powershell` and press Enter. Or open PowerShell and type:

```powershell
cd C:\SmartHome
```

## Step 4 — Run the check script (first time)

Folder: **project folder** (`C:\SmartHome`).

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows_stage1_check.ps1
```

It only reads; it changes nothing. `-ExecutionPolicy Bypass` applies to this
one command only. On a fresh setup you should see PASS for the project
structure and Python, and BLOCKED for the steps not done yet.

## Step 5 — Create the virtual environment

Folder: **backend** (`C:\SmartHome\backend`).

```powershell
cd C:\SmartHome\backend
py -3.11 -m venv .venv
```

## Step 6 — Activate it

```powershell
.\.venv\Scripts\Activate.ps1
```

The prompt now starts with `(.venv)`. If you get *"running scripts is
disabled on this system"*, allow scripts **for this window only**, then
activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

Activate again every time you open a new PowerShell window.

## Step 7 — Install the backend packages

Folder: **backend**, with `(.venv)` active.

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip check
python -m pip list
```

`requirements.txt` gives version ranges (for example `fastapi>=0.115,<1.0`,
`sqlalchemy>=2.0,<3.0`, `pydantic>=2.7,<3.0`); pip picks the newest version
inside each range. `pip check` should say `No broken requirements found.`
Send me the `pip list` output so the exact installed versions are recorded.

## Step 8 — Create the configuration file

Folder: **backend**.

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
notepad .env
```

In Notepad, find the line `SECRET_KEY=` and paste the printed value right
after the `=` (no spaces, no quotes). Save and close.

- **Never share this value**, not even with me.
- `.env` is required before tests, migrations and the server: the
  application and its tests refuse to start without a strong `SECRET_KEY`.
- Leave `AI_ENABLED=false` and `GEMINI_ENABLED=false`.

## Step 9 — Run the check script again

Folder: **backend** (the script path is relative to it here).

```powershell
powershell -ExecutionPolicy Bypass -File ..\scripts\windows_stage1_check.ps1
```

Every check should now be PASS except "Database file" and "Health
endpoints" (BLOCKED, done in later steps).

## Step 10 — Run the backend tests

Folder: **backend**, `(.venv)` active.

```powershell
python -m pytest -q -rs
```

There are **1,261 tests**. Expected on Windows: **1,261 passed, 0 skipped**,
or 1,252 passed and 9 skipped if your account cannot create symbolic links
(the skip message says so). To run those 9 too, turn on
**Settings → System → For developers → Developer Mode** and run the tests
again. Send me the last 30 lines of output, including any failures.

## Step 11 — Apply the migrations to a fresh test database

Folder: **backend**. This uses a separate test file, so your real database
is not touched. The `$env:` setting lasts only for this window.

```powershell
$env:DATABASE_PATH = "data\stage1_test.db"
python -m alembic upgrade head
python -m alembic current
python ..\scripts\stage1_audit_log_check.py data\stage1_test.db
```

Expected:

- `upgrade head` prints four `Running upgrade` lines, in this order:
  `-> 0001_initial_identity`, `0001_initial_identity -> 0002_events_incidents_workflows`,
  `0002_... -> 0003_retention_extensions`, `0003_... -> 0004_audit_log_append_only`.
- `current` prints `0004_audit_log_append_only (head)`.
- The audit-log check prints PASS for every line. It tests a **copy** of the
  database and never changes the original.

Then go back to the normal database setting:

```powershell
Remove-Item Env:DATABASE_PATH
```

## Step 12 — Create the real database and the first admin

Folder: **backend**.

```powershell
python -m alembic upgrade head
python -m app.cli create-admin --email you@example.com --full-name "Your Name"
```

This creates `backend\data\smarthome.db`. The password prompt does not show
what you type; use at least 12 characters, not a common password.

## Step 13 — Start the server

Folder: **backend**, `(.venv)` active.

```powershell
python -m uvicorn app.main:app --port 8000 --no-server-header
```

Expected: `Uvicorn running on http://127.0.0.1:8000`. Leave this window
open; press `Ctrl+C` to stop the server. It listens on this laptop only.

## Step 14 — Check the health endpoints

Open a **second** PowerShell window (the server keeps running in the first).

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health/ready
```

Expected: `status ok, database not_checked`, then `status ok, database ok`.
Or run the check script with the server check:

```powershell
cd C:\SmartHome
powershell -ExecutionPolicy Bypass -File .\scripts\windows_stage1_check.ps1 -CheckServer
```

The API documentation is at <http://127.0.0.1:8000/docs> while
`APP_ENV=development`.

After Step 14, send me the results. The live checks of registration, login,
refresh, logout and roles against the running server come next; I will give
you those commands once these steps pass.

---

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `'py' is not recognized` | Python not installed, or installed without the launcher. Reinstall Python 3.11 with "py launcher" ticked |
| Typing `python` opens the Microsoft Store | Windows app alias. Use `py -3.11`, or turn off the alias in Settings → Apps → Advanced app settings → App execution aliases |
| `running scripts is disabled on this system` | See Step 6 (`Set-ExecutionPolicy -Scope Process ...`, this window only) |
| `Microsoft Visual C++ 14.0 or greater is required` during pip install | pip found no ready-made package for your Python and tried to compile. Make sure the venv uses 64-bit Python 3.11 |
| `ModuleNotFoundError: No module named 'app'` | You are not in the backend folder. `cd C:\SmartHome\backend` |
| `No config file 'alembic.ini' found` | Same: run Alembic from the backend folder |
| `ValidationError ... secret_key` | `.env` missing, `SECRET_KEY` empty or shorter than 32 characters. Redo Step 8 |
| Tests error with a settings or SECRET_KEY message | Same cause; the tests also read `backend\.env` |
| `database is locked` | Another program (a database viewer, OneDrive) has the file open. Close it |
| `[Errno 10048]` or "address already in use" | Port 8000 is taken. Use `--port 8001` (and the same port in Step 14) |
| 9 tests skipped about symbolic links | Turn on Developer Mode (Step 10) and re-run |
| `UnicodeDecodeError` | Run `$env:PYTHONUTF8 = "1"` in this window, then retry, and send me the message |
| Windows Firewall asks about Python | The server only listens on 127.0.0.1; you can cancel |

## Known risks I could not test without Windows

- The read-only database connection (for the future AI tier) opens SQLite
  with a `file:` URI. Paths with `#` or `?` in a folder name would break it;
  a path like `C:\SmartHome` is safe. Nothing uses this connection yet.
- The symbolic-link tests depend on how Windows resolves links; they pass
  on Linux. If any of them fail on Windows, send me the output.
- `scripts\windows_stage1_check.ps1` has never been executed: PowerShell is
  not available in the Kiro sandbox.
