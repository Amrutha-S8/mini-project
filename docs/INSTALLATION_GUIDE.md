# Installation Guide

**Status:** the backend has **never been installed or started** anywhere yet.
These steps are the intended procedure; they will be corrected after the first
real run.

The virtual door is a software simulation. It does not secure a real door.

## 1. Requirements

| Item | Version |
|---|---|
| Python | 3.11 (the version all tests run on) |
| OS | Windows 10/11 for the final app (webcam); Linux works for the backend |
| Disk | ~1 GB for dependencies |
| Webcam | Built-in laptop camera (face recognition stage, not built yet) |
| Node.js | 20+ (frontend stage, not built yet) |

## 2. Windows backend setup (PowerShell)

**Use `docs/WINDOWS_SETUP_GUIDE.md` instead of this section.** It runs the
first migration on a separate test database, runs every tool as
`python -m ...` (so it does not depend on PATH), states that `.env` must
exist before the tests, and adds the read-only check scripts and
troubleshooting. This section is kept for reference.

```powershell
# 1. Unpack the project snapshot and open the backend folder
cd C:\path\to\smarthome\backend

# 2. Virtual environment
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Dependencies (needs internet on this computer)
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4. Configuration
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
#    paste the printed value into .env as SECRET_KEY=...

# 5. Database and first admin
alembic upgrade head
python -m app.cli create-admin --email you@example.com --full-name "Your Name"

# 6. Tests
python -m pytest -q -rs

# 7. Start (local machine only)
uvicorn app.main:app --port 8000 --no-server-header
```

Then open `http://127.0.0.1:8000/api/v1/health` and `/api/v1/health/ready`.
API docs are at `/docs` when `APP_ENV=development`.

## 3. Sandbox (offline) setup

The Kiro sandbox cannot reach PyPI. Use the offline wheelhouse procedure in
`OFFLINE_INSTALL.md`, then run the same steps 4–7 inside `backend/`.

## 4. Configuration reference

All settings come from environment variables or `backend/.env`. See
`backend/.env.example`. `SECRET_KEY` is required in every environment.
Login throttling settings are described in `DESIGN_DECISIONS.md` DD-05.

## 5. Not yet covered

Webcam, face model, Gemini key, WhatsApp/SMS credentials and the frontend are
added to this guide when those stages are built.
