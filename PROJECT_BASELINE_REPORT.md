# Project Baseline Report (Phase 0)

**Date:** 2026-11-16. Read-only; no application code changed.

## 1. Backup and workspace

| Check | Result |
|---|---|
| `backup/project-snapshot-20261116-155729Z.zip` SHA-256 | OK (`1f8b02b7…3360b4`) |
| All backups | 16 of 16 pass their checksums |
| Workspace vs `155729Z` | identical, 180 files |
| Environment | Kiro sandbox, `INTEGRATIONS_ONLY`; `pip download fastapi` → `No matching distribution found` (proxy 403); no webcam, no PowerShell, no Git |

## 2. Test baseline (run 2026-11-16)

| Suite | Collected | Passed | Failed | Skipped |
|---|---|---|---|---|
| Backend `python3 -m pytest -q` | 1,261 | 1,198 | 0 | 63 |
| Frontend `npm run check` | 97 | 97 | 0 | 0 |

- **Skipped:** 62 API integration tests (FastAPI stack missing); 1 runtime
  migration test (SQLAlchemy and Alembic missing).
- **Static checks:** Ruff clean, mypy clean (103 files), TypeScript, ESLint
  and Prettier clean.
- **Runtime milestones of the real application:** 0 of 10
  (`COMPLETE_TESTING_AND_VERIFICATION_REPORT.md` §9).

## 3. Inputs read

`FINAL_COMPLETE_PROJECT_AUDIT.md`, `COMPLETE_TESTING_AND_VERIFICATION_REPORT.md`,
`COMPLETE_MISSING_FEATURES_ROADMAP.md`, `API_ENDPOINT_INVENTORY.md`,
`SECURITY_FINDINGS_STATUS.md`, `FINAL_PRODUCT_GAP_ANALYSIS.md`,
`DEVELOPMENT_PROGRESS.md`, `docs/WINDOWS_SETUP_GUIDE.md`,
`docs/INSTALLATION_GUIDE.md`, `docs/DESIGN_DECISIONS.md` (DD-01–DD-12).

## 4. Security findings at baseline

S1 open (critical for real use), **S2 open, high, confirmed**, S3 open
(high, latent), S4 fixed in the reference schema but migration 0004 never
applied, S5–S14 open. Details: `SECURITY_FINDINGS_STATUS.md`.

## 5. Checklist

The development checklist is `MASTER_IMPLEMENTATION_TRACKER.md`.
