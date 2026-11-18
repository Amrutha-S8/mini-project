<#
.SYNOPSIS
  Stage 1 readiness check for the Smart Home Security backend on Windows.

.DESCRIPTION
  Read-only. Reports PASS, FAIL or BLOCKED for each check. It never installs
  packages, never changes execution policy or other security settings, never
  creates, deletes or overwrites files, and never prints SECRET_KEY.

  BLOCKED means a check could not run because an earlier step is missing
  (for example, no virtual environment yet). The message says what to do.

  Run it from the project folder (the one that contains backend\ and scripts\):

      powershell -ExecutionPolicy Bypass -File .\scripts\windows_stage1_check.ps1

  "-ExecutionPolicy Bypass" applies to this one command only.

  Add -CheckServer to also query the health endpoints. That needs the backend
  running in another PowerShell window (see docs\WINDOWS_SETUP_GUIDE.md).

  Exit code: 0 if nothing FAILED, 1 otherwise.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$CheckServer,
    [string]$ServerUrl = "http://127.0.0.1:8000"
)

# Windows PowerShell 5.1 turns stderr from native commands into errors when
# redirected with 2>&1; with "Stop" that would abort the whole check. Each
# check below handles failures itself.
$ErrorActionPreference = "Continue"
$script:Results = @()

function Add-Result([string]$Status, [string]$Name, [string]$Detail) {
    $script:Results += [pscustomobject]@{ Status = $Status; Check = $Name; Detail = $Detail }
    $colour = switch ($Status) { "PASS" { "Green" } "FAIL" { "Red" } default { "Yellow" } }
    Write-Host ("{0,-8} {1}" -f $Status, $Name) -ForegroundColor $colour
    if ($Detail) { Write-Host ("         {0}" -f $Detail) }
}

$Backend = Join-Path $ProjectRoot "backend"
$VenvPython = Join-Path $Backend ".venv\Scripts\python.exe"

Write-Host ""
Write-Host "Smart Home Security - Stage 1 check (read-only)" -ForegroundColor Cyan
Write-Host "Project folder: $ProjectRoot"
Write-Host ""

# --- 1. Project structure -----------------------------------------------------
$required = @(
    "backend\app\main.py",
    "backend\alembic.ini",
    "backend\alembic\env.py",
    "backend\alembic\versions\0001_initial_identity.py",
    "backend\alembic\versions\0002_events_incidents_workflows.py",
    "backend\alembic\versions\0003_retention_extensions.py",
    "backend\alembic\versions\0004_audit_log_append_only.py",
    "backend\requirements.txt",
    "backend\pyproject.toml",
    "backend\.env.example",
    "backend\tests\conftest.py",
    "scripts\stage1_audit_log_check.py"
)
$missing = @($required | Where-Object { -not (Test-Path (Join-Path $ProjectRoot $_)) })
if ($missing.Count -eq 0) {
    Add-Result "PASS" "Project structure" "all $($required.Count) expected files found"
} else {
    Add-Result "FAIL" "Project structure" ("missing: " + ($missing -join ", ") + ". Extract the whole backup into one folder and run this script from that folder.")
}

# --- 2. Python available on this computer ---------------------------------------
$pyLauncher = Get-Command py -ErrorAction SilentlyContinue
if ($pyLauncher) {
    $out = & py -3.11 --version 2>&1
    if ($LASTEXITCODE -eq 0 -and "$out" -match "Python 3\.11\.") {
        Add-Result "PASS" "Python 3.11 installed" "$out"
    } else {
        $list = (& py --list 2>&1) -join "; "
        Add-Result "FAIL" "Python 3.11 installed" "py -3.11 did not run. Installed versions: $list. Install Python 3.11 from python.org."
    }
} else {
    Add-Result "FAIL" "Python 3.11 installed" "the 'py' launcher was not found. Install Python 3.11 from python.org (keep 'py launcher' ticked)."
}

# --- 3. Virtual environment -------------------------------------------------------
$haveVenv = Test-Path $VenvPython
if ($haveVenv) {
    $ver = & $VenvPython -c "import sys; print('.'.join(map(str, sys.version_info[:3])))" 2>&1
    if ("$ver" -match "^3\.11\.") {
        Add-Result "PASS" "Virtual environment (backend\.venv)" "Python $ver"
    } else {
        Add-Result "FAIL" "Virtual environment (backend\.venv)" "uses Python $ver; the project is tested on 3.11. Recreate it with: py -3.11 -m venv .venv"
    }
    if ($env:VIRTUAL_ENV -and ((Resolve-Path $env:VIRTUAL_ENV).Path -eq (Resolve-Path (Join-Path $Backend ".venv")).Path)) {
        Add-Result "PASS" "Virtual environment active in this window" ""
    } else {
        Add-Result "BLOCKED" "Virtual environment active in this window" "not active (this script does not need it). Before running project commands: cd backend; .\.venv\Scripts\Activate.ps1"
    }
} else {
    Add-Result "BLOCKED" "Virtual environment (backend\.venv)" "not created yet. In backend\ run: py -3.11 -m venv .venv"
}

# --- 4. Required packages -----------------------------------------------------------
if ($haveVenv) {
    # name to import, distribution name for the version
    $packages = @(
        @("fastapi", "fastapi"), @("uvicorn", "uvicorn"), @("sqlalchemy", "SQLAlchemy"),
        @("alembic", "alembic"), @("pydantic", "pydantic"), @("pydantic_settings", "pydantic-settings"),
        @("email_validator", "email-validator"), @("argon2", "argon2-cffi"), @("jwt", "PyJWT"),
        @("pytest", "pytest"), @("httpx", "httpx")
    )
    $code = @"
import importlib, importlib.metadata as md, sys
bad = []
for mod, dist in [$( ($packages | ForEach-Object { "('$($_[0])', '$($_[1])')" }) -join ', ' )]:
    try:
        importlib.import_module(mod)
        print('OK', dist, md.version(dist))
    except Exception as exc:
        print('MISSING', dist, type(exc).__name__)
        bad.append(dist)
sys.exit(1 if bad else 0)
"@
    # Run from a neutral folder so the local backend\alembic folder is not imported.
    Push-Location $env:TEMP
    try { $lines = & $VenvPython -B -c $code 2>&1 } finally { Pop-Location }
    $ok = ($LASTEXITCODE -eq 0)
    $summary = (($lines | ForEach-Object { "$_" }) -join "; ")
    if ($ok) { Add-Result "PASS" "Required packages import" $summary }
    else { Add-Result "FAIL" "Required packages import" "$summary. In backend\ run: python -m pip install -r requirements.txt" }

    $check = & $VenvPython -m pip check 2>&1
    if ($LASTEXITCODE -eq 0) { Add-Result "PASS" "pip check (no conflicting versions)" "$check" }
    else { Add-Result "FAIL" "pip check (no conflicting versions)" (($check | ForEach-Object { "$_" }) -join "; ") }
} else {
    Add-Result "BLOCKED" "Required packages import" "needs backend\.venv first"
}

# --- 5. Environment configuration (.env) ---------------------------------------------
$envFile = Join-Path $Backend ".env"
$dbSetting = "./data/smarthome.db"
if (Test-Path $envFile) {
    $values = @{}
    foreach ($line in Get-Content $envFile) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
            $v = $Matches[2].Trim()
            if ($v -notmatch '^["'']' ) { $v = ($v -replace '\s+#.*$', '').Trim() }
            $values[$Matches[1].ToUpper()] = $v.Trim('"').Trim("'")
        }
    }
    $secret = $values["SECRET_KEY"]
    if (-not $secret) {
        Add-Result "FAIL" "SECRET_KEY set in backend\.env" "empty. Generate one (see the guide, step 7) and paste it after SECRET_KEY="
    } elseif ($secret.Length -lt 32) {
        Add-Result "FAIL" "SECRET_KEY set in backend\.env" "too short ($($secret.Length) characters; at least 32 are required). The value is not shown."
    } else {
        Add-Result "PASS" "SECRET_KEY set in backend\.env" "$($secret.Length) characters (value not shown)"
    }
    if ($values["APP_ENV"]) { Add-Result "PASS" "APP_ENV" $values["APP_ENV"] }
    if ($values["DATABASE_PATH"]) { $dbSetting = $values["DATABASE_PATH"] }
    if ($env:DATABASE_PATH) { $dbSetting = $env:DATABASE_PATH; Write-Host "         (DATABASE_PATH is overridden in this window: $dbSetting)" }
    if ($values["AI_ENABLED"] -and $values["AI_ENABLED"].ToLower() -ne "false") {
        Add-Result "FAIL" "AI kill switch" "AI_ENABLED is '$($values["AI_ENABLED"])'; it must stay false for Stage 1"
    } else {
        Add-Result "PASS" "AI kill switch" "AI_ENABLED is off"
    }
} else {
    Add-Result "BLOCKED" "backend\.env exists" "not created yet. In backend\ run: Copy-Item .env.example .env"
}

# --- 6. Database file ---------------------------------------------------------------------
$dbPath = if ([System.IO.Path]::IsPathRooted($dbSetting)) { $dbSetting } else { Join-Path $Backend $dbSetting }
if (Test-Path $dbPath) {
    $size = (Get-Item $dbPath).Length
    Add-Result "PASS" "Database file" "$dbPath ($size bytes)"
} else {
    Add-Result "BLOCKED" "Database file" "$dbPath does not exist yet. It is created by: python -m alembic upgrade head"
}

# --- 7. Alembic configuration ---------------------------------------------------------------
$ini = Join-Path $Backend "alembic.ini"
if (Test-Path $ini) {
    $iniText = Get-Content $ini -Raw
    if ($iniText -match '(?m)^script_location\s*=\s*alembic\s*$') {
        Add-Result "PASS" "alembic.ini script_location" "alembic (so Alembic must be run from backend\)"
    } else {
        Add-Result "FAIL" "alembic.ini script_location" "unexpected value; the project expects 'script_location = alembic'"
    }
    $chain = @{}
    foreach ($f in Get-ChildItem (Join-Path $Backend "alembic\versions") -Filter "*.py") {
        $t = Get-Content $f.FullName -Raw
        if ($t -match 'revision: str = "([^"]+)"') { $rev = $Matches[1] } else { continue }
        if ($t -match 'down_revision: str \| None = "([^"]+)"') { $down = $Matches[1] } else { $down = "" }
        $chain[$down] = $rev
    }
    $order = @(); $cur = ""
    while ($chain.ContainsKey($cur) -and $order.Count -lt 20) { $cur = $chain[$cur]; $order += $cur }
    $expected = @("0001_initial_identity", "0002_events_incidents_workflows", "0003_retention_extensions", "0004_audit_log_append_only")
    if (($order -join ",") -eq ($expected -join ",")) {
        Add-Result "PASS" "Migration chain 0001 -> 0004" ($order -join " -> ")
    } else {
        Add-Result "FAIL" "Migration chain 0001 -> 0004" ("found: " + ($order -join " -> "))
    }
} else {
    Add-Result "FAIL" "alembic.ini" "not found in backend\"
}
if ($haveVenv) {
    Push-Location $env:TEMP
    try { $a = & $VenvPython -m alembic --version 2>&1 } finally { Pop-Location }
    if ($LASTEXITCODE -eq 0) { Add-Result "PASS" "Alembic command" "$a (run as: python -m alembic ...)" }
    else { Add-Result "FAIL" "Alembic command" "$a" }
} else {
    Add-Result "BLOCKED" "Alembic command" "needs backend\.venv first"
}

# --- 8. Test command --------------------------------------------------------------------------
if ($haveVenv) {
    Push-Location $env:TEMP
    try { $p = & $VenvPython -m pytest --version 2>&1 } finally { Pop-Location }
    if ($LASTEXITCODE -eq 0) { Add-Result "PASS" "pytest available" (($p | ForEach-Object { "$_" }) -join " ") }
    else { Add-Result "FAIL" "pytest available" (($p | ForEach-Object { "$_" }) -join " ") }
} else {
    Add-Result "BLOCKED" "pytest available" "needs backend\.venv first"
}

# --- 9. Running server (optional) ----------------------------------------------------------------
if ($CheckServer) {
    foreach ($ep in @("/api/v1/health", "/api/v1/health/ready")) {
        try {
            $r = Invoke-RestMethod -Uri ($ServerUrl + $ep) -TimeoutSec 5
            $detail = "status=$($r.status) database=$($r.database)"
            if ($r.status -eq "ok") { Add-Result "PASS" "GET $ep" $detail }
            else { Add-Result "FAIL" "GET $ep" $detail }
        } catch {
            Add-Result "BLOCKED" "GET $ep" "no answer from $ServerUrl. Start the backend in another window first (guide, step 12)."
        }
    }
} else {
    Add-Result "BLOCKED" "Health endpoints" "not checked. Needs the backend running; then re-run with -CheckServer"
}

# --- summary ------------------------------------------------------------------------------------
$pass = @($script:Results | Where-Object Status -eq "PASS").Count
$fail = @($script:Results | Where-Object Status -eq "FAIL").Count
$blocked = @($script:Results | Where-Object Status -eq "BLOCKED").Count
Write-Host ""
Write-Host "Summary: $pass PASS, $fail FAIL, $blocked BLOCKED" -ForegroundColor Cyan
Write-Host "Nothing was installed, changed or deleted."
if ($fail -gt 0) { exit 1 } else { exit 0 }
