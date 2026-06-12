#Requires -Version 5.1
<#
.SYNOPSIS
    AITerm Connector installer for Windows.

.DESCRIPTION
    One-liner install:  iwr -useb https://aiterm.io/install.ps1 | iex

    Equivalent to the Linux install.sh:
      - Detects existing installation -> update mode (download + restart)
      - Fresh install -> full pairing flow
      - Ensures Python 3.10+ is present (winget bootstrap if missing)
      - Verifies SHA-256 hashes against manifest-win.json before installing
      - Registers a Scheduled Task at Logon so the connector auto-starts
#>

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# ── Constants ─────────────────────────────────────────────────────────
$ApiUrl       = 'https://www.aiterm.io'
$DownloadBase = "$ApiUrl/dl/win"
$HubUrl       = 'wss://www.aiterm.io/connector'
$TaskName     = 'AITerm Connector'
$MinBuild     = 17763   # Windows 10 1809 — ConPTY requirement

# ── Pretty printers ───────────────────────────────────────────────────
function Write-Banner {
    Write-Host ''
    Write-Host '  ┌──────────────────────────────────────┐' -ForegroundColor White
    Write-Host '  │      AITerm Connector for Windows     │' -ForegroundColor White
    Write-Host '  └──────────────────────────────────────┘' -ForegroundColor White
    Write-Host ''
}
function Write-Step([string]$m) { Write-Host "  ▸ $m" -ForegroundColor Cyan }
function Write-OK  ([string]$m) { Write-Host "  ✓ $m" -ForegroundColor Green }
function Write-Warn([string]$m) { Write-Host "  ! $m" -ForegroundColor Yellow }
function Write-Fail([string]$m) { Write-Host "  ✗ $m" -ForegroundColor Red; exit 1 }

Write-Banner

# ── Preflight: Windows version + admin status + install dir ───────────
$build = [System.Environment]::OSVersion.Version.Build
if ($build -lt $MinBuild) {
    Write-Fail "Windows 10 build $MinBuild (1809, Oct 2018) or newer required for ConPTY. This host: build $build."
}

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Mirror Linux dual-mode: admin -> system-wide ProgramFiles, user -> LOCALAPPDATA.
# Most Windows installs end up per-user; admin path is for shared boxes / RDS hosts.
if ($IsAdmin) {
    $InstallDir = Join-Path $env:ProgramFiles 'AITerm'
    Write-Step "System-wide install (admin) -> $InstallDir"
} else {
    $InstallDir = Join-Path $env:LOCALAPPDATA 'AITerm'
    Write-Step "Per-user install -> $InstallDir"
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$ConfigPath = Join-Path $InstallDir 'connector.json'
$IsRepair   = Test-Path $ConfigPath
if ($IsRepair) { Write-Step 'Existing install detected -> update mode' }

# ── Ensure Python 3.10+ is on PATH ────────────────────────────────────
function Test-Python {
    try {
        $verLine = (& python --version) 2>&1
        if ($LASTEXITCODE -ne 0) { return $null }
        if ($verLine -match 'Python (\d+)\.(\d+)') {
            $maj = [int]$Matches[1]; $min = [int]$Matches[2]
            if ($maj -gt 3 -or ($maj -eq 3 -and $min -ge 10)) { return $verLine }
        }
    } catch { }
    return $null
}

$pyVer = Test-Python
if (-not $pyVer) {
    Write-Step 'Python 3.10+ not found — bootstrapping via winget'
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Fail 'winget unavailable. Install Python 3.11 from https://python.org and re-run.'
    }
    # Silent install; suppress output but check exit code.
    & winget install --silent --accept-source-agreements --accept-package-agreements --id Python.Python.3.11 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Fail 'winget install of Python 3.11 failed. Install manually from https://python.org.'
    }
    # Refresh PATH in this session — winget update is HKLM, not auto-imported.
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
    $pyVer = Test-Python
    if (-not $pyVer) { Write-Fail 'Python install reported success but `python` still not callable. Reboot and retry.' }
}
Write-OK "Python: $pyVer"

# ── Download + verify ─────────────────────────────────────────────────
# Manifest-win.json is a flat {filename: sha256} map (no Ed25519 in M2;
# TLS + SHA-256 covers CDN-tampering. Signed-manifest verify comes in M3
# when we have a tested .NET Ed25519 path that works on PS 5.1 + 7+.)
Write-Step 'Downloading manifest...'
try {
    $manifest = Invoke-RestMethod -UseBasicParsing -Uri "$DownloadBase/manifest-win.json" -TimeoutSec 30
} catch {
    Write-Fail "Could not fetch manifest-win.json: $($_.Exception.Message)"
}
if (-not $manifest) { Write-Fail 'Empty manifest' }

function Get-VerifiedFile($name, $expectedSha) {
    $dest = Join-Path $InstallDir $name
    $tmp  = "$dest.tmp"
    if (Test-Path $tmp) { Remove-Item $tmp -Force }
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "$DownloadBase/$name" -OutFile $tmp -TimeoutSec 60
    } catch {
        Write-Fail "Download failed for ${name}: $($_.Exception.Message)"
    }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLower()
    if ($actual -ne $expectedSha.ToLower()) {
        Remove-Item $tmp -Force
        Write-Fail "$name SHA-256 mismatch (expected $expectedSha, got $actual)"
    }
    Move-Item -Force $tmp $dest
    Write-Host "    $name verified ($(([IO.FileInfo]$dest).Length) bytes)"
}

foreach ($prop in $manifest.PSObject.Properties) {
    Get-VerifiedFile -name $prop.Name -expectedSha $prop.Value
}
Write-OK 'Files installed (SHA-256 verified)'

# ── pip deps ──────────────────────────────────────────────────────────
Write-Step 'Installing Python deps (pywinpty, websockets, cryptography)...'
& python -m pip install --quiet --upgrade pip 2>$null
$reqPath = Join-Path $InstallDir 'requirements.txt'
$pipOut = & python -m pip install --quiet -r $reqPath 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host $pipOut
    Write-Fail 'pip install failed. See output above.'
}
Write-OK 'Python deps installed'

# ── Pairing flow ──────────────────────────────────────────────────────
# Only on fresh install. On update we keep the existing token.
$token = $null
if ($IsRepair) {
    try {
        $existing = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        $token = $existing.hub_token
        Write-OK "Re-using existing pairing for '$($existing.name)'"
    } catch {
        Write-Warn 'connector.json unreadable — falling back to fresh pairing'
        $IsRepair = $false
    }
}

if (-not $IsRepair) {
    Write-Step 'Registering with AITerm hub...'
    $body = @{ hostname = $env:COMPUTERNAME } | ConvertTo-Json -Compress
    try {
        $pair = Invoke-RestMethod -Method Post -Uri "$ApiUrl/api/pairing/request" -ContentType 'application/json' -Body $body -TimeoutSec 15
    } catch {
        Write-Fail "Pairing request failed: $($_.Exception.Message)"
    }
    if (-not $pair.ok) { Write-Fail "Pairing rejected: $($pair | ConvertTo-Json -Compress)" }
    $code    = $pair.code
    $pairUrl = "$ApiUrl/pair/$code"

    Write-Host ''
    Write-Host '  ┌────────────────────────────────────────────────────────────────┐' -ForegroundColor White
    Write-Host '  │                                                                │' -ForegroundColor White
    Write-Host '  │  Open this link in your browser:                              │' -ForegroundColor White
    Write-Host '  │                                                                │' -ForegroundColor White
    Write-Host "  │    $pairUrl" -ForegroundColor Yellow
    Write-Host '  │                                                                │' -ForegroundColor White
    Write-Host '  │  Sign in and confirm. This terminal is waiting.               │' -ForegroundColor White
    Write-Host '  │                                                                │' -ForegroundColor White
    Write-Host '  └────────────────────────────────────────────────────────────────┘' -ForegroundColor White
    Write-Host ''

    # Poll up to 1 hour (matches Linux behavior). 5xx swallowed -> keep polling.
    for ($i = 0; $i -lt 360; $i++) {
        Start-Sleep -Seconds 10
        try {
            $st = Invoke-RestMethod -Uri "$ApiUrl/api/pairing/status?code=$code" -TimeoutSec 10
            if ($st.status -eq 'confirmed') { $token = $st.token; break }
            if ($st.status -eq 'expired')   { Write-Fail 'Pairing code expired. Re-run installer.' }
        } catch { }
        Write-Host -NoNewline ("`r  ▸ Waiting for confirmation... ({0}/3600)" -f (($i + 1) * 10))
    }
    Write-Host ''
    if (-not $token) { Write-Fail 'Timeout. No confirmation received.' }
    Write-OK 'Pairing confirmed'
}

# ── Write connector.json (0600-equivalent ACL) ────────────────────────
$cfg = @{
    hub_url     = $HubUrl
    hub_token   = $token
    name        = $env:COMPUTERNAME
    default_cwd = $env:USERPROFILE
}
# PowerShell 5.1's Set-Content -Encoding UTF8 writes a BOM; Python's
# json.load rejects that. Use the .NET API with an explicit no-BOM
# UTF8Encoding so we're compatible with both PS 5.1 and 7+.
[System.IO.File]::WriteAllText($ConfigPath, ($cfg | ConvertTo-Json -Compress), (New-Object System.Text.UTF8Encoding($false)))

# ACL hardening: only attempted in admin mode. Disabling inheritance
# requires SeSecurityPrivilege, which non-admin users don't have — and
# they don't need it either: %LOCALAPPDATA%\AITerm\ inherits from the
# user profile, which by default is restricted to that user + SYSTEM +
# Administrators. So per-user installs already have a chmod-600-equivalent
# without touching ACLs.
if ($IsAdmin) {
    try {
        $acl = Get-Acl $ConfigPath
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators', 'FullControl', 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -Path $ConfigPath -AclObject $acl
        Write-OK 'Config saved (ACL restricted to Administrators)'
    } catch {
        Write-Warn "Config saved but ACL hardening failed: $($_.Exception.Message)"
    }
} else {
    Write-OK 'Config saved (inherits per-user ACL from %LOCALAPPDATA%)'
}

# ── Scheduled Task at Logon ───────────────────────────────────────────
# We use a Scheduled Task rather than a Windows Service because:
#   1. Doesn't require Administrator for per-user install.
#   2. The connector spawns interactive AI sessions for the logged-in user;
#      running as SYSTEM would put PTYs in the wrong session.
# Service-mode (system-wide, SYSTEM principal) is a future option for
# headless RDS hosts; not needed for M2.
Write-Step 'Registering Scheduled Task at logon...'
$pythonW = (Get-Command pythonw -ErrorAction SilentlyContinue)
if (-not $pythonW) {
    # Fall back to python.exe — a console window will flash; cosmetic only.
    $pythonW = Get-Command python
}
$entrypoint = Join-Path $InstallDir 'connector-win.py'
$action     = New-ScheduledTaskAction -Execute $pythonW.Source `
                                       -Argument ('"{0}"' -f $entrypoint) `
                                       -WorkingDirectory $InstallDir
$trigger    = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$settings   = New-ScheduledTaskSettingsSet `
                -StartWhenAvailable `
                -RestartCount 999 `
                -RestartInterval (New-TimeSpan -Minutes 1) `
                -ExecutionTimeLimit ([TimeSpan]::Zero) `
                -DisallowHardTerminate
$principal  = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask    -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-OK 'Scheduled Task registered + started'

# ── aiterm CLI on PATH ────────────────────────────────────────────────
# Drop a .cmd shim next to aiterm.ps1 so plain `aiterm status` works
# from any shell (cmd.exe, PowerShell, Terminal). Then make sure the
# install dir is on the User PATH — persistent across logons, picked up
# by every new shell. Existing shells still need a manual refresh or
# new window; we print the hint.
$cmdShim = Join-Path $InstallDir 'aiterm.cmd'
@'
@echo off
REM Thin .cmd wrapper for aiterm.ps1 so the CLI works from cmd.exe + PowerShell.
REM ExecutionPolicy Bypass: PS 5.1 default Restricted blocks script execution
REM even from a known-safe install dir; bypass is scoped to this invocation.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0aiterm.ps1" %*
'@ | Set-Content -Path $cmdShim -Encoding ASCII

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if (($userPath -split ';') -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$InstallDir", 'User')
    Write-OK "Added $InstallDir to User PATH (open a new shell to use 'aiterm')"
} else {
    Write-OK "aiterm CLI on PATH"
}
# Make it available in *this* shell too, so users can run `aiterm status`
# right after the install without opening a new window.
$env:Path = "$env:Path;$InstallDir"

# ── Smoke test: poke /api/health ──────────────────────────────────────
try {
    $h = Invoke-RestMethod "$ApiUrl/api/health" -TimeoutSec 5
    if ($h.ok) { Write-OK 'Hub reachable' }
} catch {
    Write-Warn 'Hub health probe failed (proceeding anyway)'
}

# ── Final summary ─────────────────────────────────────────────────────
Write-Host ''
if ($IsRepair) {
    Write-Host '  Update complete. The connector restarts automatically.' -ForegroundColor Green
} else {
    Write-Host '  Installation complete. The machine should appear in the dashboard.' -ForegroundColor Green
}
Write-Host ''
Write-Host "  Dashboard:    https://www.aiterm.io/app"
Write-Host "  Install dir:  $InstallDir"
Write-Host "  Logs:         $InstallDir\connector.log"
Write-Host "  Manage:       Get-ScheduledTask -TaskName '$TaskName'"
Write-Host ''
