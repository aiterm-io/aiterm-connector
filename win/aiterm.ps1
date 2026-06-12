#Requires -Version 5.1
<#
.SYNOPSIS
    AITerm Windows CLI wrapper. Mirrors the Linux `aiterm` bash CLI.

.USAGE
    aiterm status        Show install state + version + task status
    aiterm scan          Print local AI scan as JSON
    aiterm update        Re-run install.ps1 (downloads latest version)
    aiterm restart       Stop + start the Scheduled Task
    aiterm stop          Stop the connector
    aiterm start         Start the connector
    aiterm logs [N]      Tail last N lines of connector.log (default 100)
    aiterm uninstall     Remove task + install dir (asks for confirmation)
#>

param(
    [Parameter(Position = 0)]
    [ValidateSet('status','scan','update','restart','stop','start','logs','uninstall','help','--help','-h')]
    [string]$Cmd = 'status',

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = 'Stop'
$TaskName    = 'AITerm Connector'
$UserDir     = Join-Path $env:LOCALAPPDATA 'AITerm'
$SystemDir   = Join-Path $env:ProgramFiles 'AITerm'
$InstallDir  = if (Test-Path $SystemDir) { $SystemDir } elseif (Test-Path $UserDir) { $UserDir } else { $UserDir }
$ConfigPath  = Join-Path $InstallDir 'connector.json'
$Entrypoint  = Join-Path $InstallDir 'connector-win.py'
$LogPath     = Join-Path $InstallDir 'connector.log'

function Show-Help {
    @"
AITerm Windows CLI

  aiterm status        Show install + task status
  aiterm scan          Print local scan (JSON)
  aiterm update        Re-run installer from https://aiterm.io
  aiterm restart       Restart connector
  aiterm stop          Stop connector
  aiterm start         Start connector
  aiterm logs [N]      Tail N lines from connector.log
  aiterm uninstall     Remove everything
"@ | Write-Host
}

switch ($Cmd) {

    'help'    { Show-Help; return }
    '--help'  { Show-Help; return }
    '-h'      { Show-Help; return }

    'status' {
        Write-Host ''
        Write-Host '  AITerm Connector — status' -ForegroundColor White
        Write-Host ('  Install dir : {0}' -f $InstallDir)
        if (Test-Path $ConfigPath) {
            $cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
            Write-Host ('  Name        : {0}' -f $cfg.name)
            Write-Host ('  Hub URL     : {0}' -f $cfg.hub_url)
            Write-Host ('  Default CWD : {0}' -f $cfg.default_cwd)
        } else {
            Write-Host '  Config      : MISSING (not paired yet)' -ForegroundColor Yellow
        }
        if (Test-Path $Entrypoint) {
            try {
                $ver = & python $Entrypoint --version 2>&1
                Write-Host ('  Version     : {0}' -f $ver)
            } catch { Write-Host '  Version     : (python unavailable)' -ForegroundColor Yellow }
        }
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($t) {
            $info = Get-ScheduledTaskInfo -TaskName $TaskName
            Write-Host ('  Task state  : {0}' -f $t.State)
            Write-Host ('  Last run    : {0}' -f $info.LastRunTime)
            Write-Host ('  Last result : 0x{0:X}' -f $info.LastTaskResult)
        } else {
            Write-Host '  Task        : NOT REGISTERED' -ForegroundColor Yellow
        }
        Write-Host ''
    }

    'scan' {
        if (-not (Test-Path $Entrypoint)) { Write-Host 'connector-win.py missing — re-run install.ps1' -ForegroundColor Red; exit 1 }
        & python $Entrypoint --scan
    }

    'update' {
        Write-Host 'Re-running installer (updates files, keeps pairing)...' -ForegroundColor Cyan
        # Pipe the remote script into iex — same UX as Linux `aiterm update`.
        Invoke-WebRequest -UseBasicParsing -Uri 'https://aiterm.io/install.ps1' | Select-Object -ExpandProperty Content | Invoke-Expression
    }

    'restart' {
        Stop-ScheduledTask  -TaskName $TaskName -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        Start-ScheduledTask -TaskName $TaskName
        Write-Host '  ✓ Restarted' -ForegroundColor Green
    }

    'stop' {
        Stop-ScheduledTask -TaskName $TaskName
        Write-Host '  ✓ Stopped' -ForegroundColor Green
    }

    'start' {
        Start-ScheduledTask -TaskName $TaskName
        Write-Host '  ✓ Started' -ForegroundColor Green
    }

    'logs' {
        $n = if ($Rest -and $Rest[0] -match '^\d+$') { [int]$Rest[0] } else { 100 }
        if (-not (Test-Path $LogPath)) { Write-Host "No log at $LogPath" -ForegroundColor Yellow; return }
        Get-Content -Path $LogPath -Tail $n
    }

    'uninstall' {
        $confirm = Read-Host "Remove AITerm Connector completely? (yes/no)"
        if ($confirm -ne 'yes') { Write-Host 'Aborted.'; return }
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Stop-ScheduledTask    -TaskName $TaskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Host '  ✓ Scheduled Task removed' -ForegroundColor Green
        }
        if (Test-Path $InstallDir) {
            Remove-Item -Recurse -Force $InstallDir
            Write-Host ('  ✓ Removed {0}' -f $InstallDir) -ForegroundColor Green
        }
        Write-Host 'Uninstall complete.'
    }
}
