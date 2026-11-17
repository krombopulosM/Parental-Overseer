# Run Parental Gateway on Windows at start-up, as SYSTEM, restarting if it stops.
#
#   Right-click PowerShell > Run as administrator, then from the program's folder:
#     powershell -ExecutionPolicy Bypass -File .\deploy\windows-install.ps1
#   To remove:
#     powershell -ExecutionPolicy Bypass -File .\deploy\windows-install.ps1 -Uninstall
#
# Choose "Block" in the dashboard's setup wizard (or set `mode: gateway` in
# config.local.yaml) for it to block rather than only watch. Give children a
# standard (non-administrator) Windows account: they can't stop a SYSTEM task.
param([switch]$Uninstall)
$ErrorActionPreference = "Stop"
$TaskName = "Parental Gateway"

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this from an Administrator PowerShell."
    exit 1
}

if ($Uninstall) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Removed. Parental Gateway no longer starts with Windows."
    exit 0
}

$Root = Split-Path -Parent $PSScriptRoot
$Python = (Get-Command python -ErrorAction Stop).Source
Write-Host "==> Installing Python packages with $Python"
& $Python -m pip install --disable-pip-version-check -q -r "$Root\requirements.txt" -r "$Root\requirements-windows.txt"
if ($LASTEXITCODE -ne 0) { Write-Error "pip install failed"; exit 1 }

Write-Host "==> Checking this copy works"
& $Python "$Root\run.py" --selftest
if ($LASTEXITCODE -ne 0) { Write-Error "Self-test failed - see above"; exit 1 }

Write-Host "==> Starting with Windows"
$Action    = New-ScheduledTaskAction -Execute $Python -Argument "`"$Root\run.py`"" -WorkingDirectory $Root
$Trigger   = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
             -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) `
             -StartWhenAvailable
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal `
    -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "Done. Parental Gateway starts with Windows and restarts if it stops."
Write-Host "Dashboard: http://127.0.0.1:8080   Logs: $Root\logs\gateway.log"
