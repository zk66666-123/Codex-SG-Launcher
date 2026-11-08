# One-time admin setup so Codex updates are re-guarded without a UAC prompt.
# Copies the guard (ManageCodexGuard.ps1 + CodexWfpGuard.exe) to C:\Program Files\CodexSG (admin-write-only,
# so nothing non-elevated can swap the script the elevated task runs) and registers task CodexSG-GuardSync
# (runs -Mode Sync with highest privileges; this user may start it, not modify it).
# codex_env.py starts that task when Check reports an unguarded codex.exe, then re-checks.
#   InstallAutoSync.ps1              install / update (rerun after editing the guard files in tools\)
#   InstallAutoSync.ps1 -Uninstall   remove task + folder (then run tools\ManageCodexGuard.ps1 -Mode Sync)
param([switch]$Uninstall)
$ErrorActionPreference = 'Stop'
$p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run PowerShell as administrator.' }

$Dest = Join-Path $env:ProgramFiles 'CodexSG'
$Task = 'CodexSG-GuardSync'

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Dest -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "removed $Task and $Dest; now run tools\ManageCodexGuard.ps1 -Mode Sync"
    return
}

New-Item -ItemType Directory -Force $Dest | Out-Null
foreach ($f in 'ManageCodexGuard.ps1', 'CodexWfpGuard.exe') { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $f) $Dest -Force }

$user = [Security.Principal.WindowsIdentity]::GetCurrent()
$script = Join-Path $Dest 'ManageCodexGuard.ps1'
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$script`" -Mode Sync"
$principal = New-ScheduledTaskPrincipal -UserId $user.Name -LogonType Interactive -RunLevel Highest
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user.Name
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $Task -Action $action -Principal $principal -Trigger $trigger -Settings $settings -Force | Out-Null

# Admins/SYSTEM full control; this user read + run only (cannot change the elevated action).
$svc = New-Object -ComObject Schedule.Service; $svc.Connect()
$svc.GetFolder('\').GetTask($Task).SetSecurityDescriptor("D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;$($user.User.Value))", 0)

& $script -Mode Sync
if ($LASTEXITCODE) { throw "Sync failed ($LASTEXITCODE)" }
Write-Output "auto-sync installed: $Task -> $script"
