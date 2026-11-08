# Codex-SG guard layer, plan B: WFP application filters via tools\CodexWfpGuard.exe.
# Every guarded exe may only open TCP to 127.0.0.1:7899; everything else (other hosts, other
# loopback ports such as Clash Verge 7897, UDP, IPv6) is blocked in a max-weight WFP sublayer.
#   -Mode Install | Sync   (admin) rescan codex.exe copies, replace filters, run probe
#   -Mode Check            (no admin) every current codex.exe is in the snapshot AND live probe passes
#   -Mode List             (admin) print installed filters
#   -Mode Rollback         (admin) remove all filters (and legacy plan-A firewall rules)
param([ValidateSet('Install', 'Sync', 'Check', 'List', 'Rollback')][string]$Mode = 'Check')
$ErrorActionPreference = 'Stop'
$Guard = Join-Path $PSScriptRoot 'CodexWfpGuard.exe'
# Snapshot lives next to the script: in C:\Program Files\CodexSG (InstallAutoSync.ps1) it is admin-write-only.
$Snapshot = Join-Path $PSScriptRoot 'guard-snapshot.json'

function Get-Targets {
    $dirs = @("$env:LOCALAPPDATA\OpenAI\Codex\bin", "$env:APPDATA\npm\node_modules\@openai")
    # Get-AppxPackage intermittently throws UnauthorizedAccessException; retry before giving up.
    foreach ($i in 1..3) {
        try { $pkg = Get-AppxPackage -Name 'OpenAI.Codex'; if ($pkg) { $dirs += $pkg.InstallLocation }; break }
        catch { Start-Sleep -Milliseconds 500 }
    }
    @($dirs | Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
        ForEach-Object { Get-ChildItem -LiteralPath $_ -Recurse -Filter 'codex.exe' -File -ErrorAction SilentlyContinue } |
        ForEach-Object { $_.FullName } | Sort-Object -Unique)
}

function Assert-Admin {
    $p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights required: run PowerShell as administrator.'
    }
}

function Remove-LegacyRules {
    Get-NetFirewallRule -DisplayName 'CodexSG-Block-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}

if (-not (Test-Path -LiteralPath $Guard)) { throw "Missing $Guard" }

switch ($Mode) {
    { $_ -in 'Install', 'Sync' } {
        Assert-Admin
        $targets = Get-Targets
        if (-not $targets) { throw 'No codex.exe found; nothing to guard.' }
        # The guard exe guards itself too, so its probe reflects what codex.exe experiences.
        $all = @($targets) + $Guard
        & $Guard sync @all
        if ($LASTEXITCODE) { throw "CodexWfpGuard sync failed ($LASTEXITCODE)" }
        Remove-LegacyRules
        foreach ($t in $targets) { Write-Output "guarded $t" }
        New-Item -ItemType Directory -Force (Split-Path $Snapshot) | Out-Null
        $snap = [pscustomobject]@{ installed = (Get-Date).ToString('s'); paths = $all }
        [IO.File]::WriteAllText($Snapshot, (ConvertTo-Json $snap -Depth 3), [Text.UTF8Encoding]::new($false))
        & $Guard probe
        if ($LASTEXITCODE) { Write-Output 'WARNING: filters installed but probe failed (another WFP filter overrides them).'; exit 2 }
        Write-Output "guard active: $($targets.Count) codex.exe + probe"
    }
    'Check' {
        if (-not (Test-Path -LiteralPath $Snapshot)) { Write-Output 'not installed: run -Mode Install as administrator.'; exit 1 }
        $paths = @((Get-Content -LiteralPath $Snapshot -Raw | ConvertFrom-Json).paths)
        $missing = @(Get-Targets | Where-Object { $paths -notcontains $_ })
        foreach ($m in $missing) { Write-Output "unguarded (new/updated install?): $m" }
        if ($missing) { Write-Output 'run -Mode Sync as administrator.'; exit 1 }
        $probe = & $Guard probe
        if ($LASTEXITCODE) { $probe; Write-Output 'probe failed: filters are not effective.'; exit 1 }
        Write-Output "active: $($paths.Count - 1) codex.exe guarded, probe pass"
        exit 0
    }
    'List' {
        Assert-Admin
        & $Guard list
    }
    'Rollback' {
        Assert-Admin
        & $Guard remove-all
        if ($LASTEXITCODE) { throw "CodexWfpGuard remove-all failed ($LASTEXITCODE)" }
        Remove-LegacyRules
        Remove-Item -LiteralPath $Snapshot -ErrorAction SilentlyContinue
        Write-Output 'guard removed; direct outbound restored.'
    }
}
