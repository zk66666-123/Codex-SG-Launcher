param(
    [ValidateSet('Install','Sync','Prepare','Status','Rollback','Inventory')][string]$Mode='Status',
    [string]$Target
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
$InstallRoot=Join-Path $env:ProgramFiles 'Claude7898Guard'
$InstalledScript=Join-Path $InstallRoot 'ManageClaudeGuard.ps1'
$Helper=Join-Path $InstallRoot 'ClaudeNetworkGuard.exe'
$StateFile=Join-Path $InstallRoot 'state.json'
$BackupFile=Join-Path $InstallRoot 'before-install.json'
$TaskName='Claude7898Guard-Maintenance'
$Family='Claude_pzs8sxrjxfjjc'
$Policy='HKLM:\SOFTWARE\Policies\Claude'
$PolicyName='disableAutoUpdates'
$PowerShell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Require-Admin {
    $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator authorization is required.'}
}
function Write-Json($Path,$Value){
    $tmp=$Path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    [IO.File]::WriteAllText($tmp,($Value | ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($false)))
    if(Test-Path -LiteralPath $Path){[IO.File]::Replace($tmp,$Path,[NullString]::Value)}else{[IO.File]::Move($tmp,$Path)}
}
function Read-State {
    if(-not(Test-Path -LiteralPath $StateFile)){throw 'No installed protection state. Run the protection installer.'}
    Get-Content -LiteralPath $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json
}
function Assert-NoReparse([string]$Path){
    $item=Get-Item -LiteralPath $Path -Force
    while($null -ne $item){
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw ('Reparse point is not supported: '+$item.FullName)}
        if($item -is [IO.FileInfo]){$item=$item.Directory}else{$item=$item.Parent}
    }
}
function Get-Components {
    # Query Windows package registration, never user-supplied paths or process names.
    $packages=@(Get-AppxPackage -AllUsers -Name Claude | Where-Object { $_.PackageFamilyName -ceq $Family -and -not $_.IsDevelopmentMode } | Sort-Object InstallLocation -Unique)
    if($packages.Count -eq 0){throw 'No registered official Claude package found.'}
    $result=@()
    foreach($pkg in $packages){
        $root=[IO.Path]::GetFullPath($pkg.InstallLocation)
        if($root -notmatch '^[A-Za-z]:\\(?:Program Files\\)?WindowsApps\\Claude_[^\\]+__pzs8sxrjxfjjc$'){throw 'Unrecognized Claude package location; refusing automatic scope expansion.'}
        $app=Join-Path $root 'app'; Assert-NoReparse $app
        $pending=New-Object 'Collections.Generic.Queue[string]'; $pending.Enqueue($app)
        $files=@()
        while($pending.Count){
            $dir=$pending.Dequeue()
            foreach($item in Get-ChildItem -LiteralPath $dir -Force){
                if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Package contains a reparse point; manual inspection required.'}
                if($item.PSIsContainer){$pending.Enqueue($item.FullName)}elseif($item.Extension -ieq '.exe'){$files+=$item}
            }
        }
        if(-not($files | Where-Object {$_.FullName -ieq (Join-Path $app 'claude.exe')})){throw 'Claude main executable missing.'}
        foreach($file in $files){
            $sig=Get-AuthenticodeSignature -LiteralPath $file.FullName
            if($sig.Status -ne 'Valid' -or $null -eq $sig.SignerCertificate -or $sig.SignerCertificate.Subject -cne $pkg.Publisher){throw ('Component signature not validated against package publisher: '+$file.Name)}
            $result += [pscustomobject]@{path=$file.FullName;sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash;version=$pkg.Version.ToString();family=$Family}
        }
    }
    @($result | Sort-Object path -Unique)
}
function Invoke-HelperProcess([string[]]$Arguments){
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$Helper
    $info.Arguments=($Arguments | ForEach-Object {'"'+$_+'"'}) -join ' '
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::Start($info)
    try{
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(45000)){$process.Kill();throw 'Own network helper timed out.'}
        @{exitCode=$process.ExitCode;text=($stdout.Result+$stderr.Result)}
    }finally{$process.Dispose()}
}
function Invoke-Guard([string[]]$Arguments){
    $result=Invoke-HelperProcess $Arguments
    if($result.exitCode -ne 0){throw ('Network filter operation failed: '+$result.text)}
    @($result.text -split '\r?\n' | Where-Object {$_})
}
function Get-FilterPaths {
    @(Invoke-Guard @('status') | ForEach-Object {if($_ -match '^\d+\t(.+)$'){$Matches[1]}} | Sort-Object -Unique)
}
function Get-PolicyValue {
    if(Test-Path -LiteralPath $Policy){$key=Get-Item -LiteralPath $Policy; if($key.GetValueNames() -contains $PolicyName){return $key.GetValue($PolicyName)}}
    return $null
}
function Policy-Backup {
    $keyExists=Test-Path -LiteralPath $Policy
    $exists=$false;$value=$null;$kind=$null
    if($keyExists){$key=Get-Item -LiteralPath $Policy;$exists=$key.GetValueNames() -contains $PolicyName;if($exists){$value=$key.GetValue($PolicyName);$kind=$key.GetValueKind($PolicyName).ToString()}}
    @{keyExisted=$keyExists;valueExisted=$exists;value=$value;kind=$kind}
}
function Sync-Protection {
    Require-Admin
    $started=[DateTime]::UtcNow
    $components=@(Get-Components)
    # Update policy is informational only. Network protection must work with updates enabled.
    $repair=@()
    foreach($item in $components){if((Invoke-HelperProcess @('verify',$item.path)).exitCode -ne 0){$repair+=$item.path}}
    if($repair.Count){Invoke-Guard (@('add')+$repair) | Out-Null}
    Invoke-Guard (@('verify')+@($components.path)) | Out-Null
    # Re-read exact inventory after mutation. Do not launch across a concurrent package update.
    $after=@(Get-Components)
    $a=($components | ForEach-Object {$_.path+'|'+$_.sha256}) -join "`n"
    $b=($after | ForEach-Object {$_.path+'|'+$_.sha256}) -join "`n"
    if($a -cne $b){throw 'Claude package changed while synchronizing; launch stopped. Retry after update completes.'}
    $state=@{schema=2;active=$true;success=$true;startedUtc=$started.ToString('o');completedUtc=[DateTime]::UtcNow.ToString('o');allowed='TCP 127.0.0.1:7898';components=$after;updatePolicy=(Get-PolicyValue);updatePolicyManaged=$false;repairedPaths=$repair;scope='Official Windows package EXEs only. External interpreters and VM guest traffic are not covered.'}
    Write-Json $StateFile $state
    Write-Output ('PASS: '+$after.Count+' signed Claude components verified; '+$repair.Count+' paths repaired; update settings preserved.')
}
function Prepare-Launch {
    if(-not $Target){throw 'A Claude executable path is required.'}
    $state=Read-State
    if(-not $state.active){Write-Output 'Protection explicitly removed. Using the original proxy-only launcher.';return}
    $requestTime=[DateTime]::UtcNow
    $service=New-Object -ComObject 'Schedule.Service';$service.Connect()
    $task=$service.GetFolder('\').GetTask($TaskName)
    $null=$task.Run($null)
    $limit=[DateTime]::UtcNow.AddSeconds(100)
    $finished=$false
    do{
        Start-Sleep -Milliseconds 250
        $task=$service.GetFolder('\').GetTask($TaskName)
        if($task.State -notin @(2,4) -and $task.LastRunTime.ToUniversalTime() -ge $requestTime.AddSeconds(-1)){
            if($task.LastTaskResult -eq -1073741510){throw 'Protection maintenance was interrupted (0xC000013A). Claude was not launched; existing network restrictions remain in place. Please retry the dedicated launcher.'}
            if($task.LastTaskResult -ne 0){throw ('Protection maintenance failed with code '+$task.LastTaskResult+'; Claude was not launched.')}
            $fresh=Read-State
            $finished=[DateTime]::Parse($fresh.completedUtc).ToUniversalTime() -ge $requestTime
        }
    }while(-not $finished -and [DateTime]::UtcNow -lt $limit)
    if(-not $finished){throw 'Protection maintenance timed out; Claude was not launched.'}
    $state=Read-State
    if(-not $state.active -or -not $state.success -or [DateTime]::Parse($state.completedUtc).ToUniversalTime() -lt $requestTime){throw 'No fresh successful protection verification; Claude was not launched.'}
    $targetFull=[IO.Path]::GetFullPath($Target)
    $main=@($state.components | Where-Object {$_.path -ieq $targetFull})
    if($main.Count -ne 1 -or [IO.Path]::GetFileName($targetFull) -ine 'claude.exe'){throw 'Current launcher target is not protected.'}
    $app=[IO.Path]::GetDirectoryName($targetFull)
    Assert-NoReparse $app
    $expected=@($state.components | Where-Object {$_.path.StartsWith($app+'\',[StringComparison]::OrdinalIgnoreCase)} | Sort-Object path)
    $actual=@(Get-ChildItem -LiteralPath $app -Recurse -File -Filter '*.exe' | Sort-Object FullName)
    if($actual.Count -ne $expected.Count){throw 'Component inventory changed after verification; launch stopped.'}
    for($i=0;$i -lt $actual.Count;$i++){
        Assert-NoReparse $actual[$i].FullName
        if($actual[$i].FullName -ine $expected[$i].path -or (Get-FileHash -LiteralPath $actual[$i].FullName -Algorithm SHA256).Hash -cne $expected[$i].sha256){throw 'Component changed after verification; launch stopped.'}
    }
    Write-Output ('PASS: launch gate verified '+$expected.Count+' components. No Claude process or account was contacted.')
}
function Install-Protection {
    Require-Admin
    $resume=Test-Path -LiteralPath $InstallRoot
    if($resume){
        Assert-NoReparse $InstallRoot
        $oldState=Read-State
        if($oldState.success -or -not(Test-Path -LiteralPath $BackupFile)){throw 'Protection is already installed or directory is not a failed installation; inspect before reinstalling.'}
    }
    $components=@(Get-Components)
    $sourceHelper=Join-Path $PSScriptRoot 'ClaudeNetworkGuard.exe'
    if(-not(Test-Path -LiteralPath $sourceHelper)){throw 'Compiled rule helper missing.'}
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if(-not $resume){New-Item -ItemType Directory -Path $InstallRoot | Out-Null}
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)')
    Set-Acl -LiteralPath $InstallRoot -AclObject $acl
    Copy-Item -LiteralPath $PSCommandPath -Destination $InstalledScript
    Copy-Item -LiteralPath $sourceHelper -Destination $Helper
    $prior=@(Get-FilterPaths)
    if($resume){$backup=Get-Content -LiteralPath $BackupFile -Raw -Encoding UTF8 | ConvertFrom-Json}
    else{$backup=@{at=[DateTime]::UtcNow.ToString('o');policy=(Policy-Backup);previousFilterPaths=$prior;taskName=$TaskName;userSid=$sid};Write-Json $BackupFile $backup}
    $taskCreated=$false
    try{
        Sync-Protection
        $scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect();$folder=$scheduler.GetFolder('\')
        try{$existing=$folder.GetTask($TaskName)}catch{$existing=$null}
        if($null -ne $existing){throw 'Task name already exists; refusing to replace another task.'}
        $definition=$scheduler.NewTask(0)
        $definition.RegistrationInfo.Description='Verify signed Claude package components and maintain TCP 127.0.0.1:7898 restrictions. Runs at sign-in and before the dedicated launcher. Never starts Claude.'
        $definition.Principal.UserId=$sid;$definition.Principal.LogonType=3;$definition.Principal.RunLevel=1
        $definition.Settings.Enabled=$true;$definition.Settings.Hidden=$true;$definition.Settings.AllowDemandStart=$true
        $definition.Settings.DisallowStartIfOnBatteries=$false;$definition.Settings.StopIfGoingOnBatteries=$false
        $definition.Settings.ExecutionTimeLimit='PT2M';$definition.Settings.MultipleInstances=2
        $logon=$definition.Triggers.Create(9);$logon.UserId=$sid
        $action=$definition.Actions.Create(0);$action.Path=$PowerShell;$action.Arguments='-NoProfile -NonInteractive -WindowStyle Hidden -File "'+$InstalledScript+'" -Mode Sync';$action.WorkingDirectory=$InstallRoot
        $sddl='D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;'+$sid+')'
        $null=$folder.RegisterTaskDefinition($TaskName,$definition,2,$sid,$null,3,$sddl);$taskCreated=$true
        Write-Output 'PASS: restricted maintenance task installed. Other applications and their update settings were not changed.'
    }catch{
        $failure=$_
        if($taskCreated){$folder.DeleteTask($TaskName,0)}
        $added=@(Get-FilterPaths | Where-Object {$_ -notin $prior})
        if($added.Count){Invoke-Guard (@('remove')+$added) | Out-Null}
        Write-Json $StateFile @{schema=2;active=$true;success=$false;error=$failure.Exception.Message;completedUtc=[DateTime]::UtcNow.ToString('o')}
        throw $failure
    }
}
function Rollback-Protection {
    Require-Admin
    $backup=Get-Content -LiteralPath $BackupFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $service=New-Object -ComObject 'Schedule.Service';$service.Connect();$folder=$service.GetFolder('\')
    try{$task=$folder.GetTask($TaskName)}catch{$task=$null}
    if($task){
        $task.Enabled=$false
        if($task.State -in @(2,4)){
            try{$task.Stop(0)}catch{if($folder.GetTask($TaskName).State -in @(2,4)){throw}}
        }
        $folder.DeleteTask($TaskName,0)
    }
    Invoke-Guard @('remove-all') | Out-Null
    Write-Json $StateFile @{schema=2;active=$false;success=$true;completedUtc=[DateTime]::UtcNow.ToString('o');reason='Explicit user rollback'}
    Write-Output 'Removed only Claude7898Guard filters/task; current update settings preserved. Launcher is proxy-only again.'
}
try{
    switch($Mode){
        'Install'{Install-Protection}
        'Sync'{Sync-Protection}
        'Prepare'{Prepare-Launch}
        'Status'{Read-State | ConvertTo-Json -Depth 8}
        'Inventory'{Get-Components | ConvertTo-Json -Depth 5}
        'Rollback'{Rollback-Protection}
    }
    exit 0
}catch{
    $failureMessage=$_.Exception.Message
    $failureStack=$_.ScriptStackTrace
    if($Mode -in @('Sync','Install')){
        try{Write-Json (Join-Path $InstallRoot 'last-error.json') @{at=[DateTime]::UtcNow.ToString('o');mode=$Mode;message=$failureMessage;stack=$failureStack}}catch{}
    }
    [Console]::Error.WriteLine($failureMessage)
    [Console]::Error.WriteLine($failureStack)
    exit 1
}
