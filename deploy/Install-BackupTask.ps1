param(
    [Parameter(Mandatory=$true)][string]$Python,
    [Parameter(Mandatory=$true)][string]$Config,
    [string]$TaskName = 'SentinelOps encrypted off-server backup'
)
$ErrorActionPreference = 'Stop'
$taskPython = (Resolve-Path -LiteralPath $Python).Path
$taskConfig = (Resolve-Path -LiteralPath $Config).Path
$taskScript = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'offserver_backup.py')).Path
foreach ($taskPath in @($taskPython,$taskConfig,$taskScript)) {
    if ($taskPath.Contains('"') -or (Get-Item -LiteralPath $taskPath).PSIsContainer) { throw 'Invalid file path.' }
}
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw 'Task already exists; review it before changing its schedule.' }
# Require one authenticated, fresh, off-server copy before registering any job.
& $taskPython $taskScript --config $taskConfig
if ($LASTEXITCODE -ne 0) { throw 'Backup verification failed; no task was registered.' }
$taskAction = New-ScheduledTaskAction -Execute $taskPython -Argument ('"'+$taskScript+'" --config "'+$taskConfig+'"')
$taskTrigger = New-ScheduledTaskTrigger -Daily -At '04:00'
$taskSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
$taskPrincipal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal -Description 'Pull and authenticate encrypted SentinelOps snapshots. Requires this PC on, signed in, and able to reach the server. No retention deletion or restore.' | Out-Null
Write-Output 'Daily backup registered at 04:00 local time. Check task history and available disk space; keep the backup key separately protected.'
