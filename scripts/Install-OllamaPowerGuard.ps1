#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$TargetIP,
 [Parameter(Mandatory=$true)][string]$TargetMac,
 [Parameter(Mandatory=$true)][string]$CoordinatorIP
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$guardSource = Join-Path $PSScriptRoot 'Ollama-PowerGuard.ps1'
if (-not (Test-Path -LiteralPath $guardSource -PathType Leaf)) {
    throw 'Place Ollama-PowerGuard.ps1 beside this installer.'
}
. $guardSource -LibraryOnly
$targetConfig = [pscustomobject]@{target_ip=$TargetIP; target_mac=$TargetMac.Replace(':','-').ToUpperInvariant()}
if (-not (Test-TargetComputer $targetConfig)) {
    throw 'Run on the configured Ollama PC; IP and adapter MAC must match.'
}

$root = Join-Path $env:ProgramData 'AiMonitorPower'
if (Test-Path -LiteralPath $root) {
    if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'The installation directory must not be a junction or symbolic link.'
    }
} else {
    New-Item -ItemType Directory -Path $root | Out-Null
}
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
    $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $root -AclObject $acl
foreach ($name in @('Ollama-PowerGuard.ps1','config.json','pairing-key.dpapi')) {
    $target = Join-Path $root $name
    if ((Test-Path -LiteralPath $target) -and
        ((Get-Item -LiteralPath $target).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw ('Unexpected reparse point: ' + $target)
    }
}

$keyPath = Join-Path $root 'pairing-key.dpapi'
if (-not (Test-Path -LiteralPath $keyPath)) {
    $secret = Read-Host 'Paste the 64-character power pairing key from the coordinator (input is hidden)' -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer).Trim()
        $key = Convert-HexBytes $plain
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        $plain = $null
        $secret.Dispose()
    }
    Add-Type -AssemblyName System.Security
    $protected = [Security.Cryptography.ProtectedData]::Protect(
        $key, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    [IO.File]::WriteAllBytes($keyPath, $protected)
}
Copy-Item -LiteralPath $guardSource -Destination (Join-Path $root 'Ollama-PowerGuard.ps1') -Force
$configuration = @{ version=1; status_url=('http://' + $CoordinatorIP + ':8766/completion'); target_ip=$targetConfig.target_ip; target_mac=$targetConfig.target_mac } | ConvertTo-Json
[IO.File]::WriteAllText((Join-Path $root 'config.json'), $configuration, [Text.UTF8Encoding]::new($false))

$taskName = 'AI Monitor - Ollama shutdown guard'
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' +
             (Join-Path $root 'Ollama-PowerGuard.ps1') + '" -Arm'
$action = New-ScheduledTaskAction -Execute $powershell -Argument $arguments
$triggers = @(
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1))
)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
# Register disabled until the user's cold-start Wake-on-LAN check has passed.
$settings.Enabled = $false
$registration = @{
    TaskName=$taskName; Action=$action; Trigger=$triggers; Principal=$principal; Settings=$settings
    Description='After verified AI log report completion, shut down only if no interactive users are logged in; 04:00-06:00 New York.'
}
Register-ScheduledTask @registration -Force | Out-Null
Write-Host 'Installed. The shutdown task is DISABLED until the Wake-on-LAN test passes.'
Write-Host 'Checking coordinator signature and current sessions; this check cannot shut down the PC.'
& $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $root 'Ollama-PowerGuard.ps1') -Check
if ($LASTEXITCODE -ne 0) { throw 'Status check failed. Leave the shutdown task disabled and review the error.' }
