#requires -Version 5.1
# Upgrade the original portable repository guard, preserving its pairing/config.
# Run in elevated Windows PowerShell 5.1 on the configured Ollama PC.
[CmdletBinding()]
param(
    [ValidateSet('InstallAudit', 'EnableArmed', 'Rollback')]
    [string]$Mode = 'InstallAudit',
    [string]$BackupPath,
    [switch]$ResumeOriginal
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$guardDirectory = Join-Path $env:ProgramData 'AiMonitorPower'
$installedPath = Join-Path $guardDirectory 'Ollama-PowerGuard.ps1'
$candidatePath = Join-Path $PSScriptRoot 'Ollama-PowerGuard.ps1'
$sentinelPath = Join-Path $guardDirectory 'shutdown-disabled'
$taskName = 'AI Monitor - Ollama shutdown guard'
$taskPath = '\'
$originalNormalizedHash = '6c1bb2ae207027c0e7789bf67f71d6438ab7487363cbc51e11782a26c9a3c4d5'
$expectedPrefix = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $installedPath + '"'
$utf8 = [Text.UTF8Encoding]::new($false)
$deploymentLock = $null
$guardLock = $null
$mutationsStarted = $false
$createdSentinel = $false
$sentinelText = 'PowerGuard deployment hold: ' + [Guid]::NewGuid().ToString('N')

function Get-Hash([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-NormalizedHash([string]$Path) {
    $text = [IO.File]::ReadAllText($Path).Replace("`r`n", "`n").Replace("`r", "`n").TrimEnd() + "`n"
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Assert-NoReparse([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ('Refusing a reparse-point path: ' + $item.FullName)
        }
        if ($item -is [IO.FileInfo]) { $item = $item.Directory } else { $item = $item.Parent }
    }
}

function Assert-Parser([string]$Path) {
    $tokens = $null; $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { throw ('PowerShell syntax validation failed: ' + $errors[0].Message) }
}

function Assert-PrivatePath([string]$Path, [switch]$Secret) {
    $trusted = @('S-1-5-18', 'S-1-5-32-544') # SYSTEM and BUILTIN\Administrators.
        Assert-NoReparse $Path
        $acl = Get-Acl -LiteralPath $Path
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $trusted) {
            throw ('Installation ACL review required: owner must be SYSTEM or Administrators: ' + $path + '. No permissions or credentials were changed.')
        }
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        if ($rules.Count -eq 0) { throw ('Installation ACL is empty or ambiguous: ' + $path) }
        foreach ($rule in $rules) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                $rule.IdentityReference.Value -in $trusted) { continue }
            # WriteData/CreateFiles, AppendData/CreateDirectories, WriteEA,
            # DeleteChild, WriteAttributes, Delete, WriteDACL, WriteOwner.
            $writeMask = 2 -bor 4 -bor 16 -bor 64 -bor 256 -bor 65536 -bor 262144 -bor 524288
            if (([int]$rule.FileSystemRights -band $writeMask) -ne 0) {
                throw ('Installation ACL allows a non-administrator to modify protected content: ' + $path + ' (' + $rule.IdentityReference.Value + '). Review permissions first; none were changed.')
            }
            if ($Secret -and
                (([int]$rule.FileSystemRights -band 1) -ne 0)) {
                throw ('Pairing-key ACL allows a non-administrator to read the LocalMachine DPAPI blob: ' + $path + '. Review permissions first; credentials were not changed.')
            }
        }
}

function Assert-PrivateInstallation {
    $paths = @($guardDirectory, $installedPath, (Join-Path $guardDirectory 'config.json'), (Join-Path $guardDirectory 'pairing-key.dpapi'))
    $paths += @(Get-ChildItem -LiteralPath $guardDirectory -File -Force | ForEach-Object FullName)
    foreach ($path in @($paths | Select-Object -Unique)) {
        Assert-PrivatePath $path -Secret:([IO.Path]::GetFileName($path) -ieq 'pairing-key.dpapi')
    }
}

function Get-GuardTask {
    return Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
}

function Assert-GuardTask($Task) {
    $actions = @($Task.Actions)
    if ($actions.Count -ne 1) { throw 'Expected exactly one guard task action; refusing to replace an unfamiliar task.' }
    $action = $actions[0]
    $expectedExecutable = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if ([IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($action.Execute)) -ine $expectedExecutable) {
        throw 'The guard task is not using the expected Windows PowerShell executable.'
    }
    $arguments = ($action.Arguments -replace '\s+', ' ').Trim()
    if ($arguments -ine ($expectedPrefix + ' -Arm') -and $arguments -ine ($expectedPrefix + ' -Check')) {
        throw 'The guard task arguments differ from the reviewed configuration. Refusing to overwrite them.'
    }
    $principal = [string]$Task.Principal.UserId
    if ($principal -notmatch '^S-1-') {
        $principal = ([Security.Principal.NTAccount]::new($principal)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    if ($principal -ne 'S-1-5-18') { throw 'The reviewed guard task must run as SYSTEM.' }
}

function Stop-GuardTask {
    $null = Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath
    Stop-ScheduledTask -TaskName $taskName -TaskPath $taskPath
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $registered = $service.GetFolder($taskPath).GetTask($taskName)
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        if ($registered.GetInstances(0).Count -eq 0) { return }
        Start-Sleep -Milliseconds 200
    }
    throw 'The guard task still has a running instance. It remains disabled; replacement was not attempted.'
}

function Set-GuardAction([ValidateSet('Check', 'Arm')][string]$Switch) {
    $task = Get-GuardTask
    Assert-GuardTask $task
    $old = @($task.Actions)[0]
    $arguments = $old.Arguments -replace '(?i)(?<!\S)-(Arm|Check)(?!\S)', ('-' + $Switch)
    $parameters = @{ Execute = $old.Execute; Argument = $arguments }
    if (-not [string]::IsNullOrWhiteSpace($old.WorkingDirectory)) { $parameters.WorkingDirectory = $old.WorkingDirectory }
    $action = New-ScheduledTaskAction @parameters
    $null = Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action
    $verify = Get-GuardTask
    Assert-GuardTask $verify
    if (@($verify.Actions)[0].Arguments -cne $arguments) { throw 'The task action did not retain the requested arguments.' }
}

function Write-Manifest($Manifest, [string]$Directory) {
    $path = Join-Path $Directory 'manifest.json'
    $temporary = $path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $bytes = $utf8.GetBytes(($Manifest | ConvertTo-Json -Depth 5))
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        if ([IO.File]::Exists($path)) { [IO.File]::Replace($temporary, $path, [Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($temporary, $path) }
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}

function Read-Manifest([string]$Directory) {
    if ([string]::IsNullOrWhiteSpace($Directory) -or -not [IO.Path]::IsPathRooted($Directory)) {
        throw 'Supply the exact absolute -BackupPath printed by InstallAudit.'
    }
    $resolved = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
    $backupRoot = (Join-Path $guardDirectory 'backups') + '\'
    if (-not $resolved.StartsWith($backupRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw ('BackupPath must identify a backup created under ' + $backupRoot)
    }
    Assert-PrivatePath $backupRoot.TrimEnd('\')
    Assert-PrivatePath $resolved
    $manifestPath = Join-Path $resolved 'manifest.json'
    Assert-PrivatePath $manifestPath
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.version -ne 1 -or $manifest.machine_name -cne $env:COMPUTERNAME -or
        $manifest.installed_path -cne $installedPath -or $manifest.task_name -cne $taskName -or
        $manifest.backup_path -ine $resolved) { throw 'The backup manifest does not match this machine, task, or directory.' }
    foreach ($name in @('Ollama-PowerGuard.original.ps1', 'task.original.xml')) { Assert-PrivatePath (Join-Path $resolved $name) }
    if ((Get-Hash (Join-Path $resolved 'Ollama-PowerGuard.original.ps1')) -cne $manifest.original_script_sha256 -or
        (Get-Hash (Join-Path $resolved 'task.original.xml')) -cne $manifest.original_task_sha256 -or
        (Get-NormalizedHash (Join-Path $resolved 'Ollama-PowerGuard.original.ps1')) -cne $originalNormalizedHash) {
        throw 'A backup file hash does not match the reviewed original. No restoration is permitted.'
    }
    Assert-Parser (Join-Path $resolved 'Ollama-PowerGuard.original.ps1')
    return $manifest
}

function Replace-Installed([string]$Source, [string]$ExpectedHash) {
    $temporary = Join-Path $guardDirectory ('.PowerGuard-' + [Guid]::NewGuid().ToString('N') + '.ps1')
    try {
        $bytes = [IO.File]::ReadAllBytes($Source)
        $hash = [Security.Cryptography.SHA256]::Create()
        try { $actualHash = [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
        finally { $hash.Dispose() }
        if ($actualHash -cne $ExpectedHash) { throw 'Replacement source changed from its verified hash.' }
        [IO.File]::WriteAllBytes($temporary, $bytes)
        Assert-Parser $temporary
        # Same-volume replacement preserves the target file's ACL.
        [IO.File]::Replace($temporary, $installedPath, [Management.Automation.Language.NullString]::Value)
        if ((Get-Hash $installedPath) -cne $ExpectedHash) { throw 'Installed script hash verification failed.' }
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

try {
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
        throw 'Use Windows PowerShell 5.1 to run this deployment helper.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this helper in an elevated Windows PowerShell 5.1 window.'
    }
    if ($ResumeOriginal -and $Mode -ne 'Rollback') { throw '-ResumeOriginal is only valid with -Mode Rollback.' }
    if ($Mode -eq 'InstallAudit' -and $BackupPath) { throw 'InstallAudit creates and prints a new backup path; do not supply -BackupPath.' }
    # Do not rewrite config or infer identity for a custom installation. Both
    # fields are supplied by the original portable installer.
    Assert-PrivateInstallation
    $configuration = Get-Content -LiteralPath (Join-Path $guardDirectory 'config.json') -Raw | ConvertFrom-Json
    $ip = $null
    if ($configuration.target_ip -isnot [string] -or
        -not [Net.IPAddress]::TryParse($configuration.target_ip, [ref]$ip) -or
        $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $configuration.target_ip -cne $ip.ToString() -or
        $configuration.target_mac -isnot [string] -or
        $configuration.target_mac -cnotmatch '^([0-9A-F]{2}-){5}[0-9A-F]{2}$') {
        throw 'The existing config must contain the portable installer target_ip and canonical target_mac. Custom installations require a tailored update.'
    }
    $targetFound = $false
    foreach ($address in @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq $configuration.target_ip)) {
        $adapter = Get-NetAdapter -InterfaceIndex $address.InterfaceIndex
        if ($adapter.MacAddress.Replace(':', '-').ToUpperInvariant() -eq $configuration.target_mac) { $targetFound = $true }
    }
    if (-not $targetFound) { throw 'This is not the configured Ollama PC (IP/MAC mismatch). No changes were made.' }
    Assert-NoReparse $installedPath
    Assert-Parser $installedPath
    $task = Get-GuardTask
    Assert-GuardTask $task
    $deploymentLock = [IO.File]::Open((Join-Path $guardDirectory 'deployment.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)

    if ($Mode -eq 'InstallAudit') {
        Assert-NoReparse $candidatePath
        Assert-Parser $candidatePath
        if ([IO.Path]::GetFullPath($candidatePath) -ieq $installedPath) { throw 'Run the helper from the extracted package, not the installed directory.' }
        if ((Get-NormalizedHash $installedPath) -cne $originalNormalizedHash) {
            throw 'Installed script differs from the original portable repository guard. Do not overwrite custom installations with this updater.'
        }
        $originalHash = Get-Hash $installedPath
        $candidateHash = Get-Hash $candidatePath
        $backupRoot = Join-Path $guardDirectory 'backups'
        if (-not (Test-Path -LiteralPath $backupRoot)) { $null = New-Item -ItemType Directory -Path $backupRoot }
        Assert-PrivatePath $backupRoot
        $BackupPath = Join-Path $backupRoot ((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        $null = New-Item -ItemType Directory -Path $BackupPath
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
            $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $BackupPath -AclObject $acl
        Copy-Item -LiteralPath $installedPath -Destination (Join-Path $BackupPath 'Ollama-PowerGuard.original.ps1')
        $xmlPath = Join-Path $BackupPath 'task.original.xml'
        $xml = Export-ScheduledTask -TaskName $taskName -TaskPath $taskPath
        [IO.File]::WriteAllText($xmlPath, $xml, [Text.Encoding]::Unicode)
        $manifest = [ordered]@{
            version = 1; machine_name = $env:COMPUTERNAME; created_utc = [DateTimeOffset]::UtcNow.ToString('o')
            installed_path = $installedPath; task_name = $taskName; backup_path = $BackupPath
            original_enabled = [bool]$task.Settings.Enabled; original_script_sha256 = $originalHash
            original_task_sha256 = Get-Hash $xmlPath; candidate_sha256 = $candidateHash; phase = 'prepared'
        }
        Write-Manifest $manifest $BackupPath
        Write-Output ('BACKUP_PATH=' + $BackupPath)
    } else {
        $manifest = Read-Manifest $BackupPath
        if ($manifest.phase -notin @('audit_installed', 'armed', 'prepared', 'rollback_started', 'rolled_back')) { throw 'This backup is not in an install/enable/rollback state.' }
        $installedHash = Get-Hash $installedPath
        $resumingRollback = $Mode -eq 'Rollback' -and $manifest.phase -in @('prepared', 'rollback_started', 'rolled_back') -and $installedHash -ceq $manifest.original_script_sha256
        if ($installedHash -cne $manifest.candidate_sha256 -and -not $resumingRollback) {
            throw 'Installed script has changed since this package was installed. Refusing to overwrite or arm unreviewed changes.'
        }
        if ($Mode -eq 'EnableArmed') {
            if ($manifest.phase -notin @('audit_installed', 'armed')) { throw 'Complete InstallAudit before enabling armed mode.' }
            Assert-NoReparse $candidatePath
            Assert-Parser $candidatePath
            if ((Get-Hash $candidatePath) -cne $manifest.candidate_sha256) { throw 'The package script differs from the installed version recorded in the backup.' }
            if (Test-Path -LiteralPath $sentinelPath) { throw 'shutdown-disabled is present. Resolve that deliberate hold before enabling armed mode.' }
        }
    }

    $mutationsStarted = $true
    if (-not (Test-Path -LiteralPath $sentinelPath)) {
        [IO.File]::WriteAllText($sentinelPath, $sentinelText, $utf8)
        $createdSentinel = $true
    } else { Assert-NoReparse $sentinelPath }
    Stop-GuardTask
    $guardLock = [IO.File]::Open((Join-Path $guardDirectory 'powerguard.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)

    if ($Mode -eq 'InstallAudit') {
        if ((Get-Hash $installedPath) -cne $manifest.original_script_sha256) { throw 'The original script changed while preparing installation.' }
        if ((Get-Hash $candidatePath) -cne $manifest.candidate_sha256) { throw 'The candidate script changed while preparing installation.' }
        Replace-Installed $candidatePath $manifest.candidate_sha256
        Set-GuardAction 'Check'
        $manifest.phase = 'audit_installed'
        Write-Manifest $manifest $BackupPath
    } elseif ($Mode -eq 'EnableArmed') {
        if ((Get-Hash $installedPath) -cne $manifest.candidate_sha256) { throw 'Installed script changed while preparing armed mode.' }
        Set-GuardAction 'Arm'
        $manifest.phase = 'armed'
        Write-Manifest $manifest $BackupPath
    } else {
        $installedHash = Get-Hash $installedPath
        if ($installedHash -cne $manifest.candidate_sha256 -and -not ($resumingRollback -and $installedHash -ceq $manifest.original_script_sha256)) {
            throw 'Installed script changed while preparing rollback.'
        }
        $manifest.phase = 'rollback_started'
        Write-Manifest $manifest $BackupPath
        if ($installedHash -cne $manifest.original_script_sha256) {
            Replace-Installed (Join-Path $BackupPath 'Ollama-PowerGuard.original.ps1') $manifest.original_script_sha256
        }
        # Restore all original task settings, but register it disabled first.
        [xml]$xml = Get-Content -LiteralPath (Join-Path $BackupPath 'task.original.xml') -Raw
        $ns = [Xml.XmlNamespaceManager]::new($xml.NameTable)
        $ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
        $settings = $xml.SelectSingleNode('/t:Task/t:Settings', $ns)
        $enabled = $settings.SelectSingleNode('t:Enabled', $ns)
        if ($null -eq $enabled) { $enabled = $xml.CreateElement('Enabled', $ns.LookupNamespace('t')); $null = $settings.AppendChild($enabled) }
        $enabled.InnerText = 'false'
        $null = Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Xml $xml.OuterXml -Force
        $manifest.phase = 'rolled_back'
        Write-Manifest $manifest $BackupPath
    }

    $guardLock.Dispose(); $guardLock = $null
    if ($Mode -ne 'Rollback') {
        if ($createdSentinel -and [IO.File]::ReadAllText($sentinelPath) -ceq $sentinelText) {
            Remove-Item -LiteralPath $sentinelPath
        }
        $null = Enable-ScheduledTask -TaskName $taskName -TaskPath $taskPath
        if ($Mode -eq 'InstallAudit') {
            Write-Output 'Installed in CHECK/AUDIT mode. The task is enabled with -Check; it cannot request shutdown.'
            if (Test-Path -LiteralPath $sentinelPath) { Write-Output 'A pre-existing shutdown-disabled hold was preserved; eligibility remains blocked until you resolve it.' }
        } else { Write-Output 'Armed mode enabled. All guard conditions and explicit unattended authorization still apply.' }
    } else {
        if ($ResumeOriginal -and [bool]$manifest.original_enabled) {
            Write-Warning 'Resuming the original enabled task. The original script does NOT honor shutdown-disabled and may shut down when its original conditions pass.'
            $null = Enable-ScheduledTask -TaskName $taskName -TaskPath $taskPath
        } else { Write-Output 'Original script and task configuration restored. The guard task remains DISABLED.' }
        Write-Output 'shutdown-disabled was retained. Config, pairing key, policy, authorization, and decision logs were not restored or removed.'
    }
    Write-Output ('BACKUP_PATH=' + $BackupPath)
} catch {
    if ($mutationsStarted) {
        try {
            if (-not (Test-Path -LiteralPath $sentinelPath)) { [IO.File]::WriteAllText($sentinelPath, $sentinelText, $utf8) }
        } catch { }
        try { Stop-GuardTask } catch { }
        Write-Warning 'Deployment stopped. The guard task was left disabled where possible; the safety hold was retained. Do not re-enable it until the reported error is resolved.'
        if ($BackupPath) { Write-Warning ('Backup path: ' + $BackupPath) }
    }
    throw
} finally {
    if ($null -ne $guardLock) { $guardLock.Dispose() }
    if ($null -ne $deploymentLock) { $deploymentLock.Dispose() }
}
