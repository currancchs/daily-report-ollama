#requires -Version 5.1
<#
Offline safety regression tests. Does not run the installed guard, contact the
coordinator, read pairing credentials, enumerate real sessions, or shut down.
All fixtures stay in a unique directory; no recursive cleanup is performed.
#>
param(
    [string]$GuardPath = (Join-Path $PSScriptRoot 'Ollama-PowerGuard.ps1'),
    [string]$FixtureRoot = ([IO.Path]::GetTempPath())
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$script:Passed = 0
$script:Failed = 0
$script:Failures = @()
$script:TestRoot = Join-Path ([IO.Path]::GetFullPath($FixtureRoot)) ('PowerGuard-tests-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $script:TestRoot -Force
$script:ConfigPath = Join-Path $script:TestRoot 'config.json'
[IO.File]::WriteAllText($script:ConfigPath, '{"target_ip":"192.0.2.100","target_mac":"02-00-00-00-00-01","status_url":"http://192.0.2.24:8766/completion"}')

# -LibraryOnly is mandatory. No production entry point runs during import.
. $GuardPath -LibraryOnly -ConfigPath $script:ConfigPath
$script:NativeShutdownDefinition = (Get-Item Function:\Invoke-ShutdownRequest).ScriptBlock.ToString()

# Replace the sole native shutdown wrapper BEFORE any policy test invokes code.
function Invoke-ShutdownRequest { $script:ShutdownCalls++ }
function Get-InteractiveSessions { throw 'TEST TRAP: native session query is forbidden.' }
function Test-TargetComputer($Config) { return $script:MockIdentity }
function Get-BootUnix { return $script:MockBoot }
function Get-UnixNow { return $script:MockNow }
function Get-SessionEvidence {
    if ($script:SessionFailure) { throw 'simulated WTS failure' }
    return $script:MockSessions
}
function Get-Completion($Config, [byte[]]$Key) {
    $script:CompletionCalls++
    if ($script:CompletionFailure) { throw 'simulated coordinator rejection' }
    return $script:MockData
}
function Wait-GuardGrace($Observation, $Ticket, $Data, [byte[]]$Key, [long]$Boot, [int]$Seconds = 60) {
    $script:GraceCalls++
    if ($script:GraceAction) { & $script:GraceAction }
    return [pscustomobject]@{ observation = $Observation; reason = $script:GraceReason }
}
$script:OriginalSaveResult = (Get-Item Function:\Save-Result).ScriptBlock

function Assert-Equal($Actual, $Expected, [string]$Because = '') {
    if ($Actual -cne $Expected) { throw ("Expected [{0}], got [{1}]. {2}" -f $Expected, $Actual, $Because) }
}
function Assert-True([bool]$Condition, [string]$Because) { if (-not $Condition) { throw $Because } }
function Assert-Throws([scriptblock]$Action) {
    $threw = $false
    try { & $Action | Out-Null } catch { $threw = $true }
    if (-not $threw) { throw 'Expected a terminating error.' }
}
function Test-Case([string]$Name, [scriptblock]$Action) {
    try { & $Action; $script:Passed++; Write-Output ('PASS ' + $Name) }
    catch {
        $script:Failed++
        $text = $Name + ': ' + $_.Exception.Message
        $script:Failures += $text
        Write-Output ('FAIL ' + $text)
    }
}
function Unix([string]$Iso) { return ([DateTimeOffset]::Parse($Iso, [Globalization.CultureInfo]::InvariantCulture)).ToUnixTimeSeconds() }
function Clone($Value) { return ($Value | ConvertTo-Json -Depth 12 -Compress | ConvertFrom-Json) }

$script:Key = [byte[]](1..32)
$script:Boot = Unix '2026-11-04T03:30:00-05:00'
$script:Now = Unix '2026-11-04T04:44:00-05:00'
$script:Sid = 'S-1-5-21-1-2-3-1001'

function Valid-Session {
    return [pscustomobject]@{
        id = 1; user = 'FixtureUser'; domain = 'FIXTURE'; sid = $script:Sid
        state = 0; protocol = 0; lock = 0
        logon = $script:Boot + 19; input = $script:Boot + 25; current = $script:Now
        input_stamp = [long]134382000000000000
        logon_stamp = [long]134381999900000000
    }
}
function Valid-State {
    $state = New-BootState ($script:Boot + 40) $script:Boot
    $state.last_observed = $script:Now
    return $state
}
function Valid-Ticket {
    return [pscustomobject]@{
        version = 2; purpose = 'unattended-ticket'; id = 'fixture-ticket'
        machine = '192.0.2.100|02-00-00-00-00-01'
        issued_boot = $script:Boot - 86400; issued = $script:Boot - 36000
        boot_start = $script:Boot - 600; boot_end = $script:Boot + 900
        expires = (Unix '2026-11-04T06:00:00-05:00')
        bound_boot = $script:Boot; expected_date = '2026-11-04'; allowed_sid = $script:Sid
    }
}
function Valid-RecurringPolicy {
    return [pscustomobject]@{
        version = 2; purpose = 'recurring-policy'; enabled = $true
        machine = '192.0.2.100|02-00-00-00-00-01'; allowed_sid = $script:Sid
        created = (Unix '2026-01-02T12:00:00-05:00')
        created_boot = (Unix '2026-01-01T12:00:00-05:00')
        boot_start_minute = 200; boot_end_minute = 225
    }
}
function Assert-Blocked([scriptblock]$Action, [string]$Because) {
    $blocked = $false
    try {
        $reason = & $Action
        $blocked = -not [string]::IsNullOrEmpty([string]$reason)
    } catch { $blocked = $true }
    if (-not $blocked) { throw $Because }
}
function Valid-Data {
    return [pscustomobject]@{
        version = 1; nonce = 'fixture-nonce'; issued_utc = $script:Now; ready = $true
        report_date = '2026-11-04'; started_utc = $script:Boot + 300; completed_utc = $script:Now - 240
    }
}
function Envelope($Data) {
    $payload = $Data | ConvertTo-Json -Compress
    $hmac = New-Object Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = $script:Key
        $hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($payload))
        $signature = ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    } finally { $hmac.Dispose() }
    return [pscustomobject]@{ payload = $payload; signature = $signature }
}
function Reset-Fixture([string]$Name) {
    $dir = Join-Path $script:TestRoot $Name
    $null = New-Item -ItemType Directory -Path $dir -Force
    $script:ConfigPath = Join-Path $dir 'config.json'
    [IO.File]::WriteAllText($script:ConfigPath, '{"target_ip":"192.0.2.100","target_mac":"02-00-00-00-00-01","status_url":"http://192.0.2.24:8766/completion"}')
    $script:MockNow = $script:Now
    $script:MockBoot = $script:Boot
    $script:MockIdentity = $true
    $script:MockSessions = @()
    $script:MockData = Valid-Data
    $script:SessionFailure = $false
    $script:CompletionFailure = $false
    $script:ShutdownCalls = 0
    $script:CompletionCalls = 0
    $script:GraceCalls = 0
    $script:GraceAction = $null
    $script:GraceReason = ''
    $script:Check = $false
    $script:Arm = $true
    $script:AuthorizeNextBoot = $false
    $script:EnableRecurring = $false
    $script:DisableRecurring = $false
    $script:DecisionContext = [ordered]@{ boot_origin = 'unknown' }
    Set-Item Function:\Save-Result $script:OriginalSaveResult
    Write-LocalRecord (Join-Path $dir 'boot-state.json') (Valid-State) $script:Key
    return $dir
}

Test-Case 'Coordinator valid HMAC, nonce and issued time accepted' {
    $r = Read-SignedCompletion (Envelope (Valid-Data)) $script:Key 'fixture-nonce' $script:Now
    Assert-Equal $r.ready $true
}
Test-Case 'Native shutdown wrapper statically requests /s /t 0 without force' {
    Assert-True ($script:NativeShutdownDefinition -match '&\s+"\$env:SystemRoot\\System32\\shutdown\.exe"\s+/s\s+/t\s+0\s+/d\s+p:0:0\s+/c') 'Native shutdown command changed from the reviewed non-forced form.'
    Assert-True ($script:NativeShutdownDefinition -notmatch '(?i)(?:^|\s)/f(?:\s|$)|Stop-Process|Stop-Computer|taskkill|Win32Shutdown') 'Unexpected forced or alternative shutdown/process action.'
}
Test-Case 'Coordinator tampered signature rejected' {
    $e = Envelope (Valid-Data); $e.signature = ('00' * 32)
    Assert-Throws { Read-SignedCompletion $e $script:Key 'fixture-nonce' $script:Now }
}
Test-Case 'Coordinator tampered payload rejected' {
    $e = Envelope (Valid-Data); $e.payload = $e.payload.Replace('true','false')
    Assert-Throws { Read-SignedCompletion $e $script:Key 'fixture-nonce' $script:Now }
}
Test-Case 'Coordinator nonce mismatch rejected' {
    Assert-Throws { Read-SignedCompletion (Envelope (Valid-Data)) $script:Key 'another-nonce' $script:Now }
}
Test-Case 'Coordinator stale or future issued timestamp rejected' {
    foreach ($offset in @(-31,31)) {
        $d = Valid-Data; $d.issued_utc = $script:Now + $offset
        Assert-Throws { Read-SignedCompletion (Envelope $d) $script:Key 'fixture-nonce' $script:Now }
    }
}
Test-Case 'Coordinator nonboolean ready rejected' {
    $d = Valid-Data; $d.ready = 'true'
    Assert-Throws { Read-SignedCompletion (Envelope $d) $script:Key 'fixture-nonce' $script:Now }
}
Test-Case 'Original ready, date, current-boot and report-time gates retained' {
    $d = Valid-Data
    Assert-Equal (Get-BlockReason $d $script:Now $script:Boot 0) ''
    $d.ready = $false; Assert-Equal (Get-BlockReason $d $script:Now $script:Boot 0) 'report_not_ready'
    $d = Valid-Data; $d.report_date = '2026-11-03'; Assert-Equal (Get-BlockReason $d $script:Now $script:Boot 0) 'wrong_report_date'
    $d = Valid-Data; $d.started_utc = $script:Boot - 1; Assert-Equal (Get-BlockReason $d $script:Now $script:Boot 0) 'report_started_before_this_boot'
    $d = Valid-Data; $d.completed_utc = $script:Now + 1; Assert-Equal (Get-BlockReason $d $script:Now $script:Boot 0) 'invalid_report_time'
    $d = Valid-Data; $d.completed_utc = $d.started_utc - 1; Assert-Equal (Get-BlockReason $d $script:Now $script:Boot 0) 'invalid_report_time'
}
Test-Case '04:00 inclusive and 06:00 exclusive Eastern, winter and summer' {
    foreach ($case in @(@('2026-11-04','-05:00'), @('2026-07-04','-04:00'))) {
        $date = $case[0]; $offset = $case[1]
        foreach ($row in @(@('03:59:59',$false), @('04:00:00',$true), @('05:59:59',$true), @('06:00:00',$false))) {
            $n = Unix ($date + 'T' + $row[0] + $offset)
            $b = Unix ($date + 'T03:30:00' + $offset)
            $d = Valid-Data; $d.report_date = $date; $d.started_utc = $b + 10; $d.completed_utc = $n - 1
            $reason = Get-BlockReason $d $n $b 0
            if ($row[1]) { Assert-Equal $reason '' } else { Assert-Equal $reason 'outside_04_to_06_New_York' }
        }
    }
}
Test-Case 'No users retains original policy without ticket' {
    Assert-Equal (Get-SessionBlockReason @() (Valid-State) $null $script:Now $script:Boot) ''
}
Test-Case 'Explicit valid ticket plus locked idle boot console qualifies' {
    Assert-Equal (Get-SessionBlockReason @((Valid-Session)) (Valid-State) (Valid-Ticket) $script:Now $script:Boot) ''
}
Test-Case 'Locked console without opt-in remains blocked' {
    Assert-Equal (Get-SessionBlockReason @((Valid-Session)) (Valid-State) $null $script:Now $script:Boot) 'no_unattended_authorization'
}
Test-Case 'Unlocked and unknown lock states block even after long idle' {
    foreach ($lock in @(1,-1,99)) {
        $s = Valid-Session; $s.lock = $lock
        Assert-Equal (Get-ObservationProblem @($s) $script:Now $script:Boot) 'console_unlocked_or_lock_unknown'
    }
}
Test-Case 'Connected and disconnected RDP always block' {
    foreach ($state in @(0,1,4)) {
        $s = Valid-Session; $s.protocol = 2; $s.state = $state
        Assert-Equal (Get-ObservationProblem @($s) $script:Now $script:Boot) 'rdp_session_present'
    }
}
Test-Case 'Disconnected console and unknown protocol block' {
    $s = Valid-Session; $s.state = 4
    Assert-Equal (Get-ObservationProblem @($s) $script:Now $script:Boot) 'console_not_active_or_protocol_unknown'
    $s = Valid-Session; $s.protocol = 99
    Assert-Equal (Get-ObservationProblem @($s) $script:Now $script:Boot) 'console_not_active_or_protocol_unknown'
}
Test-Case 'Multiple users block' {
    Assert-Equal (Get-ObservationProblem @((Valid-Session),(Valid-Session)) $script:Now $script:Boot) 'multiple_users'
}
Test-Case 'Zero, future, stale and pre-logon input timestamps block' {
    foreach ($input in @([long]0, ($script:Now + 1), ($script:Boot + 18))) {
        $s = Valid-Session; $s.input = $input
        Assert-Equal (Get-ObservationProblem @($s) $script:Now $script:Boot) 'invalid_session_timestamps'
    }
    $s = Valid-Session; $s.current = $script:Now - 16
    Assert-Equal (Get-ObservationProblem @($s) $script:Now $script:Boot) 'invalid_session_timestamps'
    Assert-Throws { Convert-FileTimeUnix 0 }
    Assert-Throws { Convert-FileTimeUnix -1 }
}
Test-Case 'Input or console logon after startup tolerance blocks' {
    $s = Valid-Session; $s.input = $script:Boot + 121
    Assert-Equal (Get-ObservationProblem @($s) $script:Now $script:Boot) 'input_after_boot_startup'
    $s = Valid-Session; $s.logon = $script:Boot + 121
    Assert-Equal (Get-ObservationProblem @($s) $script:Now $script:Boot) 'console_not_created_at_boot'
}
Test-Case 'Less than 60 minutes of observations blocks' {
    $state = Valid-State; $state.first_observed = $script:Now - 3599
    Assert-True ([bool](Get-SessionBlockReason @((Valid-Session)) $state (Valid-Ticket) $script:Now $script:Boot)) 'Insufficient observations must block.'
}
Test-Case 'Ticket wrong machine, boot, date window, expiry and user block' {
    foreach ($field in @('machine','bound_boot','issued_boot','issued','boot_start','boot_end','expires','allowed_sid')) {
        $t = Valid-Ticket
        switch ($field) {
            'machine' { $t.machine = 'another-machine' }
            'bound_boot' { $t.bound_boot = $script:Boot - 1 }
            'issued_boot' { $t.issued_boot = $script:Boot }
            'issued' { $t.issued = $script:Boot }
            'boot_start' { $t.boot_start = $script:Boot + 1 }
            'boot_end' { $t.boot_end = $script:Boot }
            'expires' { $t.expires = $script:Now }
            'allowed_sid' { $t.allowed_sid = 'invalid' }
        }
        Assert-True ([bool](Get-TicketReason $t $script:Now $script:Boot)) ('Invalid ticket field passed: ' + $field)
    }
    $s = Valid-Session; $s.sid = 'S-1-5-21-9-9-9-1001'
    Assert-Equal (Get-SessionBlockReason @($s) (Valid-State) (Valid-Ticket) $script:Now $script:Boot) 'console_user_not_authorized'
}
Test-Case 'Late first observation and missed samples become sticky vetoes' {
    Assert-Equal (New-BootState ($script:Boot + 121) $script:Boot).veto 'observation_started_late'
    $state = Valid-State; $state.last_observed = $script:Now - 151
    $state = Update-BootState $state @((Valid-Session)) $script:Now $script:Boot
    Assert-Equal $state.veto 'observation_gap_or_clock_change'
    $state = Update-BootState $state @((Valid-Session)) $script:Now $script:Boot
    Assert-Equal $state.veto 'observation_gap_or_clock_change'
}
Test-Case 'Observed unlock remains blocked after relock' {
    $s = Valid-Session; $s.lock = 1
    $state = Update-BootState (Valid-State) @($s) $script:Now $script:Boot
    $s.lock = 0
    $state = Update-BootState $state @($s) $script:Now $script:Boot
    Assert-Equal $state.veto 'console_unlocked_or_lock_unknown'
    Assert-True ([bool](Get-SessionBlockReason @($s) $state (Valid-Ticket) $script:Now $script:Boot)) 'Relock must not erase observed activity.'
}
Test-Case 'Session replacement and later input leave sticky vetoes' {
    $s = Valid-Session
    $state = Update-BootState (Valid-State) @($s) $script:Now $script:Boot
    $s.id = 2
    $state = Update-BootState $state @($s) $script:Now $script:Boot
    Assert-Equal $state.veto 'console_session_changed'
    $s = Valid-Session
    $state = Update-BootState (Valid-State) @($s) $script:Now $script:Boot
    $s.input++; $s.input_stamp++
    $state = Update-BootState $state @($s) $script:Now $script:Boot
    Assert-Equal $state.veto 'input_changed_since_first_observation'
}
Test-Case 'Local state round trip and tamper rejection' {
    $dir = Reset-Fixture 'state-authentication'
    $path = Join-Path $dir 'boot-state.json'
    $r = Read-LocalRecord $path 'boot-state' $script:Key
    Assert-Equal $r.boot $script:Boot
    Assert-Throws { Read-LocalRecord $path 'unattended-ticket' $script:Key }
    $e = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $e.payload = $e.payload.Replace('boot-state','corruption')
    [IO.File]::WriteAllText($path, ($e | ConvertTo-Json -Compress))
    Assert-Throws { Read-LocalRecord $path 'boot-state' $script:Key }
}
Test-Case 'Persistent logs append decisions and keep UTC/Eastern timestamps' {
    $dir = Reset-Fixture 'logging'
    Save-Result 'fixture_one' 'test' | Out-Null
    Save-Result 'fixture_two' 'test' | Out-Null
    $files = @(Get-ChildItem -LiteralPath $dir -Filter 'decisions-*.jsonl')
    Assert-Equal $files.Count 1
    $lines = @(Get-Content -LiteralPath $files[0].FullName)
    Assert-Equal $lines.Count 2
    $last = Get-Content -LiteralPath (Join-Path $dir 'last-result.json') -Raw | ConvertFrom-Json
    Assert-Equal $last.status 'fixture_two'
    Assert-True ([bool][DateTimeOffset]::Parse($last.checked_utc)) 'UTC timestamp must parse.'
    Assert-True ([bool][DateTimeOffset]::Parse($last.checked_eastern)) 'Eastern timestamp must parse.'
}
Test-Case 'Check overrides Arm and never attempts shutdown' {
    $dir = Reset-Fixture 'check-plus-arm'
    $script:Check = $true; $script:Arm = $true
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 0
    Assert-Equal $script:GraceCalls 0
    Assert-Equal (Read-LocalRecord (Join-Path $dir 'boot-state.json') 'boot-state' $script:Key).attempt $false
    Assert-Equal (Get-Content -LiteralPath (Join-Path $dir 'last-result.json') -Raw | ConvertFrom-Json).status 'check_only'
}
Test-Case 'Audit binds one-night authorization but does not record an attempt' {
    $dir = Reset-Fixture 'audit-ticket-binding'
    $script:Check = $true
    $t = Valid-Ticket; $t.bound_boot = 0
    Write-LocalRecord (Join-Path $dir 'unattended-ticket.json') $t $script:Key
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal (Read-LocalRecord (Join-Path $dir 'unattended-ticket.json') 'unattended-ticket' $script:Key).bound_boot $script:Boot
    Assert-Equal (Read-LocalRecord (Join-Path $dir 'boot-state.json') 'boot-state' $script:Key).attempt $false
    Assert-Equal $script:ShutdownCalls 0
}
Test-Case 'Global hold file blocks armed run' {
    $dir = Reset-Fixture 'hold'
    [IO.File]::WriteAllText((Join-Path $dir 'shutdown-disabled'), 'test')
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 0
    Assert-Equal $script:GraceCalls 0
}
Test-Case 'Coordinator failure blocks armed run' {
    $null = Reset-Fixture 'coordinator-error'; $script:CompletionFailure = $true
    Assert-Throws { Invoke-GuardRun $script:Key }
    Assert-Equal $script:ShutdownCalls 0
}
Test-Case 'WTS failure records sticky veto and blocks armed run' {
    $dir = Reset-Fixture 'wts-error'; $script:SessionFailure = $true
    Assert-Throws { Invoke-GuardRun $script:Key }
    Assert-Equal $script:ShutdownCalls 0
    Assert-Equal (Read-LocalRecord (Join-Path $dir 'boot-state.json') 'boot-state' $script:Key).veto 'session_query_failed'
}
Test-Case 'Log write failure prevents shutdown request' {
    $null = Reset-Fixture 'log-error'
    function Save-Result { throw 'simulated full disk' }
    Assert-Throws { Invoke-GuardRun $script:Key }
    Assert-Equal $script:ShutdownCalls 0
}
Test-Case 'Activity during grace prevents shutdown request' {
    $null = Reset-Fixture 'grace-block'
    $script:GraceReason = 'console_unlocked_or_lock_unknown'
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 0
    Assert-Equal $script:GraceCalls 1
}
Test-Case 'Final identity change prevents shutdown request' {
    $null = Reset-Fixture 'identity-change'
    $script:GraceAction = { $script:MockIdentity = $false }
    Assert-Throws { Invoke-GuardRun $script:Key }
    Assert-Equal $script:ShutdownCalls 0
}
Test-Case '06:00 reached during grace prevents shutdown request' {
    $null = Reset-Fixture 'time-boundary'
    $script:GraceAction = { $script:MockNow = Unix '2026-11-04T06:00:00-05:00'; $script:MockData.issued_utc = $script:MockNow }
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 0
}
Test-Case 'Final RDP arrival prevents shutdown request' {
    $null = Reset-Fixture 'rdp-final'
    $script:GraceAction = { $s = Valid-Session; $s.protocol = 2; $script:MockSessions = @($s) }
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 0
}
Test-Case 'Eligible run calls intercepted action once and suppresses repeat attempts' {
    $dir = Reset-Fixture 'eligible-once'
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 1
    Assert-Equal $script:CompletionCalls 2
    Assert-Equal (Read-LocalRecord (Join-Path $dir 'boot-state.json') 'boot-state' $script:Key).attempt $true
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 1
}
Test-Case 'Authorized locked boot console reaches only intercepted shutdown action' {
    $dir = Reset-Fixture 'locked-console-eligible'
    $script:MockSessions = @((Valid-Session))
    Write-LocalRecord (Join-Path $dir 'unattended-ticket.json') (Valid-Ticket) $script:Key
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 1
    Assert-Equal (Read-LocalRecord (Join-Path $dir 'boot-state.json') 'boot-state' $script:Key).attempt $true
    Assert-Equal $script:DecisionContext['classification'] 'authorized_unattended_candidate'
}
Test-Case 'Activity arriving during final log write is caught before OS call' {
    $null = Reset-Fixture 'activity-after-last-log'
    function Save-Result([string]$Status, [string]$Detail = '') {
        & $script:OriginalSaveResult $Status $Detail
        if ($Status -eq 'shutdown_requesting') {
            $s = Valid-Session; $s.lock = 1; $script:MockSessions = @($s)
        }
    }
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 0
}
Test-Case 'Completion expiring during final log write is caught before OS call' {
    $null = Reset-Fixture 'freshness-after-last-log'
    function Save-Result([string]$Status, [string]$Detail = '') {
        & $script:OriginalSaveResult $Status $Detail
        if ($Status -eq 'shutdown_requesting') { $script:MockNow += 31 }
    }
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 0
}
Test-Case '06:00 reached during final log write is caught before OS call' {
    $null = Reset-Fixture 'window-after-last-log'
    function Save-Result([string]$Status, [string]$Detail = '') {
        & $script:OriginalSaveResult $Status $Detail
        if ($Status -eq 'shutdown_requesting') {
            $script:MockNow = Unix '2026-11-04T06:00:00-05:00'
            $script:MockData.issued_utc = $script:MockNow
        }
    }
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 0
}
Test-Case 'Disconnected RDP appearing during final log is caught before OS call' {
    $null = Reset-Fixture 'rdp-after-last-log'
    function Save-Result([string]$Status, [string]$Detail = '') {
        & $script:OriginalSaveResult $Status $Detail
        if ($Status -eq 'shutdown_requesting') {
            $s = Valid-Session; $s.protocol = 2; $s.state = 4; $script:MockSessions = @($s)
        }
    }
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 0
}
Test-Case 'Subsecond input change during final log vetoes locked-console exception' {
    $dir = Reset-Fixture 'input-after-last-log'
    $script:MockSessions = @((Valid-Session))
    Write-LocalRecord (Join-Path $dir 'unattended-ticket.json') (Valid-Ticket) $script:Key
    function Save-Result([string]$Status, [string]$Detail = '') {
        & $script:OriginalSaveResult $Status $Detail
        if ($Status -eq 'shutdown_requesting') { $script:MockSessions[0].input_stamp++ }
    }
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 0
}
Test-Case 'State write failure blocks before shutdown' {
    $null = Reset-Fixture 'state-write-error'
    function Write-LocalRecord { throw 'simulated state write failure' }
    Assert-Throws { Invoke-GuardRun $script:Key }
    Assert-Equal $script:ShutdownCalls 0
}
Test-Case 'Rejected non-forced shutdown is not retried on next invocation' {
    $dir = Reset-Fixture 'rejected-request'
    function Invoke-ShutdownRequest { $script:ShutdownCalls++; throw 'simulated OS rejection' }
    Assert-Throws { Invoke-GuardRun $script:Key }
    Assert-Equal $script:ShutdownCalls 1
    Assert-Equal (Read-LocalRecord (Join-Path $dir 'boot-state.json') 'boot-state' $script:Key).attempt $true
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 1
}

Test-Case 'One recurring policy authorizes consecutive dates across both DST changes' {
    $policy = Valid-RecurringPolicy
    foreach ($row in @(
        @('2026-03-07','-05:00'), @('2026-03-08','-04:00'), @('2026-03-09','-04:00'),
        @('2026-10-31','-04:00'), @('2026-11-01','-05:00'), @('2026-11-02','-05:00'),
        @('2026-11-04','-05:00'), @('2026-11-05','-05:00'), @('2026-11-06','-05:00')
    )) {
        $boot = Unix ($row[0] + 'T03:30:00' + $row[1])
        $now = Unix ($row[0] + 'T04:44:00' + $row[1])
        Assert-Equal (Get-RecurringReason $policy $now $boot) '' ('Failed date ' + $row[0])
        Assert-Equal (Get-TicketReason $policy $now $boot) '' 'Common authorization gate must accept recurring policy.'
    }
}
Test-Case 'Recurring boot window is 03:20 inclusive to 03:45 exclusive Eastern' {
    $policy = Valid-RecurringPolicy
    foreach ($dateOffset in @(@('2026-11-04','-05:00'), @('2026-07-04','-04:00'))) {
        $now = Unix ($dateOffset[0] + 'T04:44:00' + $dateOffset[1])
        foreach ($row in @(@('03:19:59',$false), @('03:20:00',$true), @('03:44:59',$true), @('03:45:00',$false), @('09:00:00',$false))) {
            $boot = Unix ($dateOffset[0] + 'T' + $row[0] + $dateOffset[1])
            if ($row[1]) { Assert-Equal (Get-RecurringReason $policy $now $boot) '' }
            else { Assert-Blocked { Get-RecurringReason $policy $now $boot } ('Boot at ' + $row[0] + ' must be blocked.') }
        }
    }
}
Test-Case 'Recurring policy cannot reuse a previous-day boot' {
    $policy = Valid-RecurringPolicy
    $boot = Unix '2026-11-04T03:30:00-05:00'
    $nextMorning = Unix '2026-11-05T04:44:00-05:00'
    Assert-Blocked { Get-RecurringReason $policy $nextMorning $boot } 'A machine left on overnight must not qualify as a new unattended boot.'
}
Test-Case 'Recurring policy created during or after current boot cannot authorize it' {
    foreach ($field in @('created','created_boot')) {
        foreach ($offset in @(0,1)) {
            $policy = Valid-RecurringPolicy; $policy.$field = $script:Boot + $offset
            Assert-Blocked { Get-RecurringReason $policy $script:Now $script:Boot } ($field + ' must predate the authorized boot.')
        }
    }
}
Test-Case 'Disabled malformed or broadened recurring policies fail closed' {
    foreach ($field in @('enabled','machine','allowed_sid','boot_start_minute','boot_end_minute')) {
        $policy = Valid-RecurringPolicy
        switch ($field) {
            'enabled' { $policy.enabled = $false }
            'machine' { $policy.machine = 'another-machine' }
            'allowed_sid' { $policy.allowed_sid = 'invalid' }
            'boot_start_minute' { $policy.boot_start_minute = 0 }
            'boot_end_minute' { $policy.boot_end_minute = 1440 }
        }
        Assert-Blocked { Get-RecurringReason $policy $script:Now $script:Boot } ('Invalid recurring field passed: ' + $field)
    }
    $policy = Valid-RecurringPolicy; $policy.enabled = 'true'
    Assert-Blocked { Get-RecurringReason $policy $script:Now $script:Boot } 'String enabled must not be treated as an explicit boolean opt-in.'
}
Test-Case 'Recurring policy rejects array identity fields and nonnumeric version' {
    foreach ($field in @('version','purpose','machine')) {
        $policy = Valid-RecurringPolicy
        $policy.$field = @($policy.$field, $policy.$field)
        Assert-Blocked { Get-RecurringReason $policy $script:Now $script:Boot } ('Array-valued ' + $field + ' must not satisfy scalar validation.')
    }
    $policy = Valid-RecurringPolicy; $policy.version = '2'
    Assert-Blocked { Get-RecurringReason $policy $script:Now $script:Boot } 'String version must not satisfy numeric schema validation.'
}
Test-Case 'Recurring policy takes precedence without rewriting it or creating a daily ticket' {
    $dir = Reset-Fixture 'recurring-read'
    $path = Join-Path $dir 'recurring-policy.json'
    Write-LocalRecord $path (Valid-RecurringPolicy) $script:Key
    $before = [IO.File]::ReadAllText($path)
    $auth = Get-GuardAuthorization $script:Key $script:Boot
    Assert-Equal $auth.purpose 'recurring-policy'
    Assert-Equal (Get-TicketReason $auth $script:Now $script:Boot) ''
    Assert-Equal ([IO.File]::ReadAllText($path)) $before
    Assert-Equal ([IO.File]::Exists((Join-Path $dir 'unattended-ticket.json'))) $false
}
Test-Case 'Disabled recurring policy blocks console despite a valid one-night ticket' {
    $dir = Reset-Fixture 'recurring-disabled-priority'
    $policy = Valid-RecurringPolicy; $policy.enabled = $false
    Write-LocalRecord (Join-Path $dir 'recurring-policy.json') $policy $script:Key
    Write-LocalRecord (Join-Path $dir 'unattended-ticket.json') (Valid-Ticket) $script:Key
    $auth = Get-GuardAuthorization $script:Key $script:Boot
    Assert-Equal $auth.purpose 'recurring-policy'
    Assert-Equal $auth.enabled $false
    $script:MockSessions = @((Valid-Session))
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 0
    Assert-Equal $script:GraceCalls 0
}
Test-Case 'Corrupt recurring policy blocks instead of falling back to a valid ticket' {
    $dir = Reset-Fixture 'recurring-corrupt-priority'
    $path = Join-Path $dir 'recurring-policy.json'
    Write-LocalRecord $path (Valid-RecurringPolicy) $script:Key
    Write-LocalRecord (Join-Path $dir 'unattended-ticket.json') (Valid-Ticket) $script:Key
    $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $record.payload = $record.payload.Replace('recurring-policy','tampered-policy')
    [IO.File]::WriteAllText($path, ($record | ConvertTo-Json -Compress))
    Assert-Throws { Get-GuardAuthorization $script:Key $script:Boot }
    $script:MockSessions = @((Valid-Session))
    Assert-Throws { Invoke-GuardRun $script:Key }
    Assert-Equal $script:ShutdownCalls 0
}
Test-Case 'Recurring policy disabled during grace is rechecked before shutdown' {
    $dir = Reset-Fixture 'recurring-disabled-during-grace'
    Write-LocalRecord (Join-Path $dir 'recurring-policy.json') (Valid-RecurringPolicy) $script:Key
    $script:MockSessions = @((Valid-Session))
    $script:GraceAction = {
        $policy = Valid-RecurringPolicy; $policy.enabled = $false
        Write-LocalRecord (Join-Path (Get-GuardDirectory) 'recurring-policy.json') $policy $script:Key
    }
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:GraceCalls 1
    Assert-Equal $script:ShutdownCalls 0
}
Test-Case 'Recurring policy disabled during final log is rechecked before OS call' {
    $dir = Reset-Fixture 'recurring-disabled-during-final-log'
    Write-LocalRecord (Join-Path $dir 'recurring-policy.json') (Valid-RecurringPolicy) $script:Key
    $script:MockSessions = @((Valid-Session))
    function Save-Result([string]$Status, [string]$Detail = '') {
        & $script:OriginalSaveResult $Status $Detail
        if ($Status -eq 'shutdown_requesting') {
            $policy = Valid-RecurringPolicy; $policy.enabled = $false
            Write-LocalRecord (Join-Path (Get-GuardDirectory) 'recurring-policy.json') $policy $script:Key
        }
    }
    Invoke-GuardRun $script:Key | Out-Null
    Assert-Equal $script:ShutdownCalls 0
}
Test-Case 'One recurring file permits three distinct nightly boot fixtures without daily ticket writes' {
    $dir = Reset-Fixture 'recurring-three-nights'
    $path = Join-Path $dir 'recurring-policy.json'
    Write-LocalRecord $path (Valid-RecurringPolicy) $script:Key
    $before = [IO.File]::ReadAllText($path)
    $expectedCalls = 0
    foreach ($date in @('2026-11-04','2026-11-05','2026-11-06')) {
        $boot = Unix ($date + 'T03:30:00-05:00')
        $now = Unix ($date + 'T04:44:00-05:00')
        $script:MockBoot = $boot; $script:MockNow = $now
        $s = Valid-Session; $s.logon = $boot + 19; $s.input = $boot + 25; $s.current = $now
        $script:MockSessions = @($s)
        $script:MockData = Valid-Data
        $script:MockData.report_date = $date; $script:MockData.started_utc = $boot + 300
        $script:MockData.completed_utc = $now - 240; $script:MockData.issued_utc = $now
        # Fixture supplies completed early/continuous observations, as in the
        # existing integration tests. It never bypasses runtime policy functions.
        $state = New-BootState ($boot + 40) $boot; $state.last_observed = $now
        Write-LocalRecord (Join-Path $dir 'boot-state.json') $state $script:Key
        Invoke-GuardRun $script:Key | Out-Null
        $expectedCalls++
        Assert-Equal $script:ShutdownCalls $expectedCalls ('Expected intercepted request on ' + $date)
        Assert-Equal ([IO.File]::ReadAllText($path)) $before
        Assert-Equal ([IO.File]::Exists((Join-Path $dir 'unattended-ticket.json'))) $false
    }
}

Test-Case 'Portable machine binding canonicalizes MAC and rejects invalid or non-IPv4 config' {
    $config = [pscustomobject]@{ target_ip = '198.51.100.42'; target_mac = '02:ab:cd:ef:00:02' }
    Assert-Equal (Get-MachineBinding $config) '198.51.100.42|02-AB-CD-EF-00-02'
    foreach ($address in @('not-an-address','999.2.3.4','2001:db8::1')) {
        $bad = Clone $config; $bad.target_ip = $address
        Assert-Throws { Get-MachineBinding $bad }
    }
    $bad = Clone $config; $bad.target_mac = '02:ab:cd:ef:00'
    Assert-Throws { Get-MachineBinding $bad }
    $bad = Clone $config; $bad.target_ip = @('198.51.100.42')
    Assert-Throws { Get-MachineBinding $bad }
}
Test-Case 'A different configured documentation IP and MAC can authorize the intercepted action' {
    $previousConfigPath = $script:ConfigPath
    try {
        $dir = Reset-Fixture 'portable-alternate-target'
        $config = [pscustomobject]@{
            target_ip = '198.51.100.42'; target_mac = '02:ab:cd:ef:00:02'
            status_url = 'http://198.51.100.24:8766/completion'
        }
        [IO.File]::WriteAllText($script:ConfigPath, ($config | ConvertTo-Json -Compress))
        $binding = Get-ConfiguredMachineBinding
        Assert-Equal $binding '198.51.100.42|02-AB-CD-EF-00-02'
        $policy = Valid-RecurringPolicy; $policy.machine = $binding
        Write-LocalRecord (Join-Path $dir 'recurring-policy.json') $policy $script:Key
        Assert-Equal (Get-RecurringReason $policy $script:Now $script:Boot) ''
        $script:MockSessions = @((Valid-Session))
        Invoke-GuardRun $script:Key | Out-Null
        Assert-Equal $script:ShutdownCalls 1
    } finally { $script:ConfigPath = $previousConfigPath }
}
Test-Case 'Changing configured identity blocks an older policy for the previous target' {
    $previousConfigPath = $script:ConfigPath
    try {
        $dir = Reset-Fixture 'portable-identity-changed'
        $policy = Valid-RecurringPolicy
        Write-LocalRecord (Join-Path $dir 'recurring-policy.json') $policy $script:Key
        Assert-Equal (Get-RecurringReason $policy $script:Now $script:Boot) ''
        [IO.File]::WriteAllText($script:ConfigPath, '{"target_ip":"203.0.113.17","target_mac":"02-00-00-00-00-03","status_url":"http://203.0.113.24:8766/completion"}')
        Assert-Blocked { Get-RecurringReason $policy $script:Now $script:Boot } 'Policy for the previous configured target must fail after identity changes.'
        $script:MockSessions = @((Valid-Session))
        Invoke-GuardRun $script:Key | Out-Null
        Assert-Equal $script:ShutdownCalls 0
        Assert-Equal $script:GraceCalls 0
    } finally { $script:ConfigPath = $previousConfigPath }
}

Write-Output ("RESULT: {0} passed, {1} failed; PowerShell {2}; fixtures: {3}" -f $script:Passed, $script:Failed, $PSVersionTable.PSVersion, $script:TestRoot)
if ($script:Failed -gt 0) { exit 1 }
exit 0
