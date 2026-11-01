#requires -Version 5.1
param(
    [switch]$Arm,
    [switch]$Check,
    [switch]$LibraryOnly,
    [string]$ConfigPath = "$env:ProgramData\AiMonitorPower\config.json"
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-UnixNow {
    return [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
}

function Convert-HexBytes([string]$Text) {
    if ($Text -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid pairing key or signature.' }
    $bytes = New-Object byte[] 32
    for ($i = 0; $i -lt 32; $i++) { $bytes[$i] = [Convert]::ToByte($Text.Substring($i * 2, 2), 16) }
    return ,$bytes
}

function Get-Nonce {
    $bytes = New-Object byte[] 32
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($bytes) } finally { $random.Dispose() }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

function Read-SignedCompletion($Envelope, [byte[]]$Key, [string]$Nonce, [long]$Now) {
    if ($Envelope.payload -isnot [string] -or $Envelope.payload.Length -gt 4096) { throw 'Invalid status payload.' }
    $hmac = New-Object Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = $Key
        $actual = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Envelope.payload))
    } finally { $hmac.Dispose() }
    $expected = Convert-HexBytes $Envelope.signature
    $difference = 0
    for ($i = 0; $i -lt 32; $i++) { $difference = $difference -bor ($actual[$i] -bxor $expected[$i]) }
    if ($difference -ne 0) { throw 'Status signature does not match the pairing key.' }
    $data = $Envelope.payload | ConvertFrom-Json
    if ($data.version -ne 1 -or $data.nonce -cne $Nonce -or
        [Math]::Abs($Now - [long]$data.issued_utc) -gt 30 -or $data.ready -isnot [bool]) {
        throw 'Status has an invalid version, nonce, timestamp or ready field.'
    }
    return $data
}

function Get-Completion($Config, [byte[]]$Key) {
    if ($Config.status_url -notmatch '^http://[0-9.]+:8766/completion$') { throw 'Use the configured coordinator IPv4 address on port 8766.' }
    $nonce = Get-Nonce
    $request = [Net.HttpWebRequest]::Create($Config.status_url + '?nonce=' + $nonce)
    $request.Proxy = $null
    $request.AllowAutoRedirect = $false
    $request.Timeout = 5000
    $request.ReadWriteTimeout = 5000
    $response = $null
    $reader = $null
    try {
        $response = $request.GetResponse()
        if ([int]$response.StatusCode -ne 200 -or $response.ContentLength -lt 0 -or $response.ContentLength -gt 8192) {
            throw 'Invalid coordinator response.'
        }
        $reader = New-Object IO.StreamReader($response.GetResponseStream(), [Text.Encoding]::UTF8)
        $characters = New-Object char[] 8193
        $count = $reader.ReadBlock($characters, 0, $characters.Length)
        if ($count -gt 8192) { throw 'Coordinator response is too large.' }
        $envelope = ([string]::new($characters, 0, $count)) | ConvertFrom-Json
        return Read-SignedCompletion $envelope $Key $nonce (Get-UnixNow)
    } finally {
        if ($reader) { $reader.Dispose() }
        if ($response) { $response.Dispose() }
    }
}

function Get-InteractiveSessions {
    if (-not ('AiMonitorPower.Sessions' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace AiMonitorPower {
    public static class Sessions {
        [StructLayout(LayoutKind.Sequential)]
        private struct Info { public int Id; public IntPtr Station; public int State; }
        [DllImport("wtsapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        private static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr info, out int count);
        [DllImport("wtsapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        private static extern bool WTSQuerySessionInformationW(IntPtr server, int id, int field, out IntPtr buffer, out int bytes);
        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr memory);
        public static string[] Users() {
            IntPtr buffer = IntPtr.Zero;
            int count;
            if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out buffer, out count))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var users = new List<string>();
            try {
                int size = Marshal.SizeOf(typeof(Info));
                for (int i = 0; i < count; i++) {
                    Info session = (Info)Marshal.PtrToStructure(IntPtr.Add(buffer, i * size), typeof(Info));
                    if (session.Id == 0 || session.State == 6) continue; // services and listeners
                    IntPtr name = IntPtr.Zero;
                    int bytes;
                    if (!WTSQuerySessionInformationW(IntPtr.Zero, session.Id, 5, out name, out bytes))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    try {
                        string user = Marshal.PtrToStringUni(name);
                        // All named sessions count, including locked and disconnected sessions.
                        if (!String.IsNullOrWhiteSpace(user)) users.Add(user);
                    } finally { if (name != IntPtr.Zero) WTSFreeMemory(name); }
                }
            } finally { if (buffer != IntPtr.Zero) WTSFreeMemory(buffer); }
            return users.ToArray();
        }
    }
}
'@
    }
    return @([AiMonitorPower.Sessions]::Users())
}

function Test-TargetComputer($Config) {
    $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object IPAddress -eq $Config.target_ip)
    foreach ($address in $addresses) {
        $adapter = Get-NetAdapter -InterfaceIndex $address.InterfaceIndex -ErrorAction Stop
        if ($adapter.MacAddress.Replace(':','-').ToUpperInvariant() -eq $Config.target_mac) { return $true }
    }
    return $false
}

function Get-BlockReason($Data, [long]$Now, [long]$Boot, [int]$SessionCount) {
    $zone = [TimeZoneInfo]::FindSystemTimeZoneById('Eastern Standard Time')
    $local = [TimeZoneInfo]::ConvertTime([DateTimeOffset]::FromUnixTimeSeconds($Now), $zone)
    if ($local.Hour -lt 4 -or $local.Hour -ge 6) { return 'outside_04_to_06_New_York' }
    if ($SessionCount -gt 0) { return 'user_logged_in' }
    if ($Data.ready -cne $true) { return 'report_not_ready' }
    if ($Data.report_date -cne $local.ToString('yyyy-MM-dd')) { return 'wrong_report_date' }
    if ([long]$Data.started_utc -lt $Boot) { return 'report_started_before_this_boot' }
    if ([long]$Data.completed_utc -lt [long]$Data.started_utc -or
        $Now - [long]$Data.completed_utc -gt 7200 -or [long]$Data.completed_utc -gt $Now) { return 'invalid_report_time' }
    return ''
}

function Wait-LoggedOutGrace([int]$Seconds = 60, [scriptblock]$ReadSessions = { @(Get-InteractiveSessions).Count },
                             [scriptblock]$Pause = { Start-Sleep -Seconds 1 }) {
    for ($i = 0; $i -lt $Seconds; $i++) {
        if ((& $ReadSessions) -gt 0) { return $false }
        & $Pause
    }
    return ((& $ReadSessions) -eq 0)
}

function Save-Result([string]$Status, [string]$Detail = '') {
    $value = [ordered]@{ checked_utc = [DateTimeOffset]::UtcNow.ToString('o'); status = $Status; detail = $Detail }
    $directory = Split-Path -Parent $ConfigPath
    $json = $value | ConvertTo-Json -Compress
    [IO.File]::WriteAllText((Join-Path $directory 'last-result.json'), $json, [Text.UTF8Encoding]::new($false))
    Write-Output $json
}

function Invoke-PowerGuard {
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    if (-not (Test-TargetComputer $config)) { throw 'This is not the configured Ollama PC. No shutdown is permitted.' }
    Add-Type -AssemblyName System.Security
    $keyFile = Join-Path (Split-Path -Parent $ConfigPath) 'pairing-key.dpapi'
    $key = [Security.Cryptography.ProtectedData]::Unprotect(
        [IO.File]::ReadAllBytes($keyFile), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    $sessions = @(Get-InteractiveSessions)
    $bootTime = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
    $boot = ([DateTimeOffset]$bootTime.ToUniversalTime()).ToUnixTimeSeconds()
    $data = Get-Completion $config $key
    $reason = Get-BlockReason $data (Get-UnixNow) $boot $sessions.Count
    if ($Check -or -not $Arm) {
        Save-Result 'check_only' ('signature_verified; logged_in_sessions=' + $sessions.Count + '; block=' + $reason)
        return
    }
    if ($reason) { Save-Result 'skipped' $reason; return }
    if (-not (Wait-LoggedOutGrace)) { Save-Result 'skipped' 'user_logged_in_during_grace'; return }
    # Refresh completion after the grace period, then recheck sessions last.
    $data = Get-Completion $config $key
    $reason = Get-BlockReason $data (Get-UnixNow) $boot (@(Get-InteractiveSessions).Count)
    if ($reason) { Save-Result 'skipped' $reason; return }
    Save-Result 'shutdown_requested' 'verified_report_complete_and_no_logged_in_users'
    if (@(Get-InteractiveSessions).Count -gt 0) { Save-Result 'skipped' 'user_logged_in_at_final_check'; return }
    # No /f. A positive shutdown.exe timeout implicitly forces applications;
    # use our own cancellable grace period above instead.
    & "$env:SystemRoot\System32\shutdown.exe" /s /t 0 /d p:0:0 /c 'AI log report completed; no users logged in.'
    if ($LASTEXITCODE -ne 0) { throw ('Windows rejected shutdown; exit=' + $LASTEXITCODE) }
}

if (-not $LibraryOnly) {
    try { Invoke-PowerGuard }
    catch {
        $message = $_.Exception.Message
        try { Save-Result 'blocked_error' $message } catch { Write-Error $message }
        exit 1
    }
}
