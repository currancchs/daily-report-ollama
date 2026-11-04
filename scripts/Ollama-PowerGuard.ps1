#requires -Version 5.1
# PowerGuard v2.1: explicit recurring locked-console policy; default remains no users.
param(
    [switch]$Arm,
    [switch]$Check,
    [switch]$LibraryOnly,
    [string]$ConfigPath = "$env:ProgramData\AiMonitorPower\config.json",
    [switch]$AuthorizeNextBoot,
    [switch]$EnableRecurring,
    [switch]$DisableRecurring,
    [string]$ExpectedBootDate,
    [string]$ConsoleAccount
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$script:GuardVersion = '2.1.0'
$script:DecisionContext = [ordered]@{ boot_origin = 'unknown' }



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

function Test-TargetComputer($Config) {
    $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object IPAddress -eq $Config.target_ip)
    foreach ($address in $addresses) {
        $adapter = Get-NetAdapter -InterfaceIndex $address.InterfaceIndex -ErrorAction Stop
        if ($adapter.MacAddress.Replace(':','-').ToUpperInvariant() -eq $Config.target_mac) { return $true }
    }
    return $false
}

function Get-MachineBinding($Config) {
    if ($Config.target_ip -isnot [string] -or $Config.target_mac -isnot [string]) {
        throw 'The configured target IPv4 address and MAC must be strings.'
    }
    $address = [Net.IPAddress]::Parse($Config.target_ip)
    if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'The configured target must use an IPv4 address.'
    }
    $mac = $Config.target_mac.Replace(':', '-').ToUpperInvariant()
    if ($mac -notmatch '^(?:[0-9A-F]{2}-){5}[0-9A-F]{2}$') {
        throw 'The configured target MAC address is invalid.'
    }
    return ($address.ToString() + '|' + $mac)
}

function Get-ConfiguredMachineBinding {
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    return (Get-MachineBinding $config)
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

function Get-InteractiveSessions {
    if (-not ('AiMonitorPowerV2.Sessions' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace AiMonitorPowerV2
{
    public sealed class SessionSnapshot
    {
        public int Id;
        public string User;
        public string Domain;
        public int State;
        public int Protocol;
        // WTS_SESSIONSTATE_LOCK=0, UNLOCK=1, UNKNOWN=-1.
        public int LockState;
        public long LogonFileTime;
        public long LastInputFileTime;
        public long CurrentFileTime;
        public long DisconnectFileTime;
    }

    // Read-only WTS interop. Does not log off users or shut down the machine.
    public static class Sessions
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct SessionInfo
        {
            public int Id;
            public IntPtr Station;
            public int State;
        }

        // WtsApi32.h: WINSTATIONNAME_LENGTH=32, USERNAME_LENGTH=20,
        // DOMAIN_LENGTH=17. Native default packing is 8, including x86.
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode, Pack=8)]
        private struct ExtendedLevel1
        {
            public uint SessionId;
            public int SessionState;
            public int SessionFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst=33)]
            public string WinStationName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst=21)]
            public string UserName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst=18)]
            public string DomainName;
            public long LogonTime;
            public long ConnectTime;
            public long DisconnectTime;
            public long LastInputTime;
            public long CurrentTime;
            public uint IncomingBytes;
            public uint OutgoingBytes;
            public uint IncomingFrames;
            public uint OutgoingFrames;
            public uint IncomingCompressedBytes;
            public uint OutgoingCompressedBytes;
        }

        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode, Pack=8)]
        private struct ExtendedInfo
        {
            public uint Level;
            public ExtendedLevel1 Data;
        }

        [DllImport("wtsapi32.dll", ExactSpelling=true, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved,
            int version, out IntPtr info, out int count);

        [DllImport("wtsapi32.dll", ExactSpelling=true, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSQuerySessionInformationW(IntPtr server, int id,
            int field, out IntPtr buffer, out int bytes);

        [DllImport("wtsapi32.dll", ExactSpelling=true)]
        private static extern void WTSFreeMemory(IntPtr memory);

        private static InvalidOperationException Invalid(string detail)
        {
            return new InvalidOperationException("Uncertain WTS session evidence: " + detail);
        }

        private static IntPtr Query(int id, int field, int minimum, out int bytes)
        {
            IntPtr buffer = IntPtr.Zero;
            if (!WTSQuerySessionInformationW(IntPtr.Zero, id, field, out buffer, out bytes))
            {
                int error = Marshal.GetLastWin32Error();
                if (buffer != IntPtr.Zero) WTSFreeMemory(buffer);
                throw new Win32Exception(error, "WTS session query failed; shutdown must remain blocked.");
            }
            if (buffer == IntPtr.Zero || bytes < minimum || bytes > 65536)
            {
                if (buffer != IntPtr.Zero) WTSFreeMemory(buffer);
                throw Invalid("missing or invalid query buffer");
            }
            return buffer;
        }

        private static string QueryString(int id, int field)
        {
            int bytes;
            IntPtr buffer = Query(id, field, 2, out bytes);
            try
            {
                if ((bytes % 2) != 0) throw Invalid("odd Unicode buffer length");
                string text = Marshal.PtrToStringUni(buffer, bytes / 2);
                int end = text.IndexOf('\0');
                if (end < 0) throw Invalid("unterminated Unicode field");
                return text.Substring(0, end);
            }
            finally { WTSFreeMemory(buffer); }
        }

        private static int QueryProtocol(int id)
        {
            int bytes;
            IntPtr buffer = Query(id, 16, 2, out bytes); // WTSClientProtocolType
            try { return (int)(ushort)Marshal.ReadInt16(buffer); }
            finally { WTSFreeMemory(buffer); }
        }

        private static ExtendedInfo QueryExtended(int id)
        {
            int bytes;
            IntPtr buffer = Query(id, 25, Marshal.SizeOf(typeof(ExtendedInfo)), out bytes);
            try
            {
                ExtendedInfo info = (ExtendedInfo)Marshal.PtrToStructure(buffer, typeof(ExtendedInfo));
                if (info.Level != 1 || info.Data.SessionId != (uint)id)
                    throw Invalid("unexpected extended-info level or session identity");
                return info;
            }
            finally { WTSFreeMemory(buffer); }
        }

        private static Dictionary<int, int> Enumerate()
        {
            IntPtr buffer = IntPtr.Zero;
            int count;
            if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out buffer, out count))
            {
                int error = Marshal.GetLastWin32Error();
                if (buffer != IntPtr.Zero) WTSFreeMemory(buffer);
                throw new Win32Exception(error, "WTS enumeration failed; shutdown must remain blocked.");
            }
            try
            {
                if (count < 1 || count > 4096 || buffer == IntPtr.Zero)
                    throw Invalid("empty or invalid enumeration");
                var sessions = new Dictionary<int, int>();
                int size = Marshal.SizeOf(typeof(SessionInfo));
                for (int i = 0; i < count; i++)
                {
                    SessionInfo item = (SessionInfo)Marshal.PtrToStructure(
                        IntPtr.Add(buffer, checked(i * size)), typeof(SessionInfo));
                    if (item.Id < 0 || item.State < 0 || item.State > 9)
                        throw Invalid("unknown session identity or connection state");
                    if (item.Id == 0 || item.State == 6) continue; // Services / listeners.
                    if (sessions.ContainsKey(item.Id)) throw Invalid("duplicate session identity");
                    sessions.Add(item.Id, item.State);
                }
                return sessions;
            }
            finally { if (buffer != IntPtr.Zero) WTSFreeMemory(buffer); }
        }

        private static SessionSnapshot ReadOne(int id, int expectedState)
        {
            string user = QueryString(id, 5); // WTSUserName
            string domain = QueryString(id, 7); // WTSDomainName
            int protocol = QueryProtocol(id);
            ExtendedLevel1 info = QueryExtended(id).Data;
            if (info.SessionState != expectedState ||
                !String.Equals(user, info.UserName, StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(domain, info.DomainName, StringComparison.OrdinalIgnoreCase))
                throw Invalid("session changed during query or identity fields disagree");
            if (String.IsNullOrWhiteSpace(user))
            {
                // Only a stable, unnamed local connected session with no logon
                // timestamp is recognized as a pre-logon console. An unnamed
                // active/RDP/disconnected/transitioning session remains unknown.
                if (user.Length != 0 || domain.Length != 0 || protocol != 0 ||
                    expectedState != 1 || info.LogonTime != 0)
                    throw Invalid("unnamed session is not a recognized pre-logon console");
            }
            return new SessionSnapshot {
                Id=id, User=user, Domain=domain, State=info.SessionState,
                Protocol=protocol, LockState=info.SessionFlags,
                LogonFileTime=info.LogonTime, LastInputFileTime=info.LastInputTime,
                CurrentFileTime=info.CurrentTime, DisconnectFileTime=info.DisconnectTime
            };
        }

        public static SessionSnapshot[] Read()
        {
            // Windows 7 / Server 2008 R2 reverse the documented lock flags.
            // Refuse those systems rather than interpreting a locked session
            // incorrectly. Version virtualization to Windows 8 remains safe.
            Version os = Environment.OSVersion.Version;
            if (os.Major < 6 || (os.Major == 6 && os.Minor < 2))
                throw Invalid("Windows 8 / Server 2012 or newer is required");
            // These assertions prevent accidental structure edits from silently
            // producing convincing but incorrect timestamps or lock flags.
            if (Marshal.SizeOf(typeof(ExtendedLevel1)) != 224 ||
                Marshal.OffsetOf(typeof(ExtendedLevel1), "LogonTime").ToInt32() != 160 ||
                Marshal.SizeOf(typeof(ExtendedInfo)) != 232 ||
                Marshal.OffsetOf(typeof(ExtendedInfo), "Data").ToInt32() != 8)
                throw Invalid("unsupported native structure layout");

            Dictionary<int, int> before = Enumerate();
            var first = new Dictionary<int, SessionSnapshot>();
            foreach (KeyValuePair<int, int> session in before)
                first.Add(session.Key, ReadOne(session.Key, session.Value));
            Dictionary<int, int> after = Enumerate();
            if (before.Count != after.Count) throw Invalid("session roster changed");
            var result = new List<SessionSnapshot>();
            foreach (KeyValuePair<int, int> session in after)
            {
                SessionSnapshot earlier;
                if (!first.TryGetValue(session.Key, out earlier) || earlier.State != session.Value)
                    throw Invalid("session roster or connection state changed");
                SessionSnapshot latest = ReadOne(session.Key, session.Value);
                if (earlier.LogonFileTime != latest.LogonFileTime ||
                    earlier.LockState != latest.LockState || earlier.Protocol != latest.Protocol ||
                    !String.Equals(earlier.User, latest.User, StringComparison.OrdinalIgnoreCase) ||
                    !String.Equals(earlier.Domain, latest.Domain, StringComparison.OrdinalIgnoreCase))
                    throw Invalid("session identity, lock, or protocol changed");
                // Valid pre-logon console entries are checked but are not users.
                if (latest.User.Length != 0) result.Add(latest);
            }
            result.Sort(delegate(SessionSnapshot a, SessionSnapshot b) { return a.Id.CompareTo(b.Id); });
            return result.ToArray();
        }
    }
}

'@
    }
    return @([AiMonitorPowerV2.Sessions]::Read())
}


function Get-BootUnix {
    $time = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
    return ([DateTimeOffset]$time.ToUniversalTime()).ToUnixTimeSeconds()
}

function Get-GuardDirectory { return (Split-Path -Parent $ConfigPath) }

function Write-AtomicText([string]$Path, [string]$Text) {
    $temp = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
        $stream = [IO.File]::Open($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temp, $Path, [Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($temp, $Path) }
    } finally { if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) } }
}

# Domain-separated local HMAC records use the existing key; the coordinator's
# signing/validation functions above are unchanged. No pairing files are written.
function Get-LocalRecordSignature([string]$Payload, [byte[]]$Key) {
    $hmac = New-Object Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = $Key
        $bytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes("PowerGuard-local-v2`n" + $Payload))
        return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
    } finally { $hmac.Dispose() }
}

function Write-LocalRecord([string]$Path, $Data, [byte[]]$Key) {
    $payload = $Data | ConvertTo-Json -Depth 8 -Compress
    $record = [ordered]@{ payload = $payload; signature = (Get-LocalRecordSignature $payload $Key) }
    Write-AtomicText $Path ($record | ConvertTo-Json -Compress)
}

function Read-LocalRecord([string]$Path, [string]$Purpose, [byte[]]$Key) {
    if (-not [IO.File]::Exists($Path)) { return $null }
    if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -gt 32768) { throw 'Local state is oversized.' }
    $record = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    if ($record.payload -isnot [string]) { throw 'Invalid local state payload.' }
    $expected = Convert-HexBytes $record.signature
    $actual = Convert-HexBytes (Get-LocalRecordSignature $record.payload $Key)
    $difference = 0
    for ($i = 0; $i -lt 32; $i++) { $difference = $difference -bor ($actual[$i] -bxor $expected[$i]) }
    if ($difference -ne 0) { throw 'Local state authentication failed.' }
    $data = $record.payload | ConvertFrom-Json
    if ($data.version -ne 2 -or $data.purpose -cne $Purpose) { throw 'Unexpected local state purpose/version.' }
    return $data
}

function Save-Result([string]$Status, [string]$Detail = '') {
    $now = [DateTimeOffset]::UtcNow
    $eastern = [TimeZoneInfo]::ConvertTime($now, [TimeZoneInfo]::FindSystemTimeZoneById('Eastern Standard Time'))
    $value = [ordered]@{
        checked_utc = $now.ToString('o'); checked_eastern = $eastern.ToString('o')
        version = $script:GuardVersion; status = $Status; detail = $Detail
        mode = $(if ($Check -or -not $Arm) { 'check' } else { 'armed' })
        evidence = $script:DecisionContext
    }
    $directory = Get-GuardDirectory
    $json = $value | ConvertTo-Json -Depth 10 -Compress
    # Daily append-only files retain all decisions; no automatic deletion.
    $path = Join-Path $directory ('decisions-' + $now.ToString('yyyy-MM-dd') + '.jsonl')
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + "`r`n")
    $stream = [IO.File]::Open($path, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    Write-AtomicText (Join-Path $directory 'last-result.json') $json
    Write-Output $json
}

function Get-UserSid($Session) {
    $name = $Session.User
    if ($Session.Domain) { $name = $Session.Domain + '\' + $Session.User }
    return ([Security.Principal.NTAccount]::new($name)).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Convert-FileTimeUnix([long]$Value) {
    if ($Value -le 0) { throw 'Missing per-session timestamp.' }
    return ([DateTimeOffset][DateTime]::FromFileTimeUtc($Value)).ToUnixTimeSeconds()
}

function Get-SessionEvidence {
    $result = @()
    foreach ($s in @(Get-InteractiveSessions)) {
        # Conversion failures are errors, never zero idle or assumed inactivity.
        $result += [pscustomobject][ordered]@{
            id = $s.Id; user = $s.User; domain = $s.Domain; sid = (Get-UserSid $s)
            state = $s.State; protocol = $s.Protocol; lock = $s.LockState
            logon = (Convert-FileTimeUnix $s.LogonFileTime)
            input = (Convert-FileTimeUnix $s.LastInputFileTime)
            input_stamp = $s.LastInputFileTime
            current = (Convert-FileTimeUnix $s.CurrentFileTime)
        }
    }
    return $result
}

function Get-ObservationProblem($Sessions, [long]$Now, [long]$Boot) {
    if ($Now -lt $Boot) { return 'clock_before_boot' }
    if (@($Sessions).Count -gt 1) { return 'multiple_users' }
    foreach ($s in $Sessions) {
        if ($s.protocol -eq 2) { return 'rdp_session_present' }
        if ($s.protocol -ne 0 -or $s.state -ne 0) { return 'console_not_active_or_protocol_unknown' }
        if ($s.lock -ne 0) { return 'console_unlocked_or_lock_unknown' }
        if ($s.logon -lt $Boot -or $s.logon -gt $Boot + 120) { return 'console_not_created_at_boot' }
        if ($s.input -lt $s.logon -or $s.input -gt $s.current -or
            $s.current -lt $Boot -or [Math]::Abs($Now - $s.current) -gt 15) { return 'invalid_session_timestamps' }
        if ($s.input -gt $Boot + 120) { return 'input_after_boot_startup' }
    }
    return ''
}

function New-BootState([long]$Now, [long]$Boot) {
    return [pscustomobject][ordered]@{
        version = 2; purpose = 'boot-state'; boot = $Boot
        first_observed = $Now; last_observed = $Now
        veto = $(if ($Now -lt $Boot -or $Now - $Boot -gt 120) { 'observation_started_late' } else { '' })
        session_key = ''; input_marker = [long]0; attempt = $false
    }
}

function Update-BootState($State, $Sessions, [long]$Now, [long]$Boot) {
    if ($State.boot -ne $Boot) { throw 'Boot identity changed.' }
    if ($State.last_observed -gt $Now -or $Now - $State.last_observed -gt 150) {
        if (-not $State.veto) { $State.veto = 'observation_gap_or_clock_change' }
    }
    $problem = Get-ObservationProblem $Sessions $Now $Boot
    if ($problem -and -not $State.veto) { $State.veto = $problem }
    if (@($Sessions).Count -eq 1) {
        $s = $Sessions[0]
        $sessionKey = [string]$s.id + ':' + $s.sid + ':' + [string]$s.logon
        if ($State.session_key -and $State.session_key -cne $sessionKey -and -not $State.veto) {
            $State.veto = 'console_session_changed'
        }
        if ($State.input_marker -ne 0 -and $State.input_marker -ne $s.input_stamp -and -not $State.veto) {
            $State.veto = 'input_changed_since_first_observation'
        }
        if (-not $State.session_key) { $State.session_key = $sessionKey; $State.input_marker = $s.input_stamp }
    } elseif ($State.session_key -and -not $State.veto) { $State.veto = 'console_session_disappeared' }
    $State.last_observed = $Now
    return $State
}

function Get-TicketReason($Ticket, [long]$Now, [long]$Boot) {
    if ($null -eq $Ticket) { return 'no_unattended_authorization' }
    if ($Ticket.PSObject.Properties['purpose'] -and $Ticket.purpose -ceq 'recurring-policy') {
        return (Get-RecurringReason $Ticket $Now $Boot)
    }
    if ($Ticket.machine -cne (Get-ConfiguredMachineBinding)) { return 'ticket_wrong_machine' }
    if ($Ticket.bound_boot -ne $Boot) { return 'ticket_not_bound_to_this_boot' }
    if ($Ticket.issued_boot -ge $Boot -or $Ticket.issued -ge $Boot -or $Ticket.issued -ge $Ticket.boot_start) {
        return 'ticket_not_created_before_boot'
    }
    if ($Boot -lt $Ticket.boot_start -or $Boot -ge $Ticket.boot_end) { return 'boot_outside_authorized_window' }
    if ($Now -ge $Ticket.expires -or $Now -lt $Ticket.issued) { return 'ticket_expired_or_clock_invalid' }
    if ($Ticket.allowed_sid -notmatch '^S-1-5-') { return 'ticket_invalid_user' }
    return ''
}

function Get-RecurringReason($Policy, [long]$Now, [long]$Boot) {
    if (($Policy.version -isnot [int] -and $Policy.version -isnot [long]) -or
        $Policy.version -ne 2 -or $Policy.purpose -isnot [string] -or
        $Policy.purpose -cne 'recurring-policy') { return 'invalid_recurring_policy' }
    if ($Policy.enabled -isnot [bool]) { return 'invalid_recurring_enabled_field' }
    if (-not $Policy.enabled) { return 'recurring_policy_disabled' }
    if ($Policy.machine -isnot [string] -or $Policy.machine -cne (Get-ConfiguredMachineBinding)) { return 'recurring_policy_wrong_machine' }
    if ($Policy.allowed_sid -isnot [string] -or $Policy.allowed_sid -notmatch '^S-1-5-') { return 'recurring_policy_invalid_user' }
    foreach ($field in @('created','created_boot','boot_start_minute','boot_end_minute')) {
        $value = $Policy.$field
        if ($value -isnot [int] -and $value -isnot [long]) { return 'invalid_recurring_numeric_field' }
    }
    if ($Policy.boot_start_minute -ne 200 -or $Policy.boot_end_minute -ne 225) { return 'unexpected_recurring_boot_window' }
    if ($Policy.created -le 0 -or $Policy.created_boot -le 0 -or $Policy.created_boot -gt $Policy.created -or
        $Policy.created -gt $Now -or $Now -lt $Boot) { return 'invalid_recurring_creation_time' }
    if ($Policy.created -ge $Boot -or $Policy.created_boot -ge $Boot) { return 'recurring_policy_requires_later_boot' }
    $zone = [TimeZoneInfo]::FindSystemTimeZoneById('Eastern Standard Time')
    $localBoot = [TimeZoneInfo]::ConvertTime([DateTimeOffset]::FromUnixTimeSeconds($Boot), $zone)
    $localNow = [TimeZoneInfo]::ConvertTime([DateTimeOffset]::FromUnixTimeSeconds($Now), $zone)
    if ($localNow.ToString('yyyy-MM-dd') -cne $localBoot.ToString('yyyy-MM-dd')) { return 'recurring_boot_not_today_Eastern' }
    $minute = $localBoot.TimeOfDay.TotalMinutes
    if ($minute -lt 200 -or $minute -ge 225) { return 'boot_outside_recurring_0320_to_0345_Eastern' }
    return ''
}

function Get-GuardAuthorization([byte[]]$Key, [long]$Boot) {
    $directory = Get-GuardDirectory
    $policyPath = Join-Path $directory 'recurring-policy.json'
    # A disabled, invalid, or unreadable policy must never revive an old ticket.
    if (Test-Path -LiteralPath $policyPath -ErrorAction Stop) {
        $policy = Read-LocalRecord $policyPath 'recurring-policy' $Key
        if ($null -eq $policy) { throw 'Recurring policy exists but cannot be read as an authenticated file.' }
        $script:DecisionContext['authorization_mode'] = 'recurring'
        return $policy
    }
    $ticketPath = Join-Path $directory 'unattended-ticket.json'
    $ticket = Read-LocalRecord $ticketPath 'unattended-ticket' $Key
    if ($null -ne $ticket -and $ticket.bound_boot -eq 0 -and $ticket.issued_boot -ne $Boot) {
        $ticket.bound_boot = $Boot
        Write-LocalRecord $ticketPath $ticket $Key
    }
    $script:DecisionContext['authorization_mode'] = $(if ($null -eq $ticket) { 'none' } else { 'one_night' })
    return $ticket
}

function Set-RecurringPolicy([byte[]]$Key, [long]$Boot) {
    if ($Arm -or $Check -or $AuthorizeNextBoot -or ($EnableRecurring -and $DisableRecurring)) {
        throw 'Choose exactly one policy operation, without -Arm, -Check or -AuthorizeNextBoot.'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Recurring policy changes require an elevated Windows PowerShell prompt.'
    }
    $path = Join-Path (Get-GuardDirectory) 'recurring-policy.json'
    if ($DisableRecurring) {
        $policy = Read-LocalRecord $path 'recurring-policy' $Key
        if ($null -eq $policy) { throw 'There is no recurring policy to disable.' }
        $policy.enabled = $false
        Write-LocalRecord $path $policy $Key
        Save-Result 'recurring_policy_disabled' 'signed_in_exception_disabled; original_no_user_policy_unchanged'
        return
    }
    if (-not $ConsoleAccount) { throw '-ConsoleAccount is required.' }
    $sid = ([Security.Principal.NTAccount]::new($ConsoleAccount)).Translate([Security.Principal.SecurityIdentifier]).Value
    $policy = [pscustomobject][ordered]@{
        version = 2; purpose = 'recurring-policy'; enabled = $true
        machine = (Get-ConfiguredMachineBinding); allowed_sid = $sid
        created = (Get-UnixNow); created_boot = $Boot
        boot_start_minute = 200; boot_end_minute = 225
    }
    Write-LocalRecord $path $policy $Key
    $script:DecisionContext['authorization_mode'] = 'recurring'
    Save-Result 'recurring_policy_enabled' 'daily_Eastern_boot_03:20-03:45; future_boots_only; locked_console_only; no_daily_ticket_required'
}

function Get-SessionBlockReason($Sessions, $State, $Ticket, [long]$Now, [long]$Boot) {
    # Preserve the original logged-out path. Sticky vetoes restrict only the new
    # signed-in-console exception, never redefine RDP disconnection as logoff.
    if (@($Sessions).Count -eq 0) { return '' }
    $problem = Get-ObservationProblem $Sessions $Now $Boot
    if ($problem) { return $problem }
    $reason = Get-TicketReason $Ticket $Now $Boot
    if ($reason) { return $reason }
    if ($State.veto) { return ('boot_veto:' + $State.veto) }
    if ($State.boot -ne $Boot -or $State.first_observed -gt $Boot + 120 -or
        $State.last_observed -ne $Now) { return 'incomplete_boot_observations' }
    $s = $Sessions[0]
    if ($s.sid -cne $Ticket.allowed_sid) { return 'console_user_not_authorized' }
    if ($s.current - $s.input -lt 3600 -or $Now - $State.first_observed -lt 3600) {
        return 'inactivity_or_observation_less_than_60_minutes'
    }
    return ''
}

function New-UnattendedTicket([byte[]]$Key, [long]$Boot) {
    if ($Arm -or $Check) { throw 'Authorization cannot be combined with -Arm or -Check.' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run next-boot authorization from an elevated Windows PowerShell prompt.'
    }
    if (-not $ConsoleAccount) { throw '-ConsoleAccount is required; for example DOMAIN\User.' }
    $sid = ([Security.Principal.NTAccount]::new($ConsoleAccount)).Translate([Security.Principal.SecurityIdentifier]).Value
    $date = [DateTime]::ParseExact($ExpectedBootDate, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    $zone = [TimeZoneInfo]::FindSystemTimeZoneById('Eastern Standard Time')
    $start = [DateTime]::SpecifyKind($date.AddHours(3).AddMinutes(20), [DateTimeKind]::Unspecified)
    $end = $start.AddMinutes(25)
    $expiry = [DateTime]::SpecifyKind($date.AddHours(6), [DateTimeKind]::Unspecified)
    $startUnix = ([DateTimeOffset][TimeZoneInfo]::ConvertTimeToUtc($start, $zone)).ToUnixTimeSeconds()
    $now = Get-UnixNow
    if ($startUnix -le $now -or $startUnix - $now -gt 172800) { throw 'Choose a future boot date within 48 hours.' }
    $ticket = [pscustomobject][ordered]@{
        version = 2; purpose = 'unattended-ticket'; id = [Guid]::NewGuid().ToString('N')
        machine = (Get-ConfiguredMachineBinding); issued = $now; issued_boot = $Boot
        expected_date = $ExpectedBootDate; allowed_sid = $sid; bound_boot = [long]0
        boot_start = $startUnix
        boot_end = ([DateTimeOffset][TimeZoneInfo]::ConvertTimeToUtc($end, $zone)).ToUnixTimeSeconds()
        expires = ([DateTimeOffset][TimeZoneInfo]::ConvertTimeToUtc($expiry, $zone)).ToUnixTimeSeconds()
    }
    Write-LocalRecord (Join-Path (Get-GuardDirectory) 'unattended-ticket.json') $ticket $Key
    Save-Result 'authorization_created' ('next_boot_date=' + $ExpectedBootDate + '; Eastern_boot_window=03:20-03:45; locked_console_only')
}

function Observe-Guard($State, [byte[]]$Key, [long]$Boot) {
    $now = Get-UnixNow
    try { $sessions = @(Get-SessionEvidence) }
    catch {
        if (-not $State.veto) { $State.veto = 'session_query_failed' }
        $State.last_observed = $now
        Write-LocalRecord (Join-Path (Get-GuardDirectory) 'boot-state.json') $State $Key
        throw
    }
    $State = Update-BootState $State $sessions $now $Boot
    Write-LocalRecord (Join-Path (Get-GuardDirectory) 'boot-state.json') $State $Key
    $script:DecisionContext['boot_utc'] = $Boot
    $script:DecisionContext['sessions'] = $sessions
    $script:DecisionContext['boot_veto'] = $State.veto
    return [pscustomobject]@{ state = $State; sessions = $sessions; now = $now }
}

function Get-AllBlockReason($Data, $Observation, $Ticket, [long]$Boot) {
    $script:DecisionContext['session_block'] = Get-SessionBlockReason $Observation.sessions $Observation.state $Ticket $Observation.now $Boot
    $script:DecisionContext['report_block'] = Get-BlockReason $Data $Observation.now $Boot 0
    if (Test-Path -LiteralPath (Join-Path (Get-GuardDirectory) 'shutdown-disabled')) { return 'shutdown_disabled_by_file' }
    if ($Observation.state.attempt) { return 'shutdown_already_attempted_this_boot' }
    $reason = Get-BlockReason $Data $Observation.now $Boot 0
    if ($reason) { return $reason }
    return (Get-SessionBlockReason $Observation.sessions $Observation.state $Ticket $Observation.now $Boot)
}

function Invoke-ShutdownRequest {
    # This is the only shutdown action. No forced retry, sign-out, or app killing.
    & "$env:SystemRoot\System32\shutdown.exe" /s /t 0 /d p:0:0 /c 'AI report verified; PowerGuard safety checks passed.'
    if ($LASTEXITCODE -ne 0) { throw ('Windows rejected shutdown; exit=' + $LASTEXITCODE) }
}

function Wait-GuardGrace($Observation, $Ticket, $Data, [byte[]]$Key, [long]$Boot, [int]$Seconds = 60) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt $Seconds) {
        Start-Sleep -Seconds 1
        $Observation = Observe-Guard $Observation.state $Key $Boot
        $reason = Get-AllBlockReason $Data $Observation $Ticket $Boot
        if ($reason) { return [pscustomobject]@{ observation = $Observation; reason = $reason } }
    }
    return [pscustomobject]@{ observation = $Observation; reason = '' }
}

function Invoke-GuardRun([byte[]]$Key) {
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $null = Get-MachineBinding $config
    $boot = Get-BootUnix
    if ($EnableRecurring -or $DisableRecurring) { Set-RecurringPolicy $Key $boot; return }
    if ($AuthorizeNextBoot) { New-UnattendedTicket $Key $boot; return }
    $directory = Get-GuardDirectory
    $statePath = Join-Path $directory 'boot-state.json'
    $state = Read-LocalRecord $statePath 'boot-state' $Key
    if ($null -eq $state -or $state.boot -ne $boot) { $state = New-BootState (Get-UnixNow) $boot }
    $ticket = Get-GuardAuthorization $Key $boot
    $observation = Observe-Guard $state $Key $boot
    $script:DecisionContext['classification'] = 'no_signed_in_users'
    if (@($observation.sessions).Count -gt 0) {
        $script:DecisionContext['classification'] = 'signed_in_session_blocked_by_default'
        if (-not (Get-SessionBlockReason $observation.sessions $observation.state $ticket $observation.now $boot)) {
            $script:DecisionContext['classification'] = 'authorized_unattended_candidate'
        }
    }
    # Observations occur even outside 04:00-06:00 and while the report is pending.
    $data = Get-Completion $config $Key
    $script:DecisionContext['signature_verified'] = $true
    $reason = Get-AllBlockReason $data $observation $ticket $boot
    if ($Check -or -not $Arm) {
        Save-Result 'check_only' $(if ($reason) { $reason } else { 'eligible_after_grace_and_final_revalidation' })
        return
    }
    if ($reason) { Save-Result 'skipped' $reason; return }
    Save-Result 'grace_started' '60_seconds; no_Windows_shutdown_timer_started'
    $grace = Wait-GuardGrace $observation $ticket $data $Key $boot
    $observation = $grace.observation
    if ($grace.reason) { Save-Result 'skipped' ('during_grace:' + $grace.reason); return }
    # Refresh cryptographic authorization, then query users and identity again.
    $data = Get-Completion $config $Key
    if (-not (Test-TargetComputer $config) -or (Get-BootUnix) -ne $boot) { throw 'Machine/boot identity changed at final check.' }
    $ticket = Get-GuardAuthorization $Key $boot
    $observation = Observe-Guard $observation.state $Key $boot
    $reason = Get-AllBlockReason $data $observation $ticket $boot
    if ($reason) { Save-Result 'skipped' ('final_check:' + $reason); return }
    Save-Result 'shutdown_prepared' 'grace_passed; fresh_signature; final_session_check_pending'
    # Persist the attempt BEFORE the OS call. A failure/crash/block leaves this
    # marker set, preventing repeated shutdown requests each minute.
    $observation.state.attempt = $true
    Write-LocalRecord $statePath $observation.state $Key
    $last = Observe-Guard $observation.state $Key $boot
    $reason = Get-BlockReason $data $last.now $boot 0
    if (-not $reason) { $reason = Get-SessionBlockReason $last.sessions $last.state $ticket $last.now $boot }
    if (-not $reason -and (Test-Path -LiteralPath (Join-Path $directory 'shutdown-disabled'))) { $reason = 'shutdown_disabled_by_file' }
    if (-not $reason -and ([Math]::Abs($last.now - [long]$data.issued_utc) -gt 30)) { $reason = 'completion_expired_at_final_check' }
    if ($reason) { Save-Result 'skipped' ('last_check:' + $reason); return }
    Save-Result 'shutdown_requesting' 'non_forced; attempt_recorded; this_is_not_confirmation_of_power_off'
    $ticket = Get-GuardAuthorization $Key $boot
    # No disk/network writes between these final observations and the OS call.
    # WTS polling cannot eliminate the residual check-to-use race entirely.
    if (-not (Test-TargetComputer $config) -or (Get-BootUnix) -ne $boot) { throw 'Machine/boot changed immediately before shutdown.' }
    $finalSessions = @(Get-SessionEvidence)
    $finalNow = Get-UnixNow
    $finalState = Update-BootState $last.state $finalSessions $finalNow $boot
    $reason = Get-BlockReason $data $finalNow $boot 0
    if (-not $reason) { $reason = Get-SessionBlockReason $finalSessions $finalState $ticket $finalNow $boot }
    if (-not $reason -and (Test-Path -LiteralPath (Join-Path $directory 'shutdown-disabled'))) { $reason = 'shutdown_disabled_by_file' }
    if (-not $reason -and ([Math]::Abs($finalNow - [long]$data.issued_utc) -gt 30)) { $reason = 'completion_expired_before_OS_call' }
    if ($reason) {
        Write-LocalRecord $statePath $finalState $Key
        Save-Result 'skipped' ('before_OS_call:' + $reason)
        return
    }
    Invoke-ShutdownRequest
    Save-Result 'shutdown_request_accepted' 'OS_command_returned_zero; power_off_not_confirmed'
}

function Invoke-PowerGuard {
    $lock = $null
    $key = $null
    try {
        $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        $null = Get-MachineBinding $config
        if (-not (Test-TargetComputer $config)) { throw 'This is not the configured Ollama PC. No shutdown is permitted.' }
        $lock = [IO.File]::Open((Join-Path (Get-GuardDirectory) 'powerguard.lock'),
            [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        Add-Type -AssemblyName System.Security
        $keyFile = Join-Path (Get-GuardDirectory) 'pairing-key.dpapi'
        $key = [Security.Cryptography.ProtectedData]::Unprotect(
            [IO.File]::ReadAllBytes($keyFile), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
        if ($key.Length -ne 32) { throw 'Unexpected pairing key length.' }
        Invoke-GuardRun $key
    } finally {
        if ($null -ne $key) { [Array]::Clear($key, 0, $key.Length) }
        if ($null -ne $lock) { $lock.Dispose() }
    }
}

if (-not $LibraryOnly) {
    try { Invoke-PowerGuard }
    catch {
        # Error text is local diagnostics only; never include key/payload contents.
        $message = $_.Exception.Message
        try { Save-Result 'blocked_error' $message } catch { Write-Error ('PowerGuard blocked; logging failed: ' + $message) }
        exit 1
    }
}
