# Optional power management

Skip this page for an always-on Ollama server. The report and viewer do not need power management. The Windows PowerShell 5.1 guard uses **America/New_York** and permits shutdown only during **04:00 inclusive to 06:00 exclusive Eastern**. Use the same reporting timezone, or adapt and test the guard first. Windows' `Eastern Standard Time` rules include daylight saving time.

The default policy blocks every signed-in user. PowerGuard 2.1 adds an optional recurring exception for one expected locked console account. Enable that policy once; no daily ticket or authorization command is required. Installing source, enabling this policy, and arming the scheduled task are separate operations.

## What is included

- `wake_ollama.py` sends a magic packet to the configured MAC/broadcast address.
- `power_status.py` exposes read-only completion metadata, restricted to the configured client IP, with nonce-bound HMAC responses. It has no remote shutdown command.
- `Ollama-PowerGuard.ps1` validates signed report completion, configured machine identity, reporting date, boot time, session evidence, and the shutdown window. It waits through its own 60-second grace period and checks again.
- `Install-OllamaPowerGuard.ps1` performs a first installation with local IP/MAC/coordinator settings and DPAPI pairing storage. Its task is **disabled**; its action is `-Arm`, and the installer invokes one separate `-Check`.
- `Update-OllamaPowerGuard.ps1` updates the exact supported earlier portable script while preserving configuration and pairing credentials. It installs an enabled **`-Check` task**, with explicit activation and rollback modes.
- `Test-PowerGuard.ps1` runs offline regression checks with synthetic keys and intercepted shutdown, network, and system probes.

No forced application termination, sign-out, process killing, or forced retry is used. The sole shutdown request is `/s /t 0` without `/f`. A positive `shutdown.exe` timeout implicitly enables force, so the grace period runs inside the guard instead. Applications may block shutdown; that is an accepted outcome.

## Coordinator setup

Set the real MAC and subnet broadcast in `/etc/ai-monitor/monitor.env`. Do not use documentation-only example addresses:

```dotenv
AI_MONITOR_WAKE_MAC=YOUR-OLLAMA-ADAPTER-MAC
AI_MONITOR_WAKE_BROADCAST=YOUR-LAN-BROADCAST
```

Create a key only for a **new pairing**. This refuses to replace an existing key:

```bash
sudo python3 - <<'PY'
from pathlib import Path
import grp, os, secrets
p=Path('/etc/ai-monitor/power.key')
fd=os.open(p, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o640)
with os.fdopen(fd,'w') as f: f.write(secrets.token_hex(32)+'\n')
os.chown(p,0,grp.getgrnam('ai-monitor').gr_gid)
PY
```

Copy `config/ai-monitor-power-status.service.example` to `/etc/systemd/system/ai-monitor-power-status.service`; replace its two placeholder IPs. Allow TCP 8766 only from the Ollama PC through the existing coordinator firewall. Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ai-monitor-power-status.service
sudo systemctl status ai-monitor-power-status.service --no-pager
```

The endpoint contains report completion metadata, not raw logs. Its response is authenticated, but HTTP transport itself is not encrypted; use a trusted LAN/VPN.

## Prepare the Windows PC

Enable Wake-on-LAN in firmware/NIC settings as supported by the hardware. Test waking from the intended power state. From the coordinator, this sends the packet and waits up to 120 seconds for Ollama:

```bash
sudo -u ai-monitor python3 -I /opt/ai-monitor/run.py wake_ollama --wait 120
```

Use an elevated **Windows PowerShell 5.1** window on the Ollama PC. Run installation, update, activation, and rollback while attended and outside 04:00–06:00 Eastern, with no shutdown underway. From the repository root, first run the offline tests:

```powershell
$ErrorActionPreference = 'Stop'
$pgPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
& $pgPowerShell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-PowerGuard.ps1
if ($LASTEXITCODE -ne 0) { throw 'PowerGuard tests failed; do not install or arm it.' }
```

These tests do not read pairing credentials, contact the real coordinator, or invoke native shutdown. They cannot establish the target PC's real SYSTEM-account session/idle values. Run one of the following installation paths, then perform the audit.

### New installation

For a PC without an existing PowerGuard installation:

```powershell
$TargetIP = Read-Host 'Ollama PC IPv4 address'
$TargetMac = Read-Host 'Ollama PC Ethernet MAC'
$CoordinatorIP = Read-Host 'Coordinator IPv4 address'
.\scripts\Install-OllamaPowerGuard.ps1 -TargetIP $TargetIP -TargetMac $TargetMac -CoordinatorIP $CoordinatorIP
```

The installer prompts for the 64-character pairing key with hidden input. Read it locally with `sudo cat /etc/ai-monitor/power.key` on the coordinator and transfer it only to that prompt. Do not put it into Git or a chat. The task remains disabled if its signed-status check fails; resolve the error before continuing.

The newly installed task has a `-Arm` action despite being disabled. **Before enabling it for an overnight audit**, change that fresh task to `-Check`:

```powershell
$pgRoot = Join-Path $env:ProgramData 'AiMonitorPower'
$pgGuard = Join-Path $pgRoot 'Ollama-PowerGuard.ps1'
$pgTaskName = 'AI Monitor - Ollama shutdown guard'
$pgArguments = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $pgGuard + '" -Check'
$pgAction = New-ScheduledTaskAction -Execute $pgPowerShell -Argument $pgArguments
Set-ScheduledTask -TaskName $pgTaskName -TaskPath '\' -Action $pgAction | Out-Null
Enable-ScheduledTask -TaskName $pgTaskName -TaskPath '\' | Out-Null
```

This action replacement is for the fresh task created by this installer. For an existing installation, use the guarded updater below instead.

### Existing portable installation

Do not rerun the first-install script to upgrade or re-pair. The updater accepts the exact earlier portable repository script and expected guard task. It refuses customized or unfamiliar versions, unexpected task actions, unsafe permissions, and reparse-point paths. A personal installation-specific package may differ even if its version number is similar; do not bypass a source mismatch by copying over the installed script.

```powershell
& $pgPowerShell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Update-OllamaPowerGuard.ps1 -Mode InstallAudit
if ($LASTEXITCODE -ne 0) { throw 'Update stopped; read its error before continuing.' }
```

Save the exact `BACKUP_PATH` printed by the helper:

```powershell
$pgBackup = 'PASTE_THE_PRINTED_ABSOLUTE_BACKUP_DIRECTORY_HERE'
```

The helper backs up the existing script and task, disables/stops only the guard, installs the replacement, and enables its `-Check` action. It preserves the existing `config.json`, DPAPI pairing key, coordinator, Ollama task, and reporting pipeline. A failure after deployment starts attempts to leave the guard disabled with a persistent stop file. Inspect the error and use the recorded backup for rollback; do not manually force an unexpected version through the updater.

## Enable the recurring policy and audit a night

Verify that the task action says **`-Check`** and its account is SYSTEM before enabling recurring authorization:

```powershell
$pgTaskName = 'AI Monitor - Ollama shutdown guard'
$pgGuard = Join-Path $env:ProgramData 'AiMonitorPower\Ollama-PowerGuard.ps1'
$pgTask = Get-ScheduledTask -TaskName $pgTaskName -TaskPath '\'
$pgTask.Actions | Format-List Execute,Arguments
$pgTask.Principal | Format-List UserId,RunLevel
```

To opt in, select the actual local or domain account that signs in at boot. Stop the audit task briefly so the policy command can take the guard's exclusive lock, then resume the **same `-Check` task**:

```powershell
Disable-ScheduledTask -TaskName $pgTaskName -TaskPath '\' | Out-Null
Stop-ScheduledTask -TaskName $pgTaskName -TaskPath '\'
& $pgPowerShell -NoProfile -ExecutionPolicy Bypass -File $pgGuard -EnableRecurring -ConsoleAccount 'YOUR-PC\YourUser'
if ($LASTEXITCODE -ne 0) { throw 'Policy authorization failed; leave the task disabled and review the error.' }
Enable-ScheduledTask -TaskName $pgTaskName -TaskPath '\' | Out-Null
```

This creates authenticated `recurring-policy.json` and logs the change; it does not arm the task, shut down the PC, or change automatic login. It takes effect only on a boot **after** policy creation. Save/close work, shut down, and let the existing overnight WOL/report pipeline run. The PC should stay on during this audit because the task uses `-Check`. There is no nightly policy renewal after this one-time setup.

The recurring signed-in exception requires all of the following:

- Boot occurs from **03:20 inclusive to 03:45 exclusive Eastern**, and the decision has the same Eastern calendar date.
- The guard first observes the boot within **120 seconds**, with no later observation gap longer than **150 seconds**.
- Exactly one named console session belongs to the authorized account SID, was created within 120 seconds of boot, and is observed locked.
- Trustworthy per-session timestamps show at least **60 minutes idle**, with at least 60 minutes of guard observations. The last input falls between session logon and boot+120 seconds and does not change after observation begins.
- No unlocked console, RDP, user/session replacement, later input, unknown session evidence, or excessive observation gap has been observed during this boot. These leave a persistent veto; relocking does not clear it.
- The existing report signature, nonce, freshness, report date/age, current-boot, identity, shutdown-window, grace, and final checks all pass.

All RDP sessions, including disconnected RDP, block the exception. Disconnected console sessions, additional users, and invalid/zero/stale/future timestamps also block. An auto-login that leaves the desktop unlocked does not qualify. The startup allowance is a tolerance, not proof of automatic login.

The coordinator authenticates **report completion**, not a wake request. Logs identify physical `boot_origin` as `unknown`. Recurring policy authorizes qualifying overnight boots; a manual boot in that same window can also qualify. Locked/idle status cannot prove apps have no unsaved work or background jobs, and polling cannot eliminate every race. Authorize this policy only when that behavior is intended.

Inspect the latest result and the daily logs after the audit. Records include UTC and Eastern timestamps; filenames use UTC dates:

```powershell
$pgRoot = Join-Path $env:ProgramData 'AiMonitorPower'
Get-Content -LiteralPath (Join-Path $pgRoot 'last-result.json') -Raw
Get-ChildItem -LiteralPath $pgRoot -Filter 'decisions-*.jsonl' |
    Sort-Object Name | Select-Object Name,Length,LastWriteTime
```

Look at entries recorded before you later unlocked or connected by RDP. A qualifying audit shows `check_only` with `eligible_after_grace_and_final_revalidation`, `evidence.authorization_mode` equal to `recurring`, and `evidence.classification` equal to `authorized_unattended_candidate`. Check `session_block`, `report_block`, and `boot_veto` for independent reasons when the primary detail is outside the shutdown window. Unlocked console, active/disconnected RDP, late observation, or WTS/idle errors should block. Keep audit mode if the real session values do not satisfy the policy; do not replace missing evidence with assumed inactivity.

## Arm only after the audit passes

For an **updated existing portable installation**, use its recorded backup:

```powershell
& $pgPowerShell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Update-OllamaPowerGuard.ps1 -Mode EnableArmed -BackupPath $pgBackup
if ($LASTEXITCODE -ne 0) { throw 'Arming failed; read the helper error.' }
```

For a **fresh installation audited above**, change only that task's action back to `-Arm`:

```powershell
Disable-ScheduledTask -TaskName $pgTaskName -TaskPath '\' | Out-Null
Stop-ScheduledTask -TaskName $pgTaskName -TaskPath '\'
$pgArguments = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $pgGuard + '" -Arm'
$pgAction = New-ScheduledTaskAction -Execute $pgPowerShell -Argument $pgArguments
Set-ScheduledTask -TaskName $pgTaskName -TaskPath '\' -Action $pgAction | Out-Null
Enable-ScheduledTask -TaskName $pgTaskName -TaskPath '\' | Out-Null
```

Verify the action is now `-Arm`. This authorizes automatic shutdown under all guard conditions. No-user shutdown remains the original policy and needs no recurring authorization; arming enables that path too. For the first live night, save and close work. Thereafter the persistent recurring policy needs no daily commands. A valid legacy one-night ticket is considered only when no recurring-policy file exists; a disabled or invalid recurring policy never revives a ticket.

## Stop or roll back

From elevated Windows PowerShell, stop the new guard before it hands a request to Windows:

```powershell
New-Item -ItemType File -Path (Join-Path $env:ProgramData 'AiMonitorPower\shutdown-disabled') -Force | Out-Null
Disable-ScheduledTask -TaskName 'AI Monitor - Ollama shutdown guard' -TaskPath '\' | Out-Null
Stop-ScheduledTask -TaskName 'AI Monitor - Ollama shutdown guard' -TaskPath '\'
```

The stop file is checked during grace and final validation. It and the disabled task remain in place until deliberately resolved. This cannot cancel an OS request already accepted. `shutdown /a` does not cancel the guard's own grace, and `/t 0` has no abort countdown.

To disable only recurring authorization, stop the task first, then run:

```powershell
& $pgPowerShell -NoProfile -ExecutionPolicy Bypass -File $pgGuard -DisableRecurring
if ($LASTEXITCODE -ne 0) { throw 'Policy change failed; leave the task stopped and review the error.' }
```

This persists `enabled=false`; it does not disable the original no-user policy. Policy changes share the execution lock and may fail while the guard is running. Do not delete signed policy/state files to bypass an observed veto. Any existing stop file remains effective, regardless of policy or task mode.

To roll back an **updater-managed portable installation**, run from this repository with its exact backup path:

```powershell
& $pgPowerShell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Update-OllamaPowerGuard.ps1 -Mode Rollback -BackupPath $pgBackup
if ($LASTEXITCODE -ne 0) { throw 'Rollback stopped; keep the task disabled and review the error.' }
```

Rollback verifies the backup and restores the exact earlier script and task configuration while leaving the task **disabled**. It preserves current configuration, pairing credentials, logs, and policy/state files. The earlier script does not honor the new stop file, so the disabled task is the rollback safety barrier. `-ResumeOriginal` explicitly restores its original enabled state where applicable; use it only deliberately, outside the shutdown window. A fresh installation has no updater backup; stop its task rather than using an unrelated backup.

## Operational files and daily wake

Under the installed `AiMonitorPower` directory, `last-result.json` holds the latest decision and `decisions-YYYY-MM-DD.jsonl` retains every logged decision without automatic deletion. Signed `boot-state.json` tracks observations and the single-attempt marker; `recurring-policy.json` stores the opt-in, and an older `unattended-ticket.json` may remain. Lock-file existence alone is normal. Do not commit these files, live configuration, pairing blobs, or installation backups. Logs include account/session evidence. Archive old daily logs as needed; keep current state intact.

For daily wake, copy the two `config/ai-monitor-wake.*.example` files into `/etc/systemd/system/` without `.example`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ai-monitor-wake.timer
systemctl list-timers 'ai-monitor-*' --all
```

The example timer wakes at 03:30; NAS export is 03:40, build 04:00, and optional email 05:00. The coordinator stays on. PowerGuard considers verified report completion, not SMTP inbox delivery. A logged request or zero shutdown command exit code is not proof the PC powered off.
