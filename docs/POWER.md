# Optional power management

Skip this entire section for an always-on Ollama server. The core report and viewer do not need it. The optional Windows guard currently uses **America/New_York** and a 04:00–06:00 shutdown window; use that same reporting timezone or adapt and test the guard first.

Included pieces:

- `wake_ollama.py`: sends a magic packet to the explicitly configured MAC/broadcast address.
- `power_status.py`: read-only completion endpoint, restricted to the configured client IP, with nonce-bound HMAC responses. It has no remote shutdown command.
- `Ollama-PowerGuard.ps1`: requires a verified completed report, checks the reporting date and boot time, refuses while any interactive session exists (including disconnected sessions), waits through a grace period, and checks again. It never uses forced application termination.
- `Install-OllamaPowerGuard.ps1`: requires the target IP/MAC and coordinator IP; stores the pairing key with DPAPI and installs a **disabled** scheduled task.

The completion policy accepts a verified saved partial report after AI batch errors, as well as a completed review or a review that reached its time budget. The errors and coverage limits remain visible in the report. A model that was unavailable during preflight (`ollama_unavailable`) still blocks automatic shutdown. Missing, failed, corrupted, stale, or actively rebuilding reports also remain ineligible. The signed response and Windows guard still enforce their reporting-date, boot-time, session, and shutdown-window checks.

## Coordinator

Set the real MAC and subnet broadcast in `/etc/ai-monitor/monitor.env`. Do not use the documentation-only example MAC/address:

```dotenv
AI_MONITOR_WAKE_MAC=YOUR-OLLAMA-ADAPTER-MAC
AI_MONITOR_WAKE_BROADCAST=YOUR-LAN-BROADCAST
```

Create a new pairing key only for a new pairing. This refuses to replace an existing key:

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

Copy `config/ai-monitor-power-status.service.example` to `/etc/systemd/system/ai-monitor-power-status.service`; replace the two placeholder IPs in its `ExecStart`. Allow TCP 8766 only from the Ollama PC through your existing coordinator firewall. Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ai-monitor-power-status.service
sudo systemctl status ai-monitor-power-status.service --no-pager
```

## Windows Ollama PC

Enable Wake-on-LAN in firmware and NIC settings as supported by your hardware. First test that another machine can wake it from the intended power state. From the coordinator, the following sends the wake packet and waits up to 120 seconds for Ollama:

```bash
sudo -u ai-monitor python3 -I /opt/ai-monitor/run.py wake_ollama --wait 120
```

In an administrator PowerShell on the Ollama PC, from this repository:

```powershell
$TargetIP = Read-Host 'Ollama PC IPv4 address'
$TargetMac = Read-Host 'Ollama PC Ethernet MAC'
$CoordinatorIP = Read-Host 'Coordinator IPv4 address'
.\scripts\Install-OllamaPowerGuard.ps1 -TargetIP $TargetIP -TargetMac $TargetMac -CoordinatorIP $CoordinatorIP
```

The installer prompts for the 64-character pairing key with hidden input. Read it locally using `sudo cat /etc/ai-monitor/power.key` on the coordinator, transfer it only to this prompt, and do not put it into Git or a chat. The task stays disabled. The endpoint contains report completion metadata, not raw logs; its response is authenticated but HTTP transport itself is not encrypted, so use a trusted LAN/VPN.

Verify the installed guard without shutting down:

```powershell
& "$env:ProgramData\AiMonitorPower\Ollama-PowerGuard.ps1" -Check
Get-ScheduledTask -TaskName 'AI Monitor - Ollama shutdown guard'
```

Only after cold-start wake and signed-status checks succeed, enabling this task authorizes automatic shutdown of the configured PC under the guard's conditions:

```powershell
Enable-ScheduledTask -TaskName 'AI Monitor - Ollama shutdown guard'
```

Disable it at any time:

```powershell
Disable-ScheduledTask -TaskName 'AI Monitor - Ollama shutdown guard'
```

For daily wake, copy the two `config/ai-monitor-wake.*.example` files into `/etc/systemd/system/` without `.example`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ai-monitor-wake.timer
systemctl list-timers 'ai-monitor-*' --all
```

The timer wakes at 03:30; NAS export is 03:40, build 04:00, optional email 05:00. The coordinator stays on. The guard considers verified report completion, not SMTP inbox delivery. Review its `last-result.json` for skip/block reasons. Publishing this source does not install or arm the optional power controls; configure them separately if you want to use them.
