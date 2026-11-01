# Setup: two Synology sites, Linux coordinator, local Ollama

These instructions install a **new** coordinator. Do not run the first-install script on an existing `/opt/ai-monitor` deployment; see [UPGRADE.md](UPGRADE.md). No changes to Matt's running coordinator are needed merely to publish this repository.

## 1. Choose the machines and record settings

- Home and Work: Synology NAS systems with Log Center already receiving device logs and writing its supported database/archive structure under `/volume1/Logs` (adjust that root if yours differs).
- Coordinator: Debian 12/13 VM or unprivileged LXC with Python 3.11+, systemd, and network access to both NAS shares and Ollama. A working site-to-site VPN is needed for a remote office NAS.
- Ollama: Windows or Linux computer with adequate memory for your chosen model. Check `ollama ps` after a test request; runtime and memory usage depend on model and hardware.
- Use reserved LAN addresses or stable names for NAS servers. Ollama's configuration in this package requires a literal private IP or loopback address.
- Keep at least 2 GiB free on the coordinator; actual history and scratch usage need additional space. Start with a modest log window and monitor the disk.

Replace `HOME_NAS`, `WORK_NAS`, `COORDINATOR_IP`, and `OLLAMA_IP` in commands where indicated. They are labels, not working addresses.

## 2. Install and configure Ollama

Install from [Ollama's Windows download](https://ollama.com/download/windows), or follow the vendor's Linux installation instructions. Download a local model:

```powershell
ollama pull qwen3:8b
ollama list
ollama run qwen3:8b "Reply with one short sentence."
ollama ps
```

Use `qwen3.6:27b` instead if reproducing Matt's model choice and your system supports it. The model must appear under exactly the configured name in `ollama list`.

On Windows, quit Ollama from the tray, then set user environment variables in PowerShell:

```powershell
$OllamaIP = Read-Host 'Ollama PC private IPv4 address'
[Environment]::SetEnvironmentVariable('OLLAMA_HOST', "${OllamaIP}:11434", 'User')
[Environment]::SetEnvironmentVariable('OLLAMA_NO_CLOUD', '1', 'User')
```

Start Ollama again from the Start menu. Do not start a second `ollama serve` beside the tray application. For a local-only coordinator on the same machine, keep Ollama bound to loopback instead.

For a separate coordinator, run this in an **administrator PowerShell** on the Ollama PC, entering the two real private addresses:

```powershell
$OllamaIP = Read-Host 'Ollama PC private IPv4 address'
$CoordinatorIP = Read-Host 'Coordinator private IPv4 address'
New-NetFirewallRule -DisplayName 'Ollama from AI coordinator' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 11434 -LocalAddress $OllamaIP -RemoteAddress $CoordinatorIP -Profile Private
```

Review any existing broad Ollama allow rules; this narrow rule does not override a broader allow rule. Keep the API behind your LAN/VPN. Do not port-forward it or expose it through a public tunnel.

On Linux, use `sudo systemctl edit ollama` to add:

```ini
[Service]
Environment="OLLAMA_HOST=YOUR_PRIVATE_IP:11434"
Environment="OLLAMA_NO_CLOUD=1"
```

Replace `YOUR_PRIVATE_IP`, then run `sudo systemctl daemon-reload` and `sudo systemctl restart ollama`. Restrict port 11434 to the coordinator using your existing host/network firewall. The cloud-disable setting is necessary even when the client URL is local: a locally listening Ollama server can otherwise use cloud models. See [Ollama configuration and cloud controls](https://docs.ollama.com/faq) and [Windows behavior](https://docs.ollama.com/windows).

## 3. Prepare the NAS exports

On each NAS:

1. Install Python 3 from Package Center and confirm its executable path. The task below defaults to `/usr/local/bin/python3`; change it to the installed path if needed.
2. In File Station create `Logs/AI-Monitor-Code`.
3. Upload **only** `src/nas_export_site.py`, `src/nas_export_recent.py`, and `scripts/nas-daily-export.sh` there. Keep the scripts together. Do not place the whole repository or credentials in that directory.
4. In Control Panel → Task Scheduler, create a scheduled user-defined script. Choose an account with permission to read the Log Center databases and write the export folder (typically root on DSM). Name it `AI Monitor home export` or `AI Monitor work export`.
5. Set it to run every day at **03:40**, with the NAS timezone matching the report timezone. The enabled checkbox must be checked.

Home task body:

```sh
SITE=home ROOT=/volume1/Logs PYTHON=/usr/local/bin/python3 /bin/sh /volume1/Logs/AI-Monitor-Code/nas-daily-export.sh
```

Work task body:

```sh
SITE=work ROOT=/volume1/Logs PYTHON=/usr/local/bin/python3 /bin/sh /volume1/Logs/AI-Monitor-Code/nas-daily-export.sh
```

Use Run once to test each task. In File Station verify the new `Logs/AI-Monitor-Exports/home-manifest.json` or `work-manifest.json` and matching run directory. Check task output for partial failures. Export retention keeps three tool-created runs; it does not remove original NAS logs.

Create an `ai-reader` account on each NAS. Give it read access to the `Logs` share/export tree and traversal to its files, no administrator role, and no write access. Verify effective DSM ACLs on the generated export files. If a root-created export is unreadable, adjust only the export subtree's read/traverse ACL for this account; do not make all NAS logs public or writable. SMB must be enabled with SMB2 or newer.

The collector downloads through `smbclient`, so CIFS mounts and privileged LXC are not necessary. A read-only mounted-export alternative is supported through `AI_MONITOR_MOUNT_ROOT`.

## 4. Install the coordinator

Copy or clone this repository into a Debian directory. From its root:

```bash
sudo bash scripts/install-coordinator.sh
sudo nano /etc/ai-monitor/monitor.env
```

Set the real values, with **no shell quotes**:

```dotenv
AI_MONITOR_OLLAMA_URL=http://OLLAMA_IP:11434
AI_MONITOR_MODEL=qwen3:8b
AI_MONITOR_TIMEZONE=America/New_York
AI_MONITOR_HOME_NAS=HOME_NAS
AI_MONITOR_WORK_NAS=WORK_NAS
```

The example above contains labels. Replace them before saving. Keep `/etc/ai-monitor/monitor.env` outside Git. Configure SMB secrets directly on the coordinator:

```bash
sudo nano /etc/ai-monitor/home.smb
sudo nano /etc/ai-monitor/work.smb
sudo chown root:ai-monitor /etc/ai-monitor/{monitor.env,home.smb,work.smb}
sudo chmod 640 /etc/ai-monitor/{monitor.env,home.smb,work.smb}
```

Each `.smb` file contains:

```ini
username = ai-reader
password = YOUR_NAS_ACCOUNT_PASSWORD
domain = WORKGROUP
```

Use the real domain if applicable. The example password must be replaced. Do not paste credentials into shell commands, GitHub issues, or the repository.

If changing timezone, edit the two timer files too, keeping the 04:00 build and 05:00 delivery aligned with `AI_MONITOR_TIMEZONE` and the NAS export time:

```bash
sudo nano /etc/systemd/system/ai-monitor-build.timer
sudo nano /etc/systemd/system/ai-monitor-send.timer
sudo systemctl daemon-reload
```

The report cutoff remains 03:30 in the configured timezone. The optional Windows power guard currently assumes America/New_York.

## 5. Check collection and AI separately

Run the NAS exports first. Then on the coordinator:

```bash
sudo -u ai-monitor python3 -I /opt/ai-monitor/run.py collect_sites
sudo -u ai-monitor python3 -I /opt/ai-monitor/run.py daily_report --audit-only
```

Collection exit code 2 means partial/unavailable coverage; inspect its warnings. An empty report is not proof of healthy devices. The audit makes no model call and sends no email.

For a bounded manual model preview (no email):

```bash
sudo -u ai-monitor python3 -I /opt/ai-monitor/run.py daily_report --max-groups-per-site 20 --max-runtime-seconds 180 --output /var/lib/ai-monitor/reports/manual-preview.txt
```

Check the generated text/JSON for coverage and AI errors. This preview is separate from the nightly viewer. To build today's actual daily result after 04:00:

```bash
sudo systemctl start ai-monitor-build.service
sudo journalctl -u ai-monitor-build.service -n 60 --no-pager
sudo -u ai-monitor python3 -I /opt/ai-monitor/run.py daily_job status
sudo systemctl start ai-monitor-publish.service
```

Before 04:00 the daily build returns `not_due`; use the manual preview or wait. A failed or interrupted build requires inspection before retrying:

```bash
sudo -u ai-monitor python3 -I /opt/ai-monitor/run.py daily_job build --force
```

That rebuilds the report for today and calls your local model; it does not resend email.

## 6. Read the private viewer

On the coordinator:

```bash
curl --noproxy '*' -I http://127.0.0.1:8088/
curl --noproxy '*' -I http://127.0.0.1:8088/report.html
curl --noproxy '*' -I http://127.0.0.1:8088/events.sqlite
```

Expect 200 for the dashboard and current-report pages and 404 for the database path. An explanatory report-unavailable page is a valid 200 response.

From your workstation, using an SSH account you already configured on the coordinator:

```powershell
ssh -N -L 8088:127.0.0.1:8088 YOUR_SSH_USER@COORDINATOR_IP
```

Keep that terminal running and open `http://127.0.0.1:8088/` in your browser. For a persistent Heimdall tile reachable on the LAN/VPN, edit `config/nginx-viewer.conf` on the installed machine: replace the loopback listen with the coordinator's private address and add explicit `allow` rules for your actual LAN/VPN CIDRs followed by `deny all`. Validate with `sudo nginx -t`, then reload NGINX. Do not put the report behind the public portfolio domain. The source setup is public; the actual reports stay private.

The dashboard includes Home/Work summaries, source details, a nightly timeline, and up to 30 days of verified report history. Open a history date to check navigation. Status publication runs every five minutes; refresh the browser to see updates. Detailed progress appears from the first run with these modules installed.

Enable the local-only reporting timers once the preceding checks pass:

```bash
sudo systemctl enable --now ai-monitor-build.timer ai-monitor-publish.timer
systemctl list-timers 'ai-monitor-*' --all
```

## 7. Optional Gmail delivery

This sends report content outside your LAN. Use the viewer alone if that is not desired. Create an app password for a Google account where the feature is available; it generally requires 2-Step Verification, and account policy may prevent its use. See [Google app-password help](https://support.google.com/accounts/answer/185833).

The interactive configuration masks the password and stores it outside the repository:

```bash
sudo python3 -I /opt/ai-monitor/run.py gmail_report configure
```

After 05:00, explicitly test delivery:

```bash
sudo systemctl start ai-monitor-send.service
sudo journalctl -u ai-monitor-send.service -n 30 --no-pager
sudo -u ai-monitor python3 -I /opt/ai-monitor/run.py daily_job status
```

This command sends the current digest, or a failure notice if the report is not ready. Verify the message in your inbox. SMTP acceptance is not proof of inbox delivery. If delivery is uncertain, inspect Sent mail before trying again. Once verified:

```bash
sudo systemctl enable --now ai-monitor-send.timer
systemctl list-timers 'ai-monitor-*' --all
```

## 8. Operate and troubleshoot

```bash
sudo journalctl -u ai-monitor-build.service -u ai-monitor-publish.service -u ai-monitor-send.service --since today --no-pager
df -h /var/lib/ai-monitor
sudo -u ai-monitor python3 -I /opt/ai-monitor/run.py daily_job status
```

- Missing site: verify the NAS export task is enabled, its manifest is fresh, VPN routing works, and `ai-reader` can read the files.
- Model missing: compare `ollama list` with `AI_MONITOR_MODEL`; use the exact tag.
- Limited review: inspect group counts and time budget before increasing limits. Try a smaller local model or reduce repetitive source noise carefully.
- 403/connection refused: check the viewer's listen address, SSH forwarding, and LAN/VPN ACLs. Do not solve it by publishing private reports.
- Clock warnings: align timezones/NTP and rerun exports. DST windows can legitimately contain 23 or 25 hours.

Pause scheduled runs without deleting data:

```bash
sudo systemctl disable --now ai-monitor-build.timer ai-monitor-send.timer ai-monitor-publish.timer
```

This does not interrupt an already running service. Let it finish before changing source. Keep raw exports/caches restricted; redaction applies to newly imported/report-bound text and does not sanitize the NAS originals.
