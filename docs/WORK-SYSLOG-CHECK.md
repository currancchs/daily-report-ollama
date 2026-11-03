# Work Proxmox syslog check

Run `scripts/test-work-syslog.sh` as root on the work Proxmox host. This is a separate reference inventory from the home script; review IDs and paths before using on another host.

| ID | Guest | Probe | Expected receipt |
|---|---|---|---|
| 100 | Debian PBX VM | Local `logger` using `local0.warning`, through `61-asterisk-to-nas.conf` | 1 Warning |
| 101 | Z-Wave JS UI LXC | Append to `/opt/zwave_store/logs/zwavejs_current.log`, through `30-zwave-driver.conf` | 1 Info |
| 102 | Home Assistant OS VM | Host journal via `systemd-cat`, through mib1185's Syslog add-on | 1 Warning |

The reference PBX forwards local0 to UDP port 600; Z-Wave forwards to UDP port 514. The script uses the installed forwarding destinations, not hard-coded network sends. The PBX configuration forwards all local0 severities: no severity-suppression test is assumed. Z-Wave also receives a DROP marker matching its queue-idle filter. Home Assistant uses the [Syslog add-on](https://github.com/mib1185/ha-addon-syslog), which reads the HAOS journal, rather than Logspout.

## Install on work Proxmox

From a checkout on the host:

```bash
bash -n scripts/test-work-syslog.sh
install -m 0755 scripts/test-work-syslog.sh /usr/local/sbin/test-work-syslog
test-work-syslog
```

After updates, run `test-work-syslog` for all three guests, or `test-work-syslog 100 101` for selected IDs. Requires Bash, Python 3, timeout, pct and qm on Proxmox, functioning guest agents for both VMs, existing rsyslog configurations, and `systemd-cat` on HAOS with the Syslog add-on running. Missing prerequisites fail visibly; no packages or logging configurations are changed.

Wait at least 10 seconds and search all hosts/severities on the work NAS for the numeric run ID. Expect **3 PASS entries** and **zero DROP entries** for a successful complete run. The terminal reports commands completed, not NAS receipt. Nonzero exit indicates a probe failed; other guests are still attempted. Failed probes may leave partial entries. Avoid concurrent runs because run IDs have one-second resolution.

The PBX probe tests local syslog forwarding, not Asterisk's own logging configuration. The HAOS probe tests journal forwarding, not Home Assistant's application-specific severity parsing. The Z-Wave probe tests its file input and queue filter, not normal device-event generation. Other filters and the NAS-to-AI pipeline are outside this check. Synthetic markers remain in logs and can appear in later digests. No services are restarted or calls, automations, email or AI jobs triggered.

The first live run must confirm HAOS has `systemd-cat` and all three expected entries arrive. Local syntax validation is not a live-delivery result.
