# Test remote syslog after guest updates

`scripts/test-remote-syslog.sh` writes synthetic messages into the configured log inputs on a Proxmox host's guests. Run it after updating a guest to check delivery to Synology Log Center and suppression of low-priority or noisy messages. It is optional and independent of the coordinator installer.

## Reference inventory

The script contains the following deployment-specific mappings. Review and adapt the target list, ID validation, case mappings, log paths and configuration filenames before using it on a different Proxmox installation. It does not discover or configure arbitrary guests.

| ID | Guest | Input tested | Expected received entries |
|---|---|---|---|
| 100 | Home Assistant OS VM | Home Assistant container stderr through existing Logspout | 1; level follows Logspout configuration, normally Error |
| 101 | Plex LXC | Plex Media Server.log | 1 Warning |
| 102 | Z-Wave JS UI LXC | Current driver log | 1 Info |
| 103 | FreePBX VM | Local logger through existing rsyslog | 1 Warning |
| 104 | Immich LXC | Web and machine-learning logs, with ANSI color codes | 2 Warnings |
| 105 | Heimdall LXC | Most recently modified Laravel log | 1 Warning |
| 106 | Jellyfin LXC | Most recently modified Jellyfin log | 1 Warning |
| 107 | qBittorrent LXC | /var/log/qbittorrent/qbittorrent.log | 1 Warning |
| 108 | Open WebUI LXC | Journal with open-webui identifier | 1 Warning |
| 109 | AI Monitor LXC | Journal from a temporary ai-monitor-syslog-check service | 1 Warning |

Run as root on Proxmox with Bash, `pct`, `qm`, Python 3 and `timeout`. Both VMs need a working QEMU guest agent. Linux guests need their existing rsyslog configuration; Home Assistant needs its running `homeassistant` and Logspout containers and Python 3 inside the Home Assistant container.

## Install and run

From a checkout of this repository on Proxmox:

```bash
bash -n scripts/test-remote-syslog.sh
install -m 0755 scripts/test-remote-syslog.sh /usr/local/sbin/test-remote-syslog
test-remote-syslog
```

After later guest updates, run `test-remote-syslog` again, or select only the updated guests:

```bash
test-remote-syslog 101 104
```

Wait at least 10 seconds, then search **all hosts and severities** in Synology Log Center for the printed **numeric run ID**. A complete default run should produce **11 PASS entries**, no `DROP` entries, and no `CRON` entries containing the run ID. Selected guests produce the counts in the table.

FreePBX's negative probe uses the numeric run ID as a synthetic UID inside the exact cron-session message format its existing filter suppresses. That message cannot include a `DROP` marker without changing the filter match, which is why the search uses the numeric ID. This only writes a log message; it does not open a session or create a user. Z-Wave's negative probe matches its queue-idle noise filter. Home Assistant has a delivery probe only; no severity suppression is assumed for Logspout.

## Interpret the result

`WROTE TESTS` means the guest command completed, not that the NAS received anything. Exit zero means all requested probes completed. Missing configurations, inactive rsyslog, stopped guests, guest-agent failures and timeouts produce a nonzero exit; later guests are still attempted. Failed probes can leave partial entries. Run IDs have one-second resolution, so avoid concurrent runs.

Missing PASS entries, extra entries, leaked DROP/CRON messages, duplicates or unexpected severity require investigation. Check the affected guest's active forwarder, file access, source configuration, forwarding rules and NAS receiver. A direct UDP `logger --server` test bypasses those inputs and filters and cannot substitute for this check.

The script appends synthetic records to existing application logs, writes journal/local-syslog entries, and uses a temporary successful systemd unit for AI Monitor. Home Assistant's probe writes to its main container stderr pipe, which [Logspout collects](https://github.com/bertbaron/hassio-addons/tree/main/logspout). It does not restart applications, change logging configurations, install packages or trigger AI jobs, email delivery or power actions. Synthetic records remain in logs and may appear in later AI digests.

These probes check the configured input-to-receiver paths and representative filters. They do not prove that updated applications still write normal events to those paths, that every severity branch works, or that the NAS export and AI review stages work. Confirm a normal application event when an update changes its logging behavior.

Validation before publication: Bash syntax checks, embedded Python parsing, and mocked guest routing/failure/timeout checks. The combined ten-guest script has not yet been confirmed end-to-end on the live NAS.

For the separate three-guest work host, see [Work syslog check](WORK-SYSLOG-CHECK.md).
