# Devices and retirement

The **Devices** link opens `/controls/devices`. It lists devices observed in retained coordinator history, their source aliases, site, IP address and last message time. It does not scan the network or prove whether a device is online.

The first action is **Retire**. Retired devices move to their own tab, where you can **Restore** them or **Retire permanently**. Permanent retirement has a separate confirmation and checkbox. It keeps an exclusion record so the same identity does not reappear as active; the web interface cannot restore it. The permanent tab provides a record of those choices.

Retirement excludes matching records before grouping and AI review. Original events remain under the existing retention policy. Saved reports and delivered email are not rewritten. The live issue view hides retired-device findings immediately; the next build applies retirement to the report and email. Restoring a device makes it eligible again, subject to any separate issue filters.

## Identity and aliases

Identity includes the site, hostname and IP address. DNS-style hostnames differing only in case, with the same IP, share a device entry. Original source labels and events remain intact. Sharing an IP alone is insufficient: a different hostname using an old address stays active. An IP change also creates a new identity, so review the inventory after a device moves addresses. Missing hostnames fall back to the exact source label and IP.

NAS-local system, connection and transfer streams share one NAS entry per site. Client IPs appearing inside those streams do not identify the NAS itself. Retiring Home Assistant retires that log sender; use an issue filter to ignore one offline sensor instead.

## Quiet sources and collection errors

No qualifying messages, archive-only sources, and source labels absent from a successful NAS discovery are informational. They can be caused by log thresholds, renamed devices or old archives. They do not establish device health and never automatically retire a device.

Failed downloads, invalid manifests, checksum failures, stale current exports, malformed records and failed inventory refreshes still produce coverage warnings. Retirement cannot clear them. If device settings cannot be read, the build leaves all devices eligible and reports the settings error.

The device inventory refreshes after collection from sanitized local history. Each build uses one retirement snapshot, so a change during a build takes effect on the following build.

## Installation and maintenance

Use a matching complete source release and the optional controls installer described in [FILTERS.md](FILTERS.md). It initializes `devices/devices.sqlite` without replacing existing choices, refreshes observations, and grants the web service write access only to its device and filter stores. It preserves the raw-history access restriction on the web service.

For an existing installation, follow [UPGRADE.md](UPGRADE.md). Copying only the web module is insufficient: collection, reporting, rendering and the service unit must be upgraded together. Back up the device store using SQLite's backup interface, alongside the suppression store. Do not copy an actively written SQLite file without its transaction state.

Read-only inventory summary:

```bash
runuser -u ai-monitor -- python3 -I /opt/ai-monitor/device_inventory.py status
```

Refresh observations without running AI or sending email:

```bash
runuser -u ai-monitor -- python3 -I /opt/ai-monitor/device_inventory.py refresh
```

Inventory refresh is bounded to 90 seconds, 10,000 identities and 20,000 aliases. An exceeded bound leaves the previous inventory intact and reports an error. Permanent exclusions persist even after old events age out. Retired and permanent records are counted separately from issue-filter suppression in report accounting.

Device mutations use the existing same-origin, CSRF-protected POST flow. A stale confirmation must be reloaded. Anyone allowed through the viewer's LAN/VPN access rules can manage devices; this release does not add individual user accounts.
