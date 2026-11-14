# Devices and retirement

The **Devices** link opens `/controls/devices`. It lists devices observed in retained coordinator history, their source aliases, site, IP addresses and last message time. New identities are added when their logs are imported from the NAS. It does not scan for unobserved devices or prove whether a device is online.

The first action is **Retire**. Retired devices move to their own tab, where you can **Restore** them or **Retire permanently**. Permanent retirement has a separate confirmation and checkbox. It keeps an exclusion record so the same identity does not reappear as active; the web interface cannot restore it. The permanent tab provides a record of those choices.

Retirement excludes matching records before grouping and AI review. Original events remain under the existing retention policy. Saved reports and delivered email are not rewritten. The live issue view hides retired-device findings immediately; the next build applies retirement to the report and email. Restoring a device makes it eligible again, subject to any separate issue filters.

## Automatic retirement and recent changes

Automatic retirement defaults to **enabled after 10 days without NAS-received logs** when the inventory is initialized or upgraded. The Devices page has an enable/disable checkbox and a whole-number threshold from 1 to 3,650 days. Settings are persisted in the device store. Saving a setting does not immediately retire devices; the next qualifying collection evaluates it.

Retirement requires a successful, fresh collection for that site with no collection or source warnings. It uses NAS receipt timestamps, or the NAS's own event timestamps for NAS-local streams, rather than coordinator import time or a remote sender's clock. Uncertain timestamps or conflicting DNS evidence pause the affected identity; a failed or stale site collection pauses the site. The dashboard displays paused checks. Missing or invalid saved settings stop automatic lifecycle changes instead of silently restoring defaults.

Automatically retired devices can return after a qualifying collection observes new, still-recent NAS receipts. Importing old archives does not establish current activity. Manual and permanent retirement remain in place when new logs arrive. A manual Restore starts a new grace period using the configured threshold.

Additions, retirements and restorations appear for seven days in the Devices page and daily report. Existing inventory entries migrate as a baseline rather than appearing as newly added. A verified alias of an existing device does not count as a new physical device, and an action covering multiple aliases appears once while retaining the per-identity audit records.

## Identity and aliases

Original log identity includes the site, hostname and IP address. DNS-style hostnames differing only in case, with the same IP, share an identity. An IP change creates a separate original identity; missing hostnames fall back to the source label and IP. These identity hashes, source labels and events remain intact after consolidation.

The collector can link same-site identities into one displayed device when local DNS provides consistent evidence: one reverse name for the private IP, forward confirmation of that IP, and a matching forward lookup for the observed hostname. Short names use the verified reverse name's suffix, not the resolver's search order. The canonical domain must match a domain observed for that site. Sharing an IP alone is insufficient, and Home and Work never merge with one another.

DNS queries target only private IPv4 or IPv6 ULA nameservers listed in `/etc/resolv.conf`. Public resolvers and loopback DNS stubs are not used. Sites containing only short names, missing reverse records, unsupported resolver configurations and ambiguous answers may therefore leave aliases separate. The module makes no DNS queries while rendering or serving a dashboard request.

Verified aliases share a device entry, with all original names, IPs and source aliases available in the details. Device actions cover the entire linked group, and inactivity uses the group's latest trusted receipt. Manual and permanent exclusions apply to newly verified aliases. When an automatically retired alias joins an active one, existing per-identity eligibility is preserved until a healthy collection can reconcile their activity; the dashboard notes this partial state.

Previously verified links survive temporary DNS failures. A positive contradiction or a changed verified canonical name separates the affected alias while preserving its existing retirement state. Conflicting aliases are flagged and pause automatic lifecycle changes until positively verified again. DNS evidence is not proof of a device's physical identity or current availability.

NAS-local system, connection and transfer streams share one NAS entry per site. Client IPs appearing inside those streams do not identify the NAS itself. Retiring Home Assistant retires that log sender; use an issue filter to ignore one offline sensor instead.

## Quiet sources and collection errors

No qualifying messages, archive-only sources, and source labels absent from a successful NAS discovery are informational. They can be caused by log thresholds, renamed devices or old archives. These notices alone do not establish device health or authorize retirement; the receipt-age threshold and collection safeguards above must also pass.

Failed downloads, invalid manifests, checksum failures, stale current exports, malformed records and failed inventory refreshes still produce coverage warnings. Retirement cannot clear them. If device settings cannot be read, the build leaves all devices eligible and reports the settings error.

The device inventory refreshes after collection from sanitized local history. Each build uses one retirement snapshot, so a change during a build takes effect on the following build.

## Installation and maintenance

Use a matching complete source release and the optional controls installer described in [FILTERS.md](FILTERS.md). It initializes `devices/devices.sqlite` without replacing existing choices, refreshes observations, and grants the web service write access only to its device and filter stores. It preserves the raw-history access restriction on the web service.

For an existing installation, follow [UPGRADE.md](UPGRADE.md). Copying only the web module is insufficient: collection, reporting, rendering and the service unit must be upgraded together. Back up the device store using SQLite's backup interface, alongside the suppression store. Do not copy an actively written SQLite file without its transaction state.

The lifecycle and DNS tables are additive. Initialization preserves existing identities, exclusions and audit records. Include `device_dns.py` alongside `device_inventory.py` in a complete source upgrade.

Read-only inventory summary:

```bash
runuser -u ai-monitor -- python3 -I /opt/ai-monitor/device_inventory.py status
```

Refresh observations without running AI or sending email:

```bash
runuser -u ai-monitor -- python3 -I /opt/ai-monitor/device_inventory.py refresh
```

Refresh observations and verify DNS aliases now, without collecting new NAS exports, running AI or sending email:

```bash
runuser -u ai-monitor -- python3 -I /opt/ai-monitor/device_inventory.py refresh-dns
```

Neither manual refresh command supplies fresh collection evidence, so it cannot initiate automatic retirement or restoration. DNS consolidation still preserves and propagates existing manual/permanent exclusions across verified aliases.

Inventory refresh is bounded to 90 seconds, 10,000 original identities and 20,000 source aliases. DNS work uses at most eight seconds of the remaining refresh budget and 160 queries. An exceeded inventory bound leaves the previous inventory intact and reports an error; unavailable DNS leaves unverified aliases separate. Permanent exclusions persist even after old events age out. Retired and permanent records are counted separately from issue-filter suppression in report accounting.

Device mutations use the existing same-origin, CSRF-protected POST flow. A stale confirmation must be reloaded. Anyone allowed through the viewer's LAN/VPN access rules can manage devices; this release does not add individual user accounts.
