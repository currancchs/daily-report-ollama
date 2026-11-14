# Architecture and dashboard

The NAS exporter produces snapshots and a manifest with source names, row counts, hashes, timestamps, and partial-failure details. The collector validates these and imports into deduplicated SQLite history. Four Log Center table shapes are supported: syslog, system/general, connection, and transfer events.

The reporting layer aggregates on disk, rolls up known repetitive families, and preserves source boundaries, occurrence counts, first/last times, and bounded examples. Review prioritizes flagged groups across Home and Work before routine groups. Defaults allow up to 7,500 selected groups per site within a 45-minute overall build budget; reaching a limit is surfaced in the result. See [BRIEFINGS.md](BRIEFINGS.md) for the opening summary and its reserved runtime.

The model receives instructions that log text is untrusted evidence. Returned JSON must match the expected assessment structure and event IDs. There are no agent tools or automatic remediation commands. AI conclusions remain suggestions to check against source evidence.

The daily window ends at 03:30 local time; exports run at 03:40 and the build starts at 04:00. Optional delivery is separate at 05:00. Optional Wake-on-LAN starts at 03:30. Those schedule times are fixed conventions; change code/timers together if changing the schedule. The timezone is configurable, except the optional Windows power guard currently assumes America/New_York.

## Dashboard in this snapshot

- Home/Work summaries show findings, record counts, review coverage, and missing or partial states.
- The opening briefing highlights new or increased findings and links to supporting events and reviewed documentation. Missing comparison coverage is stated explicitly.
- Narrowly recognized Home Assistant, Plex and Jellyfin findings share presentation families. Every member and its individual Ignore action remains accessible; unknown, critical, security and logging-pipeline errors remain separate.
- Expandable source tables expose counts, last-record times, and coverage warnings.
- A nightly timeline reads wake, export, collection, build, and delivery records; missing records stay unknown.
- Small progress records capture stages and AI batch counts. Failure to write progress does not abort report analysis.
- Up to 30 days of verified HTML reports appear in dated history. History rechecks identity, timestamps and hashes; corrupt entries become unavailable.
- The publisher runs every five minutes. Refresh the browser to load its latest saved page. No browser polling, NAS query, or model call occurs when browsing.

The static web root contains only regenerated `index.html`, `report.html`, and `history/YYYY-MM-DD.html`. NGINX permits only these static paths, plus the optional `/controls/` application when installed. Raw JSON, SQLite, progress records, credentials and caches remain outside that root. Saved report HTML is regenerated from checked JSON and escaped; it is not trusted as executable content.

## Optional suppression controls

The issue view offers Ignore, a separate Suppressed issues page and a Filters management page. Filters default to no expiry and can be deleted to restore eligibility for future builds. A full SHA-256 group identity scopes each rule to the site, source and normalized evidence fields. Recognized grouping rules may combine specific varying fields; this scope is disclosed before saving.

Each build reads one filter snapshot and removes matching groups from its temporary aggregation database before selection and AI review. It preserves their counts and representative evidence in the report. Original history and NAS data remain untouched. A broken filter store fails open with a coverage warning. Suppression is accounted for separately from unreviewed eligible groups, and an entirely suppressed report does not claim successful AI review.

The Flask application verifies the current report on each visit. It shows saved evidence with current filter settings; already-built reports and emails remain unchanged. Creation/deletion use same-origin POST forms, CSRF checks, a persistent session key and transactional SQLite writes. The existing static overview, stage tracking and dated history continue independently. See [FILTERS.md](FILTERS.md).

Detailed stage information begins with the first run after the update; older reports may have no progress records. SMTP acceptance is displayed separately from inbox delivery. The optional wake/email steps can show no confirmation if the operator has not enabled those features.

## Device lifecycle and DNS aliases

After collection, the inventory reads sanitized history and adds newly observed identities. Original site/hostname/IP identities remain immutable. Bounded forward/reverse checks against configured private DNS resolvers can persist links between same-site aliases; neither DNS nor NAS queries run during a web request. Canonical names and all original aliases remain inspectable. Positive DNS contradictions detach and flag the affected alias while retaining its retirement choice.

The Devices page stores an automatic-retirement toggle and day threshold, initially enabled at 10 days. Only a fresh, complete collection with reliable receipt timestamps can authorize automatic retirement or restoration. Linked devices use their latest trusted receipt; manual and permanent exclusions are preserved across aliases. A DNS-only refresh cannot authorize automatic lifecycle changes. The seven-day activity list counts a physical-device change once while preserving per-identity audit records. See [DEVICES.md](DEVICES.md) for safeguards, mixed-state behavior, resolver limitations and maintenance commands.

Both filtering and device retirement use a build-wide snapshot before AI selection. Presentation families are separate from that decision: they reduce repeated cards without discarding events, altering Ignore scope, or claiming an underlying problem has been repaired.

## Release state and remaining work

The dashboard update is installed on the original coordinator and passed its offline, NGINX and web checks. This portable adaptation includes the final permission-handling fix. The suppression and device-control pages are installed on the original coordinator and returned HTTP 200 in a November 11 check; that read-only check did not change filters or device retirement. The first-install and optional controls scripts have not been run on a fresh Debian deployment.

Searchable findings, source-volume charts, acknowledgment/investigation notes, and automatic browser polling are not implemented. The included preview uses synthetic data and demonstrates saved reports, not real device status.
