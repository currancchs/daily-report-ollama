# Architecture and dashboard

The NAS exporter produces snapshots and a manifest with source names, row counts, hashes, timestamps, and partial-failure details. The collector validates these and imports into deduplicated SQLite history. Four Log Center table shapes are supported: syslog, system/general, connection, and transfer events.

The reporting layer aggregates on disk, rolls up known repetitive families, and preserves source boundaries, occurrence counts, first/last times, and bounded examples. Review prioritizes flagged groups across Home and Work before routine groups. Defaults allow up to 2,000 selected groups per site within a 45-minute overall build budget; reaching a limit is surfaced in the result.

The model receives instructions that log text is untrusted evidence. Returned JSON must match the expected assessment structure and event IDs. There are no agent tools or automatic remediation commands. AI conclusions remain suggestions to check against source evidence.

The daily window ends at 03:30 local time; exports run at 03:40 and the build starts at 04:00. Optional delivery is separate at 05:00. Optional Wake-on-LAN starts at 03:30. Those schedule times are fixed conventions; change code/timers together if changing the schedule. The timezone is configurable, except the optional Windows power guard currently assumes America/New_York.

## Dashboard in this snapshot

- Home/Work summaries show findings, record counts, review coverage, and missing or partial states.
- Expandable source tables expose counts, last-record times, and coverage warnings.
- A nightly timeline reads wake, export, collection, build, and delivery records; missing records stay unknown.
- Small progress records capture stages and AI batch counts. Failure to write progress does not abort report analysis.
- Up to 30 days of verified HTML reports appear in dated history. History rechecks identity, timestamps and hashes; corrupt entries become unavailable.
- The publisher runs every five minutes. Refresh the browser to load its latest saved page. No browser polling, NAS query, or model call occurs when browsing.

The public web root contains only regenerated `index.html`, `report.html`, and `history/YYYY-MM-DD.html`. NGINX permits only these paths. Raw JSON, SQLite, progress records, credentials and caches remain outside that root. Saved report HTML is regenerated from checked JSON and escaped; it is not trusted as executable content.

Detailed stage information begins with the first run after the update; older reports may have no progress records. SMTP acceptance is displayed separately from inbox delivery. The optional wake/email steps can show no confirmation if the operator has not enabled those features.

## Release state and remaining work

The dashboard update is installed on the original coordinator and passed its offline, NGINX and web checks. This portable adaptation includes the final permission-handling fix. Its first-install script has not been run on a fresh Debian deployment.

Searchable findings, source-volume charts, acknowledgment/investigation notes, and automatic browser polling are not implemented. The included preview uses synthetic data and demonstrates saved reports, not real device status.
