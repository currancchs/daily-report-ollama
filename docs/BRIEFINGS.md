# Opening briefings and device lifecycle

The daily HTML, text email and dashboard begin with a local-AI briefing. It prioritizes newly observed and substantially increased findings, keeps significant ongoing issues visible, and distinguishes advisory critical findings from confirmed incidents. Each item links to supporting events in that day's report. Only a reviewed catalog supplies official troubleshooting links; model-generated URLs are rejected. Guidance is not presented as a verified fix.

Comparisons use up to seven prior daily reports. Missing or incomplete baseline coverage is stated explicitly. A missing finding does not prove resolution. A bounded summary failure produces clearly labeled evidence-based highlights without blocking the report or email.

The review cap is 7,500 groups per site. The overall build remains limited to 45 minutes, with up to 90 seconds reserved for the opening summary and 60 seconds for finalization. A selection or time limit is labeled `LIMITED REVIEW`; collection, grouping and model failures retain `PIPELINE ISSUE`.

## Reviewing repeated issues

The issue dashboard combines narrowly recognized Home Assistant connection problems under **Offline or possibly removed devices**. Selected Plex metadata/artwork/request and Jellyfin probe/image/metadata failures also use expandable families. Unknown messages, critical events and security/authentication or log-forwarding failures remain individual. All member evidence and per-issue Ignore actions remain available. These are display groups, not suppression rules or changes to AI coverage.

## Devices

Open **Devices → Automatic retirement** to enable or disable retirement and set a whole-number threshold from 1 to 3,650 days. The default is enabled after 10 days without NAS-received logs. Automatic retirement requires a successful, fresh collection with reliable receipt timestamps. It pauses when collection or timestamp evidence is uncertain. Existing device records migrate without being falsely reported as new.

New identities are added from received logs. Additions, retirements and restorations remain in the report for seven days. Automatically retired devices can return when new logs arrive; manual and permanent retirement are respected. Historical logs are retained.

Local DNS consolidation keeps original log identities and aliases. Verified same-site aliases share one inventory entry and lifecycle state. Ambiguous names or addresses remain separate. DNS is queried during bounded inventory refresh, never while serving a dashboard request.

## Refreshing a saved report

`refresh_briefing.py` can update today's briefing from saved assessments, with verified checksums and a backup. It preserves the event evidence, reporting window and original generation timestamp. It performs no collection or repeated event analysis and sends no email. It must run as the monitor user and cannot overlap a build or delivery.
