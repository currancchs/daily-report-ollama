# Existing installation

This package is a portable source release, not an automatic patch for an existing system. The first-install script refuses `/opt/ai-monitor` when it already exists.

For my working installation, publishing this source repository does not require reinstalling anything. Keep existing NAS tasks, schedules, Gmail configuration, pairing keys, and viewer access rules.

## November 14 briefing and device lifecycle update

The current release adds an opening local-AI briefing, linked evidence, reviewed troubleshooting references, expandable issue families, local DNS alias verification and automatic device lifecycle tracking. The per-site review cap is 7,500; the overall build allowance remains 45 minutes. A review limit alone is labeled `LIMITED REVIEW`, while collection, grouping and model failures retain `PIPELINE ISSUE`. Existing saved report coverage is not expanded by upgrading the source.

Deploy the complete matching module set, including the new `report_summary.py`, `issue_families.py`, `device_dns.py` and `refresh_briefing.py`, with the existing `settings.py`. Preserve the installed model, server, viewer origin and timezone through the environment configuration. Back up source and the device database with SQLite's backup interface while build, delivery, publication and web mutations are stopped. Apply the full-source migration below rather than mixing modules from different releases.

The device schema migration is additive and preserves existing retirement choices. Initialize it as the monitor user before serving the new controls. **Automatic retirement defaults to enabled after 10 days without NAS-received logs.** Set the toggle and threshold under **Devices → Automatic retirement** before resuming collection if another policy is needed. Initialization and a manual inventory refresh do not retire devices; retirement requires fresh, complete collection results and reliable receipt timestamps. Existing inventory entries are not relabeled as newly added.

The deployed upgrade was checked with offline regressions and a real local-model briefing refresh on November 14. The dashboard, device settings, grouped review controls and dated evidence links were verified. No email was resent and no devices were automatically retired during installation. A fresh first-install deployment still needs separate validation.

An optional `refresh_briefing.py` run updates only today's verified saved report, preserving its evidence, window and original generation timestamp. It creates a backup, locks against build and delivery, and rolls back on failure; it does not send email or re-review omitted groups. Use the configured `run.py refresh_briefing` invocation as the monitor user with the publication job stopped, then republish and restore the prior timer state. See [BRIEFINGS.md](BRIEFINGS.md) and [DEVICES.md](DEVICES.md).

## Saved partial report shutdown update

The coordinator now treats a verified saved partial report with AI batch errors as a finished run. The `ai_error` stop reason qualifies alongside `selected_groups_complete` and `time_budget`; `ollama_unavailable` remains blocked. Report verification, build locking, recency, configured model/server, and both-site checks remain in place. The report retains its errors and partial status.

This is a drop-in update to the coordinator's `/opt/ai-monitor/power_status.py` for an existing compatible installation. Back up the installed file, review and preserve any deployment-specific settings, then apply the policy change or install the reviewed module. Restart `ai-monitor-power-status.service` and confirm that it is active. Keep the service's existing `run.py` invocation and `/etc/ai-monitor/monitor.env`, so it uses the same model, server, and timezone as the daily build. Restore the backup and restart the same service if validation fails.

This update does not require replacing the Windows guard, regenerating pairing keys, rerunning installers, changing wake/shutdown schedules, or rebuilding a report. Existing newer Windows guard versions should be retained. Publishing the repository does not update an installed coordinator automatically.

## Full source migration

For a deliberate future migration:

1. Save the installed source and unit files, and record timer settings. Store any backup containing credentials outside Git.
2. Disable timers and wait for active build/send/publish jobs to finish. Record what was enabled so it can be restored.
3. Run the offline suite on the new release. Stage all Python modules as one dependency set; include `efficient_review.py`, `event_rollups.py`, `settings.py`, `dashboard.py`, `dashboard_progress.py`, `report_summary.py`, `issue_families.py`, `device_inventory.py`, `device_dns.py`, and `refresh_briefing.py`.
4. Create `/etc/ai-monitor/monitor.env` using the actual existing model, endpoints, and timezone. Keep existing SMB/Gmail credentials.
5. Adopt `run.py` in the installed service `ExecStart` lines or supply equivalent environment variables. Copying only the new modules would otherwise select the portable defaults.
6. Preserve NGINX ACLs and power settings. The included viewer template is for a fresh loopback-only install. Merge its `/report.html` and strictly dated `/history/YYYY-MM-DD.html` location rules into an existing viewer; keep raw files denied. Create the publication history directory with the same reader group/access as the existing public directory and verify that the service can create/read its files under its actual systemd restrictions.
7. Run collection/audit and one explicit build; verify report contents and status, then enable only the timers previously enabled.

A rollback restores the saved source/unit set and prior configuration together. Do not copy the new first-install files over an active coordinator while its services are running.

The suppression release also requires `suppression_rules.py` alongside the reporting modules, even if the interactive controls are not enabled. Preserve `event_rollups.py`, dashboard progress callbacks, portable environment settings and the static publisher. After the complete source migration, follow [FILTERS.md](FILTERS.md) for the optional web application. It keeps `/`, `/report.html`, history and the publication timer; it mounts editing controls separately at `/controls/`. Existing reports gain Ignore buttons only after a new build creates full matching signatures.

The November 1 runtime update keeps the 45-minute build limit and raises the selection cap to 4,000 groups per site. Compact batches retain the supplied evidence and require a validated answer for every selected group. Routine results use shorter replies; incomplete model replies are retried in smaller batches within the same request deadline. Review limits now produce `daily_partial`, and saved reports include `review_protocol` and `inference_metrics` for troubleshooting runtime.

New grouping rules cover AMI `RequestNotAllowed` repeats, NAS FTP logout byte totals, the shorter Kea INFO format, and File Editor's localhost HTTP 200 entries. They retain counts, time ranges and distinguishing identities; AMI denials remain errors. Because grouping signatures change for these families, existing exact-match filters for them may need to be recreated from a fresh report.
