# Existing installation

This package is a portable source release, not an automatic patch for an existing system. The first-install script refuses `/opt/ai-monitor` when it already exists.

For my working installation, publishing this source repository does not require reinstalling anything. Keep existing NAS tasks, schedules, Gmail configuration, pairing keys, and viewer access rules.

For a deliberate future migration:

1. Save the installed source and unit files, and record timer settings. Store any backup containing credentials outside Git.
2. Disable timers and wait for active build/send/publish jobs to finish. Record what was enabled so it can be restored.
3. Run the offline suite on the new release. Stage all Python modules as one dependency set; include `event_rollups.py`, `settings.py`, `dashboard.py`, and `dashboard_progress.py`.
4. Create `/etc/ai-monitor/monitor.env` using the actual existing model, endpoints, and timezone. Keep existing SMB/Gmail credentials.
5. Adopt `run.py` in the installed service `ExecStart` lines or supply equivalent environment variables. Copying only the new modules would otherwise select the portable defaults.
6. Preserve NGINX ACLs and power settings. The included viewer template is for a fresh loopback-only install. Merge its `/report.html` and strictly dated `/history/YYYY-MM-DD.html` location rules into an existing viewer; keep raw files denied. Create the publication history directory with the same reader group/access as the existing public directory and verify that the service can create/read its files under its actual systemd restrictions.
7. Run collection/audit and one explicit build; verify report contents and status, then enable only the timers previously enabled.

A rollback restores the saved source/unit set and prior configuration together. Do not copy the new first-install files over an active coordinator while its services are running.

The suppression release also requires `suppression_rules.py` alongside the reporting modules, even if the interactive controls are not enabled. Preserve `event_rollups.py`, dashboard progress callbacks, portable environment settings and the static publisher. After the complete source migration, follow [FILTERS.md](FILTERS.md) for the optional web application. It keeps `/`, `/report.html`, history and the publication timer; it mounts editing controls separately at `/controls/`. Existing reports gain Ignore buttons only after a new build creates full matching signatures.
