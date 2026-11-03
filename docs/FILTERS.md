# Ignore recurring issues

The optional **Issues & filters** web application adds an **Ignore…** button beside each reported issue. The confirmation shows the matching scope and defaults to **Until I remove it**. Optional durations are 24 hours, 7 days, or 30 days, with an optional reason.

- **Issues** shows the current report's findings with current filters applied.
- **Suppressed issues** shows matching groups present in the saved report, including groups excluded before AI review.
- **Filters** lists active and expired rules, their scope, reason and expiry. Delete a rule to make matching messages eligible for future builds again.

For example, a Home Assistant sensor temporarily without power can be ignored until repaired. The match includes site, source, host/IP, program, reported severity, tag and the full normalized message. A different device, site or error remains distinct. A recognized rollup can combine varying fields; the confirmation explains this scope. This is not a free-text or AI-summary matching rule.

Filters are captured once at the start of grouping and applied before group selection and Ollama review. Suppressed counts remain visible. A failed filter read keeps all logs eligible and raises a report warning. Neither ignoring nor deleting a rule changes the NAS logs, imported history, or already-built/emailed reports. Restored groups that were excluded from a saved build are marked as awaiting the next review. The page is a view of saved evidence, not a live device-health check.

## Enable on a fresh portable installation

First complete [SETUP.md](SETUP.md). From the same source checkout used for installation:

```bash
sudo bash scripts/install-controls.sh
```

This installs Flask and Gunicorn in a dedicated virtual environment, creates the SQLite filter store and a local random session key, enables `ai-monitor-web.service`, adds the NGINX controls route, and publishes dashboard links. It does not enable build/email/power timers. Software installation needs Internet access. The core collector and build still use standard-library Python.

Before publishing those links, the installer checks the enabled NGINX configuration and waits up to 25 seconds each for the backend and the reloaded viewer route. A brief startup connection failure or reload-time 404 can recover; a persistent failure stops the installer with an error. The checks only read the filters page and use the configured viewer origin.

Open `http://127.0.0.1:8088/controls/` using the existing SSH-forwarding instructions. Keep the browser's hostname and port identical to `AI_MONITOR_VIEWER_ORIGIN` in `/etc/ai-monitor/monitor.env`. The default is `http://127.0.0.1:8088`. A new report built with this release is required for Ignore buttons; older snapshots do not contain trustworthy full matching signatures.

The static overview at `/`, current saved HTML at `/report.html`, dated history and five-minute publication timer remain available. The new application is mounted only at `/controls/`; opening it makes no NAS, Ollama or SMTP calls.

## Upgrade an existing installation

Follow [UPGRADE.md](UPGRADE.md) to migrate the complete source set and its environment configuration first. The controls installer compares every installed source module with this checkout and refuses mixed or installation-specific releases. Keep the `ai-monitor-publish` service/timer; this portable upgrade does not replace the dashboard.

Inside the existing NGINX viewer `server` block, add this line without changing its listener, firewall or allow/deny rules:

```nginx
include /etc/nginx/ai-monitor-controls.d/*.conf;
```

Then run the controls installer above. It creates the optional include directory and snippet. Do not replace a LAN-restricted server with a broadly listening template. For LAN/VPN access, set `AI_MONITOR_VIEWER_ORIGIN` to the exact private IP origin used by the browser, preserve the existing allowlist, and restart `ai-monitor-web.service` after configuration changes. Only one origin is accepted. The application does not trust client-supplied forwarding headers.

## Verify and operate

```bash
systemctl status ai-monitor-web.service --no-pager
nginx -t
curl --fail http://127.0.0.1:8088/controls/filters
```

Use your configured origin in the last command if you changed it. On a newly built report, save one appropriate filter, check Suppressed issues and Filters, then delete it and confirm the message is eligible again. These actions require the web forms; GET links never change filters. The application uses same-origin checks, CSRF tokens and escaped content. Anyone with network access allowed by the viewer can manage filters: there is no separate login. Keep this service private; see [SECURITY.md](../SECURITY.md).

The filter store is `/var/lib/ai-monitor/suppressions/filters.sqlite` with an audit of creation/deletion. Back it up using SQLite's backup API, or stop the web service and build jobs before copying its database/WAL files together. The session key lives in `/etc/ai-monitor-web/session.key`. Neither belongs in Git or the public web root.

To disable editing, stop/disable `ai-monitor-web.service`, remove its NGINX include file, test/reload NGINX, and set `AI_MONITOR_CONTROLS=0`. Existing filters still affect builds until deleted through the UI or intentionally cleared as part of a database maintenance operation; disabling the UI alone does not restore messages. Retain the store for rollback/audit. The release has offline coverage for the filter and HTTP behavior; the optional installer still needs verification on a fresh Debian machine.

Implementation references: [Flask with Gunicorn](https://flask.palletsprojects.com/en/stable/deploying/gunicorn/) and [Werkzeug path dispatch](https://werkzeug.palletsprojects.com/en/stable/middleware/dispatcher/).
