# File guide

## Python source

| File | Purpose |
|---|---|
| `src/collect_sites.py` | Retrieve and verify Home/Work exports via SMB or read-only mounts. |
| `src/controls_readiness.py` | Wait for the real suppression page before the installer publishes links. |
| `src/daily_job.py` | Schedule-aware build, report integrity checks, retention and separate delivery. |
| `src/daily_report.py` | Full-window aggregation, balanced selection, AI review budgets and reporting. |
| `src/dashboard.py` | Render checked Home/Work summaries, coverage, timeline and dated history. |
| `src/dashboard_progress.py` | Write best-effort atomic stage/batch/wake progress records. |
| `src/event_rollups.py` | Recognize specific repetitive event families and retain distinguishing evidence. |
| `src/efficient_review.py` | Compact evidence/replies, complete group validation, bounded split retries and inference timing. |
| `src/gmail_report.py` | Interactive local Gmail configuration and TLS SMTP delivery/deduplication. |
| `src/html_report.py` | Escape and render bounded HTML from report metadata. |
| `src/import_synology.py` | Validate archives and deduplicate/redact newly imported SQLite events. |
| `src/nas_export_recent.py` | Read supported NAS table schemas into bounded snapshots. |
| `src/nas_export_site.py` | Discover source databases/archives and atomically publish export manifests. |
| `src/power_status.py` | Optional read-only signed completion service. |
| `src/preview_report.py` | Shared model/schema/privacy helpers and legacy preview CLI. |
| `src/publish_report.py` | Publish a verified dashboard, current report and dated HTML history; fail closed on invalid data. |
| `src/sanitize_logs.py` | Best-effort credential-pattern redaction. |
| `src/settings.py` | Read non-secret environment configuration and validate local model endpoint. |
| `src/suppression_rules.py` | Exact normalized-group filters, expiry, reversible deletion and SQLite audit. |
| `src/report_web.py` | Verified issue view, Ignore confirmation, suppressed issues and filter-management forms. |
| `src/wake_ollama.py` | Optional configured Wake-on-LAN sender and readiness wait. |

## Installation and operations

- `scripts/install-coordinator.sh`: guarded first install for Debian; leaves timers disabled.
- `scripts/install-controls.sh`: optional controls service/dependencies on a matching installed release; preserves dashboard/history and network ACLs.
- `config/nginx-controls.conf`: optional `/controls/` proxy route inside the existing viewer server.
- `requirements-web.txt`: Flask/Gunicorn for the optional web service.
- `scripts/run.py`: loads `monitor.env` without evaluating shell code, then runs a component.
- `scripts/nas-daily-export.sh`: DSM scheduled-task wrapper.
- `scripts/Install-OllamaPowerGuard.ps1` and `Ollama-PowerGuard.ps1`: optional Windows power controls.
- `scripts/test.py`: run the offline regression programs.
- `systemd/`: build, delivery and publication services/timers.
- `config/`: non-secret templates, loopback NGINX config, and optional power-unit examples.

## Evidence and documentation

- `tests/`: synthetic regression fixtures and offline checks.
- `examples/`: synthetic HTML preview and matching JSON; not real device status.
- `docs/SETUP.md`: complete prerequisites, configuration and commands.
- `docs/POWER.md`: optional wake and shutdown setup.
- `docs/FILTERS.md`: matching semantics, installation, verification and filter-store operations.
- `src/device_inventory.py` and `docs/DEVICES.md`: observed device aliases, retirement, restoration and permanent exclusions without deleting events.
- `docs/UPGRADE.md`: existing-install migration boundaries.
- `docs/ARCHITECTURE.md`: implementation and dashboard roadmap.
- `SECURITY.md`: data boundaries and publishing exclusions.
- `LICENSE`: MIT license for the reusable source/documentation.
- `.github/workflows/checks.yml`: Linux CI runner for offline tests and shell syntax.

The package intentionally omits old installation-specific upgrade wrappers, real NAS snapshots, credentials, pairing keys, model weights, screenshot captures of live logs, and unrelated troubleshooting files.
