# Daily Report + Ollama

A local AI log-review pipeline for two Synology Log Center sites, called **home** and **work**. A Linux coordinator collects the logs, groups repeated messages, asks a local Ollama model to review them, and produces a daily HTML/text digest. A private browser dashboard, dated report history, and optional Gmail delivery use the saved result.

```text
Home devices → Home Synology ─┐
                             ├→ verified exports → SQLite → grouping → local Ollama
Work devices → Work Synology ┘                                        ↓
                                                private viewer ← saved digest → optional Gmail
```

This is a reusable adaptation of my setup, prepared October 31, 2026. Personal endpoints and hardware identifiers have been replaced with configuration. The original setup uses an RTX 3090 and `qwen3.6:27b`; this package defaults to `qwen3:8b` as a smaller configurable example. No model weights, live reports, NAS databases, passwords, or pairing keys are included.

## Start here

- [Complete setup, including exact commands](docs/SETUP.md)
- [What each file does](docs/FILES.md)
- [Current capabilities and dashboard roadmap](docs/ARCHITECTURE.md)
- [Privacy and data boundaries](SECURITY.md)
- [Existing-install upgrade notes](docs/UPGRADE.md)
- [Optional Wake-on-LAN and shutdown guard](docs/POWER.md)
- [Optional Ignore buttons, suppressed issues and filter management](docs/FILTERS.md)
- [Synthetic dashboard preview](examples/dashboard/index.html)
- [Synthetic Ignore / Suppressed / Filters preview](examples/controls/report.html)
- [Synthetic report preview](examples/nightly-report-preview.html)

The default installation does **not** enable timers, send mail, or arm shutdown. Setup enables each explicitly after its checks. The report viewer initially listens on loopback and can be reached through SSH forwarding.

## Offline preview and checks

Requires Python 3.11+ on the coordinator/development machine. The NAS exporter is compatible with Python 3.8+ and uses only the standard library. Install the test dependencies (Flask, plus timezone data on Windows) first:

```powershell
py -3 -m pip install -r requirements-dev.txt
py -3 scripts/test.py
Start-Process .\examples\nightly-report-preview.html
```

Linux:

```bash
python3 -m pip install -r requirements-dev.txt
python3 scripts/test.py
```

Tests use synthetic SQLite databases and simulated Ollama/SMTP responses. They do not send email, contact your NAS, run a model, or shut down a computer. Generated test scratch data stays under ignored `work/`.

## What is implemented

- Four Synology table schemas, export manifests/checksums, ZIP validation, deduplication, and archive catch-up.
- Credential-pattern redaction before new records enter the coordinator history.
- Event-family rollups, preserved counts/timestamps, and priority/source balancing.
- Structured model replies with evidence-ID validation and bounded runtime.
- Compact review batches, shorter replies for routine logs, and request timing to help keep the nightly build within 45 minutes.
- Civil-date report windows, separate build/delivery, failure notices, and duplicate-send protection.
- Verified, escaped HTML publication for the current nightly report and up to 30 days of dated history.
- Home/Work overview cards, source coverage, nightly stage timestamps, and batch progress records.
- Optional issue controls: Ignore until removed (or for a chosen duration), inspect suppressed issues, and delete filters to restore future messages. Exact group matches are excluded before AI review, with visible suppression counts and preserved original logs.
- Optional signed completion endpoint, Wake-on-LAN sender, and Windows shutdown guard.

This source release includes the dashboard update installed and checked on the original coordinator. The portable adaptation passes offline tests; the fresh Debian installer still requires validation in a separate new environment. Search, volume charts, acknowledgments, and automatic browser polling remain future work. Current site names are `home` and `work`, and the transport expects a share named `Logs` containing `AI-Monitor-Exports`. Renaming those requires code changes. The exporter expects supported Log Center schemas; arbitrary syslog files need another adapter.

The suppression upgrade is implemented and tested offline; installation on the original coordinator is not yet confirmed. The optional web controls use Flask and Gunicorn, stay under `/controls/`, and retain the existing static dashboard and history. The installer now waits for the page to be ready after NGINX reloads. Read [FILTERS.md](docs/FILTERS.md) before enabling them.

In my November 1 replay, the faster review processed all 3,902 groups saved in that morning's report in about 20 minutes. The old run had reviewed 2,060 before reaching its time budget. That leaves useful headroom, though it isn't a guarantee for every day: the replay didn't include the 873 groups left out by the old cap. The cap is now 4,000 groups per site, with the same 45-minute build limit; unfinished reviews are marked partial.

The collector and reporting core use standard-library Python. NGINX, smbclient, systemd, Synology, and Ollama are separate prerequisites. Source is MIT licensed; external software and downloaded models retain their own licenses.
