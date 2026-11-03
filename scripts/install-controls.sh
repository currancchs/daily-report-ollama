#!/bin/bash
set -euo pipefail
test "$(id -u)" = 0 || { echo 'Run as root on the Debian coordinator.' >&2; exit 1; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# Do not mix releases or overwrite an installation-specific coordinator.
for source in "$root"/src/*.py; do
    cmp -s "$source" "/opt/ai-monitor/$(basename "$source")" || {
        echo 'Install/migrate the complete source release first; see docs/UPGRADE.md.' >&2
        exit 1
    }
done
test -f /etc/ai-monitor/monitor.env
python3 - <<'PY'
from pathlib import Path
import re
config = Path('/etc/nginx/sites-available/ai-monitor-viewer')
enabled = Path('/etc/nginx/sites-enabled/ai-monitor-viewer')
if not enabled.is_symlink() or enabled.resolve(strict=True) != config.resolve(strict=True):
    raise SystemExit('The enabled viewer must link to sites-available/ai-monitor-viewer.')
if not re.search(r'^\s*include\s+/etc/nginx/ai-monitor-controls[.]d/[*][.]conf\s*;\s*(?:#.*)?$', config.read_text(), re.M):
    raise SystemExit('Merge the controls include into the existing viewer server; keep its ACLs. See docs/FILTERS.md.')
PY
nginx -t
apt-get update
apt-get install -y python3-venv
python3 -m venv /opt/ai-monitor-web-venv
/opt/ai-monitor-web-venv/bin/python -m pip install -r "$root/requirements-web.txt"
install -d -o root -g ai-monitor -m 0750 /etc/ai-monitor-web
if test ! -e /etc/ai-monitor-web/session.key; then
    python3 - <<'PY'
import os, secrets
path='/etc/ai-monitor-web/session.key'
with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as stream:
    stream.write(secrets.token_bytes(48))
PY
    chown root:ai-monitor /etc/ai-monitor-web/session.key
    chmod 0640 /etc/ai-monitor-web/session.key
fi
runuser -u ai-monitor -- python3 -I /opt/ai-monitor/suppression_rules.py initialize
runuser -u ai-monitor -- python3 -I /opt/ai-monitor/device_inventory.py initialize
if test -f /var/lib/ai-monitor/events.sqlite; then
    runuser -u ai-monitor -- python3 -I /opt/ai-monitor/device_inventory.py refresh
fi
install -o root -g root -m 0644 "$root/systemd/ai-monitor-web.service" /etc/systemd/system/
install -d -o root -g root -m 0755 /etc/nginx/ai-monitor-controls.d
install -o root -g root -m 0644 "$root/config/nginx-controls.conf" /etc/nginx/ai-monitor-controls.d/controls.conf
nginx -t
python3 - <<'PY'
import subprocess
result = subprocess.run(['nginx', '-T'], check=True, capture_output=True, text=True)
if '# configuration file /etc/nginx/ai-monitor-controls.d/controls.conf:' not in result.stdout:
    raise SystemExit('NGINX did not load the suppression route configuration.')
PY
systemctl daemon-reload
systemctl enable --now ai-monitor-web.service
systemctl restart ai-monitor-web.service
runuser -u ai-monitor -- python3 -I /opt/ai-monitor/run.py controls_readiness --target backend
systemctl reload nginx
runuser -u ai-monitor -- python3 -I /opt/ai-monitor/run.py controls_readiness --target viewer
# Publish links only after the actual page is reachable through NGINX.
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/ai-monitor/monitor.env')
lines=[line for line in p.read_text().splitlines() if not line.strip().startswith('AI_MONITOR_CONTROLS=')]
p.write_text('\n'.join(lines+['AI_MONITOR_CONTROLS=1'])+'\n')
PY
runuser -u ai-monitor -- python3 -I /opt/ai-monitor/run.py publish_report
echo 'Controls enabled at the configured viewer origin under /controls/.'
echo 'Build a new report to enable Ignore buttons. NAS tasks, mail and power schedules were not changed.'
