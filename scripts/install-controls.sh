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
grep -Fq 'include /etc/nginx/ai-monitor-controls.d/*.conf;' /etc/nginx/sites-available/ai-monitor-viewer || {
    echo 'Merge the controls include into your existing viewer server; keep its ACLs. See docs/FILTERS.md.' >&2
    exit 1
}
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
install -o root -g root -m 0644 "$root/systemd/ai-monitor-web.service" /etc/systemd/system/
install -d -o root -g root -m 0755 /etc/nginx/ai-monitor-controls.d
install -o root -g root -m 0644 "$root/config/nginx-controls.conf" /etc/nginx/ai-monitor-controls.d/controls.conf
nginx -t
systemctl daemon-reload
systemctl enable --now ai-monitor-web.service
systemctl restart ai-monitor-web.service
systemctl reload nginx
# Only expose dashboard links after the web service starts. Preserve other settings.
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/ai-monitor/monitor.env')
lines=[line for line in p.read_text().splitlines() if not line.strip().startswith('AI_MONITOR_CONTROLS=')]
p.write_text('\n'.join(lines+['AI_MONITOR_CONTROLS=1'])+'\n')
PY
runuser -u ai-monitor -- python3 -I /opt/ai-monitor/run.py publish_report
echo 'Controls enabled at the configured viewer origin under /controls/.'
echo 'Build a new report to enable Ignore buttons. NAS tasks, mail and power schedules were not changed.'
