#!/bin/bash
set -euo pipefail
test "$(id -u)" = 0 || { echo 'Run as root on Debian 12/13.' >&2; exit 1; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test -f "$root/src/daily_job.py"
# A first-install path. Existing deployments need a reviewed upgrade, not an overwrite.
test ! -e /opt/ai-monitor || { echo '/opt/ai-monitor exists; stop and follow docs/UPGRADE.md.' >&2; exit 1; }
apt-get update
apt-get install -y python3 tzdata smbclient nginx-light curl
getent passwd ai-monitor >/dev/null || useradd --system --home /var/lib/ai-monitor --shell /usr/sbin/nologin ai-monitor
install -d -o root -g ai-monitor -m 0750 /etc/ai-monitor
install -d -o root -g root -m 0755 /opt/ai-monitor
install -d -o ai-monitor -g ai-monitor -m 0750 /var/lib/ai-monitor /var/lib/ai-monitor/reports
install -d -o ai-monitor -g www-data -m 2750 /srv/ai-monitor-report
install -o root -g root -m 0644 "$root"/src/*.py /opt/ai-monitor/
install -o root -g root -m 0644 "$root/scripts/run.py" /opt/ai-monitor/run.py
for name in monitor.env home.smb work.smb; do
    test -e "/etc/ai-monitor/$name" || install -o root -g ai-monitor -m 0640 "$root/config/$name.example" "/etc/ai-monitor/$name"
done
install -o root -g root -m 0644 "$root"/systemd/* /etc/systemd/system/
install -o root -g root -m 0644 "$root/config/nginx-viewer.conf" /etc/nginx/sites-available/ai-monitor-viewer
test ! -e /etc/nginx/sites-enabled/ai-monitor-viewer || { echo 'Viewer link already exists; inspect before enabling.' >&2; exit 1; }
ln -s /etc/nginx/sites-available/ai-monitor-viewer /etc/nginx/sites-enabled/ai-monitor-viewer
nginx -t
systemctl daemon-reload
runuser -u ai-monitor -- python3 -I /opt/ai-monitor/run.py publish_report
systemctl reload nginx
echo 'Installed. Timers are NOT enabled. Configure NAS exports and monitor.env, then follow docs/SETUP.md.'
