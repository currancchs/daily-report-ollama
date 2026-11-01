#!/bin/sh
set -eu
# Set this to the Python 3 executable installed through Synology Package Center.
PYTHON=${PYTHON:-/usr/local/bin/python3}
ROOT=${ROOT:-/volume1/Logs}
SITE=${SITE:?Set SITE to home or work}
exec "$PYTHON" "$ROOT/AI-Monitor-Code/nas_export_site.py" --root "$ROOT" --site "$SITE" --hours 72 --keep-runs 3
