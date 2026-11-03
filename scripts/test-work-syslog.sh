#!/usr/bin/env bash
# Run as root on Proxmox. No arguments tests the three work guests configured here.
set -uo pipefail
if [[ ${1:-} == --help ]]; then
    echo 'Usage: test-work-syslog [100 101 102]'
    exit 0
fi
for command in pct qm python3 timeout; do
    command -v "$command" >/dev/null || { echo "Missing $command; run on Proxmox." >&2; exit 1; }
done
targets=("$@")
((${#targets[@]})) || targets=(100 101 102)
declare -A seen=()
for id in "${targets[@]}"; do
    case "$id" in 100|101|102) ;; *) echo "Unsupported guest: $id" >&2; exit 1 ;; esac
done
runid=$(date +%s)
marker="WORK-SYSLOG-CHECK-$runid"
failed=0
expected=0

linux_test=$(cat <<'LINUX_TEST'
set -euo pipefail
export LC_ALL=C
app="$1"; conf="$2"; marker="$3"; runid="$4"
test -s "$conf" || { echo "Missing custom configuration: $conf" >&2; exit 1; }
systemctl is-active --quiet rsyslog || { echo 'rsyslog is not running' >&2; exit 1; }
if ! systemctl is-enabled --quiet rsyslog; then
    echo 'WARNING: rsyslog is not enabled at boot' >&2
fi
validation=$(rsyslogd -N1 2>&1) || { printf '%s\n' "$validation" >&2; exit 1; }
emit() {
    test -f "$1" || { echo "Log is missing: $1" >&2; return 1; }
    printf '%s\n%s\n' "$2" "$3" >> "$1"
}
ts=$(date '+%Y-%m-%d %H:%M:%S')
pass="$marker-PASS-$app"
drop="$marker-DROP-$app"
case "$app" in
    zwave)
        emit /opt/zwave_store/logs/zwavejs_current.log \
            "$ts $drop DRIVER all queues idle" "$ts $pass: manual forwarding check"
        ;;
    pbx)
        logger -p local0.warning -t work-syslog-check -- "$pass: manual forwarding check"
        ;;
esac
LINUX_TEST
)

ha_test=$(cat <<'HA_TEST'
set -eu
marker="$3"
docker ps --format '{{.Names}} {{.Image}}' | grep -Eq 'mib85/[^ ]+-ha-addon-syslog:' || {
    echo 'Expected Syslog add-on is not running' >&2; exit 1;
}
command -v systemd-cat >/dev/null || {
    echo 'systemd-cat is unavailable on HAOS; journal probe needs adjustment' >&2; exit 1;
}
printf '%s\n' "$marker-PASS-homeassistant: manual forwarding check" |
    systemd-cat --identifier=work-syslog-check --priority=warning
HA_TEST
)

vm_exec() {
    local result
    result=$(timeout 40 qm guest exec "$1" --synchronous 1 --timeout 25 -- \
        "$2" -c "$3" -- "$4" "$5" "$marker" "$runid") || return
    printf '%s\n' "$result" | python3 -c '
import json, sys
try:
    r = json.load(sys.stdin)
except (ValueError, TypeError) as e:
    raise SystemExit("Invalid guest-agent response: " + str(e))
for key, stream in (("out-data", sys.stdout), ("err-data", sys.stderr)):
    if r.get(key): print(r[key], end="", file=stream)
if r.get("exited") != 1:
    raise SystemExit("Guest test did not finish within the timeout; receipt is unconfirmed")
if r.get("exitcode") != 0:
    raise SystemExit("Guest test failed: exit=" + str(r.get("exitcode")) + ", signal=" + str(r.get("signal")))
if r.get("out-truncated") or r.get("err-truncated"):
    raise SystemExit("Guest output was truncated; inspect the guest before retrying")
'
}

printf 'Run ID: %s\n' "$runid"
for id in "${targets[@]}"; do
    [[ ${seen[$id]:-} == yes ]] && continue
    seen[$id]=yes
    mode=pct; shell=/bin/bash; code="$linux_test"; count=1; level=Warning
    case "$id" in
        100) app=pbx; config=61-asterisk-to-nas.conf; mode=qm ;;
        101) app=zwave; config=30-zwave-driver.conf; level=Info ;;
        102) app=homeassistant; config=''; mode=qm; shell=/bin/sh; code="$ha_test" ;;
    esac
    printf '\n%s %s: ' "$id" "$app"
    if ! "$mode" status "$id" 2>/dev/null | grep -q 'status: running'; then
        echo 'FAIL: guest is not running or unavailable'; failed=1; continue
    fi
    if [[ "$mode" == qm ]]; then
        vm_exec "$id" "$shell" "$code" "$app" "/etc/rsyslog.d/$config"
        rc=$?
    else
        timeout 40 pct exec "$id" -- "$shell" -c "$code" -- \
            "$app" "/etc/rsyslog.d/$config" "$marker" "$runid"
        rc=$?
    fi
    if ((rc == 0)); then
        echo "WROTE TESTS; expect $count PASS entry/entries, level: $level"
        expected=$((expected + count))
    else
        echo 'FAIL: test could not complete'; failed=1
    fi
done
printf '\nWait 10 seconds, then search ALL Synology hosts and severities for: %s\n' "$runid"
printf 'Expect %s PASS entries from guests that completed the test.\n' "$expected"
echo 'Expect ZERO DROP entries (Z-Wave queue-noise probe).'
echo 'Receipt on Synology confirms delivery. Missing entries, duplicates or wrong levels need investigation.'
echo 'These probes test the configured inputs and filters; normal application log generation is a separate check.'
if ((failed)); then echo 'One or more probes failed; a failed probe may have written partial test entries.'; fi
exit "$failed"
