#!/usr/bin/env bash
# Run as root on Proxmox. No arguments tests the ten guests configured here.
set -uo pipefail
if [[ ${1:-} == --help ]]; then
    echo 'Usage: test-remote-syslog [100 101 102 103 104 105 106 107 108 109]'
    exit 0
fi
for command in pct qm python3 timeout; do
    command -v "$command" >/dev/null || { echo "Missing $command; run on Proxmox." >&2; exit 1; }
done
targets=("$@")
((${#targets[@]})) || targets=(100 101 102 103 104 105 106 107 108 109)
declare -A seen=()
for id in "${targets[@]}"; do
    case "$id" in 10[0-9]) ;; *) echo "Unsupported guest: $id" >&2; exit 1 ;; esac
done
runid=$(date +%s)
marker="SYSLOG-CHECK-$runid"
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
latest_log() {
    local candidate newest=''
    for candidate in "$@"; do
        test -f "$candidate" || continue
        if [[ -z "$newest" || "$candidate" -nt "$newest" ]]; then newest="$candidate"; fi
    done
    test -n "$newest" || { echo 'No matching application log found' >&2; return 1; }
    printf '%s\n' "$newest"
}
ts=$(date '+%Y-%m-%d %H:%M:%S')
pass="$marker-PASS-$app"
drop="$marker-DROP-$app"
case "$app" in
    plex)
        emit '/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Logs/Plex Media Server.log' \
            "[syslog-test] INFO - $drop: manual filter check" \
            "[syslog-test] WARN - $pass: manual forwarding check"
        ;;
    zwave)
        emit /opt/zwave_store/logs/zwavejs_current.log \
            "$ts $drop DRIVER all queues idle" "$ts $pass: manual forwarding check"
        ;;
    freepbx)
        # The filter requires this exact message shape. Use the run ID as its
        # synthetic UID so searching the numeric run ID also finds a filter leak.
        logger -p cron.info -t CRON -- \
            "pam_unix(cron:session): session opened for user asterisk(uid=$runid) by (uid=0)"
        logger -p user.warning -t syslog-check -- "$pass: manual forwarding check"
        ;;
    immich)
        test -f /var/log/immich/web.log && test -f /var/log/immich/ml.log || {
            echo 'An Immich log is missing' >&2; exit 1;
        }
        us=$(date '+%m/%d/%Y, %I:%M:%S %p')
        esc=$(printf '\033')
        emit /var/log/immich/web.log \
            "${esc}[32m[Nest] 999999 - $us LOG [SyslogTest] $drop-web${esc}[0m" \
            "${esc}[33m[Nest] 999999 - $us WARN [SyslogTest] $pass-web${esc}[0m"
        emit /var/log/immich/ml.log \
            "${esc}[32m[$ts] INFO $drop-ml${esc}[0m" \
            "${esc}[33m[$ts] WARNING $pass-ml${esc}[0m"
        ;;
    heimdall)
        log=$(latest_log /opt/Heimdall/storage/logs/laravel-[0-9]*.log)
        emit "$log" "[$ts] production.INFO: $drop" "[$ts] production.WARNING: $pass"
        ;;
    jellyfin)
        log=$(latest_log /var/log/jellyfin/jellyfin[0-9]*.log)
        emit "$log" "[$ts] [INF] $drop" "[$ts] [WRN] $pass"
        ;;
    qbittorrent)
        emit /var/log/qbittorrent/qbittorrent.log \
            "(N) ${ts/ /T} - $drop" "(W) ${ts/ /T} - $pass"
        ;;
    openwebui)
        for message in "INFO: $drop" "WARNING: $pass"; do
            printf 'SYSLOG_IDENTIFIER=open-webui\nPRIORITY=6\nMESSAGE=%s\n' "$message" | logger --journald
        done
        ;;
    ai-monitor)
        systemd-run --quiet --wait --collect \
            --unit="ai-monitor-syslog-check-$marker" \
            --property=StandardOutput=journal --property=SyslogLevel=info \
            /usr/bin/python3 -c 'import sys; print("INFO: " + sys.argv[1]); print("WARNING: " + sys.argv[2])' \
            "$drop" "$pass"
        ;;
esac
LINUX_TEST
)

ha_test=$(cat <<'HA_TEST'
set -eu
marker="$3"
docker ps --format '{{.Names}}' | grep -Eq '(^|_)logspout$' || {
    echo 'Logspout is not running' >&2; exit 1;
}
test "$(docker inspect --format '{{.State.Running}}' homeassistant)" = true || {
    echo 'Home Assistant container is not running' >&2; exit 1;
}
# Write to the main container log stream, which Logspout actually collects.
docker exec -i --user 0 homeassistant python3 - "$marker" <<'HA_PY'
import datetime, os, stat, sys
path = "/proc/1/fd/2"
if not stat.S_ISFIFO(os.stat(path).st_mode):
    raise SystemExit("Home Assistant stderr is not a pipe; test was not written")
message = (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
           + " ERROR (MainThread) [syslog_check] " + sys.argv[1]
           + "-PASS-homeassistant: manual forwarding check\n").encode()
fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
try:
    if os.write(fd, message) != len(message):
        raise SystemExit("Incomplete Home Assistant test write")
finally:
    os.close(fd)
HA_PY
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
        100) app=homeassistant; config=''; mode=qm; shell=/bin/sh; code="$ha_test"; level='Logspout-defined (normally Error)' ;;
        101) app=plex; config=30-plex.conf ;;
        102) app=zwave; config=30-zwave-driver.conf; level=Info ;;
        103) app=freepbx; config=60-remote.conf; mode=qm ;;
        104) app=immich; config=30-immich.conf; count=2 ;;
        105) app=heimdall; config=30-heimdall.conf ;;
        106) app=jellyfin; config=30-jellyfin.conf ;;
        107) app=qbittorrent; config=30-qbittorrent.conf ;;
        108) app=openwebui; config=30-openwebui.conf ;;
        109) app=ai-monitor; config=30-ai-monitor.conf ;;
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
echo 'Expect ZERO DROP entries and ZERO CRON entries containing this run ID.'
echo 'Receipt on Synology confirms delivery. Missing entries, duplicates or wrong levels need investigation.'
echo 'These probes test the configured inputs and filters; normal application log generation is a separate check.'
if ((failed)); then echo 'One or more probes failed; a failed probe may have written partial test entries.'; fi
exit "$failed"
