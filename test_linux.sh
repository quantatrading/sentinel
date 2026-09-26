#!/usr/bin/env bash
# Integration test ONLY for a disposable Ubuntu 24.04 VM with systemd and resolved.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
[[ ${EUID} == 0 && ${SENTINEL_TEST_DISPOSABLE:-} == yes ]] || {
    echo 'Run as root on a disposable VM with SENTINEL_TEST_DISPOSABLE=yes.' >&2; exit 1;
}
[[ ! -e /etc/systemd/system/sentinel.service && ! -e /var/lib/sentinel && ! -e /etc/sentinel ]] || {
    echo 'Refusing to touch an existing Sentinel installation.' >&2; exit 1;
}
staging=$(mktemp -d)
trap 'rm -rf -- "$staging"' EXIT
install -m 0600 sentinel.json.example "$staging/config.json"
cat > "$staging/config.env" <<'ENV'
TELEGRAM_BOT_TOKEN=123:INVALID_INTEGRATION_TEST_TOKEN_ONLY
TELEGRAM_CHAT_IDS=123
TELEGRAM_USER_IDS=123
ENV
chmod 0600 "$staging/config.env"
./install.sh "$staging/config.json" "$staging/config.env"
main_pid=$(systemctl show sentinel --property=MainPID --value)
expected_uid=$(id -u sentinel-watchdog)
python3 - "$main_pid" "$expected_uid" <<'PY'
from pathlib import Path
import sys
status = dict(line.split(':', 1) for line in Path('/proc', sys.argv[1], 'status').read_text().splitlines())
assert all(int(x) == int(sys.argv[2]) for x in status['Uid'].split()), status['Uid']
assert int(status['CapEff'].strip(), 16) == 0, status['CapEff']
assert int(status['CapPrm'].strip(), 16) == 0, status['CapPrm']
assert status['NoNewPrivs'].strip() == '1'
print('Main UID, effective/permitted capabilities and no-new-privileges verified.')
PY
python3 -I /opt/sentinel/sentinel.py --health-check
systemd-analyze verify /etc/systemd/system/sentinel.service
# Exercise the installed host-check module without modifying host security configuration.
python3 -I - <<'PY_CHECKS'
import sys
sys.path.insert(0, '/opt/sentinel')
import sentinel_checks as checks
result = checks.HostChecks().sample()
assert result['health']['listeners_tools'] == 'ok', result['health']
assert result['baseline']['status'] == 'not approved', result['baseline']
assert isinstance(result['reboot_required'], bool)
assert 'sha256' in result['package_inventory'], result['package_inventory']
print('Installed host checks and missing-baseline reporting verified.')
PY_CHECKS
# A stopped main loop must trigger the service watchdog, even if the root collector lives.
systemctl kill --kill-whom=main --signal=STOP sentinel
for attempt in $(seq 1 30); do
    sleep 5
    replacement=$(systemctl show sentinel --property=MainPID --value)
    if [[ "$replacement" != 0 && "$replacement" != "$main_pid" ]] && systemctl is-active --quiet sentinel && python3 -I /opt/sentinel/sentinel.py --health-check >/dev/null 2>&1; then
        break
    fi
done
[[ "$replacement" != 0 && "$replacement" != "$main_pid" ]] || { echo 'Watchdog restart failed'; exit 1; }
/opt/sentinel/uninstall.sh --yes
[[ ! -e /opt/sentinel && ! -e /etc/sentinel && ! -e /var/lib/sentinel && ! -e /run/sentinel ]]
! id sentinel-watchdog >/dev/null 2>&1
echo 'Linux integration passed: installation, unprivileged main, bad-token tolerance, watchdog restart, uninstall.'
