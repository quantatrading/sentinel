#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ${EUID} -ne 0 || $(uname -s) != Linux ]]; then
    echo 'Run this installer as root on Ubuntu 24.04 LTS.' >&2
    exit 1
fi
# This detects altered files. Authenticity additionally needs an independently trusted pin.
if [[ -n ${SENTINEL_EXPECTED_MANIFEST_SHA256:-} ]]; then
    [[ $SENTINEL_EXPECTED_MANIFEST_SHA256 =~ ^[a-fA-F0-9]{64}$ ]] || { echo 'Invalid manifest pin'; exit 1; }
    manifest_digest=$(sha256sum SHA256SUMS)
    [[ ${manifest_digest%% *} == "$SENTINEL_EXPECTED_MANIFEST_SHA256" ]] || { echo 'Manifest pin mismatch'; exit 1; }
fi
sha256sum --check --strict SHA256SUMS
. /etc/os-release
if [[ ${ID:-} != ubuntu || ${VERSION_ID:-} != 24.04 ]]; then
    echo 'Only Ubuntu 24.04 LTS is supported by this installer.' >&2
    exit 1
fi
for program in /usr/bin/python3 /usr/bin/systemctl /usr/bin/journalctl /usr/bin/resolvectl /usr/bin/systemd-analyze /usr/sbin/useradd; do
    [[ -x "$program" ]] || { echo "Missing prerequisite: $program" >&2; exit 1; }
done
[[ -d /run/systemd/system ]] || { echo 'systemd must be running.' >&2; exit 1; }
/usr/bin/systemctl is-active --quiet systemd-resolved || {
    echo 'systemd-resolved must already be active. Sentinel will not change your DNS configuration.' >&2
    exit 1
}
echo 'Sentinel installation:'
echo '  Install application in /opt/sentinel (root-owned, read-only to service).'
echo '  Store secrets in /etc/sentinel/sentinel.env (0600).'
echo '  Store configuration and bounded state in /var/lib/sentinel/sentinel.json (0600).'
echo '  Install, enable and start sentinel.service; updates restart Sentinel only.'
echo '  No firewall, DNS, Gunbot or networking configuration will be changed.'
if [[ $# -ne 0 && $# -ne 2 ]]; then
    echo 'Usage: sudo ./install.sh [prepared.json prepared.env]' >&2
    exit 1
fi
if [[ $# -eq 2 ]]; then
    [[ ! -e /var/lib/sentinel/sentinel.json && ! -e /etc/sentinel/sentinel.env ]] || {
        echo 'Existing configuration found. Edit it in place; rerun without arguments to upgrade.' >&2
        exit 1
    }
    /usr/bin/python3 -I sentinel.py --config "$1" --check-config
    # Parse only the supported KEY=value format, never source a secrets file as shell code.
    /usr/bin/python3 - "$2" <<'PY'
import os, re, stat, sys
from pathlib import Path
p = Path(sys.argv[1])
s = p.stat()
if s.st_uid != 0 or stat.S_IMODE(s.st_mode) != 0o600 or p.is_symlink():
    sys.exit('Prepared environment file must be root-owned, mode 0600 and not a symlink')
values = {}
for line in p.read_text().splitlines():
    if not line.strip() or line.lstrip().startswith('#'):
        continue
    key, separator, value = line.partition('=')
    if not separator or key not in ('TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_IDS', 'TELEGRAM_USER_IDS') or key in values:
        sys.exit('Invalid environment file; use the example KEY=value format')
    values[key] = value
os.environ.update(values)
sys.path.insert(0, str(Path.cwd()))
from sentinel import Telegram
import queue, threading
try:
    Telegram(queue.Queue(), queue.Queue(), threading.Event(), 0)
except ValueError:
    sys.exit('Invalid Telegram credentials or ID lists; see sentinel.env.example')
PY
fi
for target in /var/lib/sentinel/sentinel.json /etc/sentinel/sentinel.env /opt/sentinel/sentinel.py /opt/sentinel/sentinel_checks.py /opt/sentinel/sentinel_whois.py /opt/sentinel/sentinel_baseline.py /opt/sentinel/uninstall.sh /etc/systemd/system/sentinel.service; do
    [[ ! -L "$target" ]] || { echo "Refusing symlink: $target" >&2; exit 1; }
done
# Abort on a failed stop; never replace a running application.
if [[ $(/usr/bin/systemctl show sentinel.service --property=LoadState --value) != not-found ]]; then
    /usr/bin/systemctl stop sentinel.service
fi
for directory in /opt/sentinel /etc/sentinel /var/lib/sentinel; do
    [[ ! -L "$directory" ]] || { echo "Refusing symlink: $directory" >&2; exit 1; }
done
install -d -o root -g root -m 0755 /opt/sentinel
install -d -o root -g root -m 0700 /etc/sentinel /var/lib/sentinel
if [[ $# -eq 2 ]]; then
    install -o root -g root -m 0600 -- "$1" /var/lib/sentinel/sentinel.json
    install -o root -g root -m 0600 -- "$2" /etc/sentinel/sentinel.env
fi
if [[ ! -e /var/lib/sentinel/sentinel.json && ! -e /etc/sentinel/sentinel.env ]]; then
    [[ -t 0 ]] || { echo 'First install needs a terminal, or supply prepared.json prepared.env.' >&2; exit 1; }
    /usr/bin/python3 -I sentinel.py --setup
elif [[ ! -f /var/lib/sentinel/sentinel.json || ! -f /etc/sentinel/sentinel.env ]]; then
    echo 'Incomplete installation: restore the missing config/env file, or uninstall and retry.' >&2
    exit 1
fi
/usr/bin/python3 -I sentinel.py --config /var/lib/sentinel/sentinel.json --check-config
if ! id sentinel-watchdog >/dev/null 2>&1; then
    /usr/sbin/useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sentinel-watchdog
    touch /etc/sentinel/account-created
elif [[ ! -f /etc/sentinel/account-created ]]; then
    echo 'Existing sentinel-watchdog account is not owned by this installer; refusing to reuse it.' >&2
    exit 1
fi
/usr/bin/systemd-analyze verify sentinel.service
install -o root -g root -m 0644 sentinel.py sentinel_checks.py sentinel_whois.py sentinel_baseline.py /opt/sentinel/
install -o root -g root -m 0755 uninstall.sh /opt/sentinel/uninstall.sh
install -o root -g root -m 0644 sentinel.service /etc/systemd/system/sentinel.service
chown root:root /etc/sentinel/sentinel.env
chown sentinel-watchdog:sentinel-watchdog /var/lib/sentinel
# Open state files without following symlinks before changing ownership or permissions.
/usr/bin/python3 -I - <<'PY_MIGRATE'
import os, pwd
account = pwd.getpwnam('sentinel-watchdog')
for path in ('/var/lib/sentinel/sentinel.json', '/var/lib/sentinel/.lock'):
    try:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    except FileNotFoundError:
        continue
    try:
        os.fchown(fd, account.pw_uid, account.pw_gid)
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
PY_MIGRATE
chmod 0600 /etc/sentinel/sentinel.env
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl enable --now sentinel.service
/usr/bin/systemctl is-active --quiet sentinel.service
/usr/bin/python3 -I /opt/sentinel/sentinel.py --health-check
echo 'Sentinel started. Check: sudo journalctl -u sentinel.service -n 30 --no-pager'
echo 'Then send /selftest and /security to the dedicated Telegram bot.'
echo 'Review the initial security inventory in Telegram: /baseline review'
echo 'Approve its reviewed digest in the same chat: /baseline approve DIGEST'
echo 'Set expected_gunbot_instances and monitored_paths in /var/lib/sentinel/sentinel.json while the service is stopped.'
echo 'To remove Sentinel: sudo /opt/sentinel/uninstall.sh'
