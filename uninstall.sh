#!/usr/bin/env bash
set -euo pipefail
# Only fixed Sentinel-owned installation paths; never accept an arbitrary removal path.
mode=${1:-}
if [[ $# -gt 1 || ( -n "$mode" && "$mode" != --yes && "$mode" != --dry-run ) ]]; then
    echo 'Usage: sudo ./uninstall.sh [--yes|--dry-run]' >&2
    exit 1
fi
cat <<'PLAN'
Sentinel removal will:
  Stop and disable sentinel.service (including its own collectors).
  Remove /opt/sentinel (including this installed uninstaller).
  Remove /etc/sentinel (including the Telegram token).
  Remove /var/lib/sentinel (configuration, history and state).
  Remove /run/sentinel (runtime files).
  Remove sentinel.service and its Sentinel-specific systemd overrides.
  Reload systemd and clear Sentinel's failed status.
  Remove the dedicated account if this installer created it.
Gunbot, firewall rules, DNS and other services are unaffected.
Shared journal/syslog entries, Telegram messages, downloaded source copies,
manually prepared files and external backups are not removed.
PLAN
[[ "$mode" != --dry-run ]] || exit 0
if [[ ${EUID} -ne 0 || $(uname -s) != Linux || ! -d /run/systemd/system ]]; then
    echo 'Run as root on the Linux VPS running systemd.' >&2
    exit 1
fi
if [[ "$mode" != --yes ]]; then
    read -r -p 'Permanently delete Sentinel configuration, token and history? Type REMOVE: ' answer
    [[ "$answer" == REMOVE ]] || { echo 'Cancelled.'; exit 0; }
fi
# Fail before deleting anything if a dedicated path is a symlink or contains a mount.
/usr/bin/python3 -I - <<'PY'
from pathlib import Path
import sys
roots = ['/opt/sentinel', '/etc/sentinel', '/var/lib/sentinel', '/run/sentinel',
         '/etc/systemd/system/sentinel.service.d', '/run/systemd/system/sentinel.service.d']
mounts = []
for line in Path('/proc/self/mountinfo').read_text().splitlines():
    value = line.split()[4]
    for escaped, plain in [(r'\040', ' '), (r'\011', '\t'), (r'\012', '\n'), (r'\134', '\\')]:
        value = value.replace(escaped, plain)
    mounts.append(value)
for root in roots:
    p = Path(root)
    if p.is_symlink() or any(m == root or m.startswith(root + '/') for m in mounts):
        sys.exit('Refusing symlink/mounted Sentinel directory: ' + root)
PY
load_state=$(/usr/bin/systemctl show sentinel.service --property=LoadState --value)
if [[ "$load_state" != not-found ]]; then
    /usr/bin/systemctl stop sentinel.service
    /usr/bin/systemctl disable sentinel.service
fi
active_state=$(/usr/bin/systemctl show sentinel.service --property=ActiveState --value)
[[ "$active_state" == inactive || "$active_state" == failed ]] || {
    echo 'Sentinel is still running; refusing to remove its files.' >&2
    exit 1
}
remove_account=false
[[ ! -f /etc/sentinel/account-created ]] || remove_account=true
# These paths belong exclusively to Sentinel. rm does not follow contained symlinks.
rm -rf -- /opt/sentinel /etc/sentinel /var/lib/sentinel /run/sentinel \
    /etc/systemd/system/sentinel.service.d /run/systemd/system/sentinel.service.d
rm -f -- /etc/systemd/system/sentinel.service \
    /etc/systemd/system/multi-user.target.wants/sentinel.service
if [[ $remove_account == true ]] && id sentinel-watchdog >/dev/null 2>&1; then
    /usr/sbin/userdel sentinel-watchdog
    if getent group sentinel-watchdog >/dev/null; then
        /usr/sbin/groupdel sentinel-watchdog
    fi
fi
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl reset-failed sentinel.service 2>/dev/null || true
echo 'Sentinel installation removed.'
echo 'For remaining copies: delete the downloaded source and any manually prepared config/env files.'
echo 'Revoke/delete the dedicated Telegram bot through BotFather and delete its chat if retiring it.'
echo 'Shared system logs expire under your normal retention policy; other services logs are preserved.'
