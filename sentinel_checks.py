"""Bounded read-only host checks. No commands or paths are accepted from Telegram."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

MAX_FILES = 512
MAX_FILE_BYTES = 2 * 1024 * 1024
BASELINE = Path('/etc/sentinel/baseline.json')
FIXED = ('/etc/ssh/sshd_config', '/etc/sudoers', '/etc/passwd', '/etc/group',
         '/etc/crontab', '/etc/default/ufw', '/etc/ufw/ufw.conf',
         '/etc/ufw/user.rules', '/etc/ufw/user6.rules', '/etc/ufw/before.rules',
         '/etc/ufw/before6.rules', '/etc/ufw/after.rules', '/etc/ufw/after6.rules',
         '/root/.ssh/authorized_keys', '/root/.ssh/authorized_keys2')
DIRECTORIES = ('/etc/ssh/sshd_config.d', '/etc/sudoers.d', '/etc/cron.d',
               '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly',
               '/var/spool/cron/crontabs', '/etc/systemd/system', '/etc/ufw')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def label(value):
    return re.sub(r'[\x00-\x1f\x7f]', '?', str(value))[:300]


def fingerprint(path, limit=MAX_FILE_BYTES):
    """Never follow file symlinks or open special devices; return hashes/metadata only."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {'missing': True}
    meta = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
    if stat.S_ISLNK(info.st_mode):
        return dict(meta, link_sha256=hashlib.sha256(os.readlink(path).encode()).hexdigest())
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Unsupported security file type')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > limit:
            raise ValueError('Unsupported/oversize security file')
        h = hashlib.sha256()
        size = 0
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            size += len(block)
            if size > limit:
                raise ValueError('File grew beyond limit')
            h.update(block)
        after = os.fstat(fd)
        if (opened.st_ino, opened.st_size, opened.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('File changed during hashing')
        return {'mode': stat.S_IMODE(opened.st_mode), 'uid': opened.st_uid,
                'gid': opened.st_gid, 'sha256': h.hexdigest()}
    finally:
        os.close(fd)


def security_files():
    paths = {Path(x) for x in FIXED}
    # Known public SSH authorization files only. Never read private keys or Gunbot config.
    home = Path('/home')
    if home.exists():
        for entry in home.iterdir():
            if entry.is_dir() and not entry.is_symlink():
                paths.update(entry / '.ssh' / name for name in ('authorized_keys', 'authorized_keys2'))
            if len(paths) > MAX_FILES:
                raise ValueError('Security inventory limit exceeded')
    for directory in DIRECTORIES:
        base = Path(directory)
        if base.is_symlink():
            paths.add(base)
            continue
        if not base.exists():
            paths.add(base)
            continue
        def walk_error(error):
            raise error
        for root, dirs, files in os.walk(base, followlinks=False, onerror=walk_error):
            if len(Path(root).relative_to(base).parts) > 4:
                raise ValueError('Security directory depth exceeded')
            for name in list(dirs):
                child = Path(root) / name
                if child.is_symlink():
                    paths.add(child)
                    dirs.remove(name)
            paths.update(Path(root) / name for name in files)
            if len(paths) > MAX_FILES:
                raise ValueError('Security inventory limit exceeded')
    result, total = {}, 0
    for path in sorted(paths):
        # Refuse traversing a symlinked .ssh or parent directory to another secret location.
        if any(parent.is_symlink() for parent in path.parents if parent != Path('/')):
            result[str(path)] = {'parent_symlink': True}
            continue
        value = fingerprint(path)
        total += path.lstat().st_size if path.exists() and not path.is_symlink() else 0
        if total > 16 * 1024 * 1024:
            raise ValueError('Security inventory byte limit exceeded')
        result[str(path)] = value
    return result


def endpoint(raw):
    address, port = raw.split(':')
    data = bytes.fromhex(address)
    data = b''.join(data[i:i + 4][::-1] for i in range(0, len(data), 4))
    return str(ipaddress.ip_address(data)), int(port, 16)


def tool_name(comm, process):
    name = comm.split(' ')[0]
    if name in ('apt', 'apt-get', 'dpkg', 'curl', 'wget', 'npm', 'npx', 'pip', 'pip3'):
        return name
    if not re.fullmatch(r'python[0-9.]*|node|nodejs', comm):
        return None
    # Read only the interpreter and module/script selector. Never read URL/command arguments.
    tokens = []
    with (process / 'cmdline').open('rb') as file:
        for _ in range(3):
            token = bytearray()
            while len(token) < 512:
                byte = file.read(1)
                if not byte or byte == b'\0':
                    break
                token.extend(byte)
            tokens.append(bytes(token))
            if len(tokens) == 2:
                script = os.path.basename(tokens[1])
                if comm in ('node', 'nodejs'):
                    return 'npm' if script in (b'npm-cli.js', b'npx-cli.js') else None
                if tokens[1] != b'-m':
                    return 'pip' if re.fullmatch(rb'pip[0-9.]*', script) else None
            if len(tokens) == 3:
                return 'pip' if tokens[2] == b'pip' else None
    return None


def host_processes():
    sockets = {}
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    for proto in ('tcp', 'tcp6', 'udp', 'udp6'):
        table = Path('/proc/net') / proto
        if not table.exists():
            continue
        with table.open() as file:
            next(file)
            for line in file:
                row = line.split()
                ip, port = endpoint(row[1])
                if (row[3] == '0A' or (proto.startswith('udp') and row[3] == '07')) and port:
                    sockets[row[9]] = {'protocol': proto, 'ip': ip, 'port': port, 'owners': []}
                    if len(sockets) > 512:
                        raise ValueError('Listener limit exceeded')
    tools, scanned = {}, 0
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():
            continue
        try:
            comm = (process / 'comm').read_text().strip()
            uid = process.stat().st_uid
            found = tool_name(comm, process)
            if found:
                start = (process / 'stat').read_text().rsplit(')', 1)[1].split()[19]
                tools[boot + ':' + process.name + ':' + start] = {'tool': found, 'pid': int(process.name), 'uid': uid}
                if len(tools) > 256:
                    raise ValueError('Tool process limit exceeded')
            for fd in (process / 'fd').iterdir():
                try:
                    target = os.readlink(fd)
                    inode = target[8:-1] if target.startswith('socket:[') else None
                    if inode in sockets:
                        owner = label(comm) + ' uid=' + str(uid)
                        entry = sockets[inode]
                        if owner not in entry['owners']:
                            entry['owners'].append(owner)
                        entry['pid'] = int(process.name)
                    scanned += 1
                    if scanned > 100000:
                        raise ValueError('FD inspection limit exceeded')
                except FileNotFoundError:
                    pass
        except (FileNotFoundError, ProcessLookupError):
            continue
    listeners, display = {}, []
    for entry in sockets.values():
        key = f"{entry['protocol']} {entry['ip']}:{entry['port']}"
        owners = listeners.setdefault(key, [])
        owners.extend(x for x in entry['owners'] if x not in owners)
        display.append(entry)
    return {k: sorted(v) for k, v in listeners.items()}, display, tools


def inventory():
    listeners, _, _ = host_processes()
    return {'files': security_files(), 'listeners': listeners}


def baseline_compare(current):
    if not BASELINE.exists():
        return {'status': 'not approved', 'digest': digest(current), 'changes': []}
    if BASELINE.is_symlink() or BASELINE.stat().st_uid != 0 or BASELINE.stat().st_mode & 0o022 or BASELINE.stat().st_size > 1024 * 1024:
        raise ValueError('Unsafe baseline file')
    expected = json.loads(BASELINE.read_text())
    if expected.get('digest') != digest(expected.get('inventory')):
        raise ValueError('Baseline checksum mismatch')
    changes = []
    for kind in ('files', 'listeners'):
        old, new = expected['inventory'][kind], current[kind]
        for key in sorted(old.keys() | new.keys()):
            if old.get(key) != new.get(key):
                changes.append({'kind': kind, 'name': label(key), 'fingerprint': digest(new.get(key)),
                                'change': 'added' if key not in old else 'removed' if key not in new else 'changed'})
    return {'status': 'drift' if changes else 'matches approved baseline', 'digest': digest(current),
            'expected_digest': expected['digest'], 'changes': changes[:1024]}


def filesystem_usage(paths):
    result = {}
    for path in paths:
        try:
            data = os.statvfs(path)
            result[path] = {'disk': 100 * (data.f_blocks - data.f_bfree) / data.f_blocks if data.f_blocks else 0,
                            'inodes': 100 * (data.f_files - data.f_ffree) / data.f_files if data.f_files else None}
        except OSError:
            result[path] = {'error': 'Filesystem unavailable'}
    return result


def system_status():
    result = {'reboot_required': Path('/run/reboot-required').exists(), 'clock_sync': 'unknown'}
    try:
        response = subprocess.run(['/usr/bin/timedatectl', 'show', '--property=NTPSynchronized', '--value'],
                                  capture_output=True, text=True, timeout=3,
                                  env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'})
        if response.returncode == 0 and response.stdout.strip() in ('yes', 'no'):
            result['clock_sync'] = response.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return result


class PackageLog:
    """Observe new dpkg action records, bounded per read. Never parse shell history."""
    def __init__(self, path=Path('/var/log/dpkg.log')):
        self.path, self.identity, self.offset = path, None, 0
        self.initialized = False

    def read(self):
        info = self.path.stat()
        identity = (info.st_dev, info.st_ino)
        if not self.initialized:
            self.identity, self.offset, self.initialized = identity, info.st_size, True
            return []
        if identity != self.identity or info.st_size < self.offset:
            self.identity, self.offset = identity, 0
        results = []
        with self.path.open('rb') as file:
            file.seek(self.offset)
            for _ in range(128):
                line = file.readline(4096)
                if len(line) == 4096 and not line.endswith(b'\n'):
                    self.offset = file.tell()
                    raise ValueError('Oversize dpkg log record; inspection incomplete')
                if not line or not line.endswith(b'\n'):
                    break
                self.offset = file.tell()
                match = re.fullmatch(rb'([0-9-]+) ([0-9:]+) (install|upgrade|remove|purge) ([a-zA-Z0-9.+:-]+) [^\n]{1,1024}\n', line)
                if match:
                    results.append({'action': match[3].decode(), 'package': match[4].decode(),
                                    'id': f'{identity[1]}:{self.offset}'})
        return results


class HostChecks:
    def __init__(self):
        self.packages = PackageLog()
        self.next_slow = 0
        self.slow = {}

    def sample(self):
        result = {'health': {}}
        try:
            listeners, display, tools = host_processes()
            result.update(listeners=listeners, listener_details=display, tools=tools)
            result['health']['listeners_tools'] = 'ok'
        except (OSError, ValueError, IndexError):
            listeners = None
            result['health']['listeners_tools'] = 'unavailable'
        try:
            result['packages'] = self.packages.read()
            result['health']['package_log'] = 'ok'
        except (OSError, ValueError):
            result['health']['package_log'] = 'unavailable'
        if time.monotonic() >= self.next_slow:
            self.slow = system_status()
            try:
                self.slow['package_inventory'] = fingerprint(Path('/var/lib/dpkg/status'), 32 * 1024 * 1024)
            except (OSError, ValueError):
                self.slow['package_inventory'] = {'error': 'unavailable'}
            try:
                self.slow['files'] = security_files()
            except (OSError, ValueError):
                self.slow['file_error'] = 'Security inventory incomplete'
            self.next_slow = time.monotonic() + 60
        result.update({k: v for k, v in self.slow.items() if k != 'files'})
        result['health']['package_inventory'] = 'ok' if 'sha256' in self.slow.get('package_inventory', {}) else 'unavailable'
        try:
            if listeners is None or 'files' not in self.slow:
                raise ValueError('Inventory incomplete')
            result['baseline'] = baseline_compare({'files': self.slow['files'], 'listeners': listeners})
            result['health']['security_files'] = 'ok (hashed every 60s)'
        except (OSError, ValueError, KeyError, TypeError):
            result['baseline'] = {'status': 'unavailable', 'changes': []}
            result['health']['security_files'] = 'unavailable'
        return result
