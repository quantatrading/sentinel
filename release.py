#!/usr/bin/env python3
"""Verify release files and build a deterministic, explicitly allowlisted archive."""
import argparse
import ast
import gzip
import hashlib
import io
from pathlib import Path
import re
import tarfile

FILES = ('sentinel.py', 'sentinel_checks.py', 'sentinel_whois.py', 'test_whois.py', 'test_checks.py', 'sentinel.service', 'sentinel.json.example', 'sentinel.env.example',
         'install.sh', 'uninstall.sh', 'README.md', 'test_sentinel.py', 'test_linux.sh',
         'SECURITY_REVIEW.md', 'SECURITY.md', 'CONTRIBUTING.md', 'release.py',
         'docs/configuration.md', 'docs/operations.md', 'docs/publication-review.md',
         '.gitignore', '.github/workflows/ci.yml', '.github/workflows/release.yml',
         'test_release.py', 'docs/releases/v0.3.13.md')
EXECUTABLES = {'install.sh', 'uninstall.sh', 'test_linux.sh'}


def version(root):
    for node in ast.parse((root / 'sentinel.py').read_text()).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'VERSION' for t in node.targets):
            value = ast.literal_eval(node.value)
            if isinstance(value, str) and re.fullmatch(r'\d+\.\d+\.\d+', value):
                return value
    raise ValueError('Missing or invalid application VERSION')


def release_files(root):
    contents = {}
    for name in FILES:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Release file missing or symlinked: ' + name)
        contents[name] = path.read_bytes()
    return contents


def manifest(contents):
    return ''.join(f'{hashlib.sha256(data).hexdigest()}  {name}\n' for name, data in contents.items()).encode()


def build(root, output, tag=None):
    current = version(root)
    if tag is not None and tag != 'v' + current:
        raise ValueError('Release tag must match application version v' + current)
    contents = release_files(root)
    expected = manifest(contents)
    if (root / 'SHA256SUMS').read_bytes() != expected:
        raise ValueError('Release manifest is stale; review changes and run python3 release.py')
    contents['SHA256SUMS'] = expected
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f'sentinel-{current}.tar.gz'
    # Stable metadata and compression make identical sources produce identical archives.
    with archive.open('wb') as raw:
        with gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as package:
                for name, data in contents.items():
                    entry = tarfile.TarInfo(f'sentinel-{current}/{name}')
                    entry.size = len(data)
                    entry.mode = 0o755 if name in EXECUTABLES else 0o644
                    entry.mtime = entry.uid = entry.gid = 0
                    package.addfile(entry, io.BytesIO(data))
    checksum = output / (archive.name + '.sha256')
    checksum.write_text(f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n')
    return archive, checksum


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--check', action='store_true', help='Verify the existing manifest without changing it')
    action.add_argument('--build', action='store_true', help='Verify and package release files')
    parser.add_argument('--tag', help='Require a matching vMAJOR.MINOR.PATCH release tag')
    parser.add_argument('--output', type=Path, default=Path('dist'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    if args.build:
        for path in build(root, args.output, args.tag):
            print(path)
        return
    if args.tag:
        parser.error('--tag requires --build')
    expected = manifest(release_files(root))
    if args.check:
        if (root / 'SHA256SUMS').read_bytes() != expected:
            raise SystemExit('Release manifest is stale')
        print('Release manifest verified')
    else:
        (root / 'SHA256SUMS').write_bytes(expected)
        print('Manifest SHA-256:', hashlib.sha256(expected).hexdigest())


if __name__ == '__main__':
    main()
