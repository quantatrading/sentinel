#!/usr/bin/env python3
"""Create an integrity manifest; publish its digest via an independently trusted channel."""
import hashlib
from pathlib import Path

FILES = ('sentinel.py', 'sentinel_checks.py', 'sentinel_whois.py', 'test_whois.py', 'test_checks.py', 'sentinel.service', 'sentinel.json.example', 'sentinel.env.example',
         'install.sh', 'uninstall.sh', 'README.md', 'test_sentinel.py', 'test_linux.sh',
         'SECURITY_REVIEW.md', 'SECURITY.md', 'CONTRIBUTING.md', 'release.py',
         'docs/configuration.md', 'docs/operations.md', 'docs/publication-review.md',
         '.gitignore', '.github/workflows/ci.yml')
root = Path(__file__).resolve().parent
manifest = ''.join(f'{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n' for name in FILES)
(root / 'SHA256SUMS').write_text(manifest)
print('Manifest SHA-256:', hashlib.sha256(manifest.encode()).hexdigest())
