"""Package boundary, integrity and version regression checks; no network or root."""
import hashlib
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

import release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        self.root.mkdir()
        source = Path(__file__).resolve().parent
        for name in release.FILES:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / name, target)
        (self.root / 'SHA256SUMS').write_bytes(release.manifest(release.release_files(self.root)))
        self.output = Path(self.temp.name) / 'output'

    def test_archive_allowlist_checksums_modes_and_reproducibility(self):
        (self.root / 'sentinel.env').write_text('PRIVATE TEST FIXTURE')
        (self.root / '__pycache__').mkdir()
        (self.root / '__pycache__' / 'local.pyc').write_bytes(b'private')
        current = release.version(self.root)
        archive, checksum = release.build(self.root, self.output, 'v' + current)
        first = archive.read_bytes()
        self.assertEqual(checksum.read_text(), f'{hashlib.sha256(first).hexdigest()}  {archive.name}\n')
        with tarfile.open(archive) as package:
            members = package.getmembers()
            prefix = f'sentinel-{current}/'
            self.assertEqual({m.name for m in members}, {prefix + n for n in (*release.FILES, 'SHA256SUMS')})
            for member in members:
                name = member.name[len(prefix):]
                self.assertTrue(member.isfile())
                self.assertEqual(member.mode, 0o755 if name in release.EXECUTABLES else 0o644)
                self.assertEqual(package.extractfile(member).read(), (self.root / name).read_bytes())
        release.build(self.root, self.output, 'v' + current)
        self.assertEqual(first, archive.read_bytes())

    def test_rejects_stale_manifest_and_wrong_tag(self):
        with self.assertRaisesRegex(ValueError, 'tag must match'):
            release.build(self.root, self.output, 'v999.0.0')
        self.assertFalse(self.output.exists())
        with (self.root / 'sentinel.py').open('a') as output:
            output.write('\n# unexpected modification\n')
        with self.assertRaisesRegex(ValueError, 'manifest is stale'):
            release.build(self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_rejects_symlinked_release_file(self):
        path = self.root / 'sentinel.env.example'
        path.unlink()
        path.symlink_to(self.root / 'README.md')
        with self.assertRaisesRegex(ValueError, 'symlinked'):
            release.build(self.root, self.output)


if __name__ == '__main__':
    unittest.main()
