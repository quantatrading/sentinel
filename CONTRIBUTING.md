# Development and contributions

The application uses Python's standard library. Ubuntu 24.04/Python 3.12 is the
deployment target; local logic tests also run on macOS. No pip packages are needed.

```bash
python3 -m unittest discover -v
python3 -I sentinel.py --config sentinel.json.example --check-config
bash -n install.sh uninstall.sh test_linux.sh
```

For service integration use a disposable Ubuntu 24.04 VM with systemd-resolved:

```bash
sudo env SENTINEL_TEST_DISPOSABLE=yes ./test_linux.sh
```

That test installs a service, suspends its main process to check watchdog recovery,
and uninstalls it. Never run it on a production server. It uses a deliberately
invalid token and does not verify real Telegram delivery.

## Source map

| File | Responsibility |
| --- | --- |
| `sentinel.py` | Configuration, collector streams, observations, Telegram authorization/delivery, reports and CLI |
| `sentinel_checks.py` | Fixed host inventory, baselines, listeners, tools, package and health checks |
| `sentinel_whois.py` | Bounded unprivileged WHOIS worker and cache |
| `sentinel_incidents.py` | Persistent change lifecycle, owner evidence and scoped approval |
| `sentinel_baseline.py` | Telegram baseline review, confirmation and reference comparison |
| `sentinel.service` | systemd sandbox, resource limits and watchdog |
| `install.sh`, `uninstall.sh` | Fixed-path installation and removal |
| `test_*.py`, `test_linux.sh` | Mocked logic tests and disposable system integration |
| `release.py`, `SHA256SUMS` | Explicit release-file allowlist and integrity manifest |

Preserve the one-way privileged collector interface, bounded queues/state and
secret-safe logging. Add regression tests for behaviour changes. Use synthetic
fixtures and documentation addresses; never record real tokens or deployment data.
Review the full staged diff before committing. Do not run the installer locally
merely to test Python logic.

## Prepare a release

1. Review source, examples, tests and documentation for private data and regressions.
2. Update version references for behavioural releases and document changes.
3. Update the explicit `FILES` list in `release.py` for new distributable files.
4. Run the checks above and the appropriate target-platform acceptance tests.
5. Run `python3 release.py`, then verify `SHA256SUMS` with `sha256sum --check --strict SHA256SUMS` on Linux or `shasum -a 256 -c SHA256SUMS` on macOS.
6. Review `git diff --check`, the diff and staged file list before publishing.

## Build and publish

Create a local installation package after regenerating and reviewing the manifest:

```bash
python3 release.py --check
python3 release.py --build --tag v0.3.15
```

The output is `dist/sentinel-0.3.15.tar.gz` and its `.sha256` file. Only files in
`FILES` plus `SHA256SUMS` enter the archive; generated caches and local files are
excluded. Archive ownership, timestamps and modes are normalized; installers
remain executable. The build fails if a file changed since manifest generation
or the tag differs from `VERSION` in `sentinel.py`.

To publish a new version:

1. Update the application version and user-facing version references.
2. Add `docs/releases/vVERSION.md` with release notes and add that file to `FILES`.
3. Run tests, regenerate `SHA256SUMS`, commit and push the reviewed changes.
4. Create and push the matching tag, for example:

   ```bash
   git tag -a v0.3.15 -m "Sentinel 0.3.15"
   git push origin v0.3.15
   ```

The **Release** GitHub Actions workflow runs on `v*` tags. It runs tests on
Ubuntu, builds the archive, verifies the extracted manifest and installer modes,
then publishes a GitHub release with the archive, checksum and prepared notes.
It uses the repository's built-in `GITHUB_TOKEN`; no personal token is required.
Release creation requires Actions to have write access to repository contents.
Inspect the workflow result before announcing a release. Do not move an already
published version tag; publish a new version for fixes. Release notes are required
for each tag. No privileged installation or live Telegram testing runs in CI.

The manifest is integrity evidence, not a signature. Publish its digest through
an independently trusted channel when distributing a release. GitHub CI checks
logic, shell syntax, example configuration and manifest consistency; it does not
run the privileged integration test or real Telegram traffic.

No redistribution license has been selected yet. A public repository alone is
not a declaration that the project is licensed as open source.
