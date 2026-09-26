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

The manifest is integrity evidence, not a signature. Publish its digest through
an independently trusted channel when distributing a release. GitHub CI checks
logic, shell syntax, example configuration and manifest consistency; it does not
run the privileged integration test or real Telegram traffic.

No redistribution license has been selected yet. A public repository alone is
not a declaration that the project is licensed as open source.
