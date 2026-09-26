# Initial public-source review

Review date: 26 September 2026. Application version: 0.3.13.

## Scope and changes

Reviewed the source modules, shell scripts, systemd unit, examples, tests and
documentation for embedded credentials, personal/deployment identifiers and
accidental publication of operational data. The input directory had no Git
repository or commit history to clean.

- No real bot token, password, private key or populated deployment credential file
  was found in the reviewed source. Invalid tokens in tests are synthetic fixtures.
- Replaced organisation-specific report/test labels with generic examples and
  removed deployment-specific troubleshooting narrative from public documentation.
- Excluded generated Python bytecode (which can embed local filesystem paths),
  populated config/state, secrets, logs, backups and local editor/agent metadata.
- Added configuration, operational, development and security-reporting guides.
- Corrected the README version and clarified that older review findings and line
  numbers refer to historical implementations. Retained security limitations.
- Added CI and regenerated the explicit release integrity manifest.

Runtime monitoring behaviour was not changed for publication.

## Validation and limits

All 74 existing Python unit tests pass on the local macOS/Python 3.14 development
host. Shell syntax, example JSON configuration, Python compilation and the
release manifest are checked locally. Tests use synthetic/mocked observations;
no real Telegram messages or WHOIS queries were sent for this review.

Ubuntu service integration, real Telegram delivery, actual resolver coverage and
resource/flood behaviour were not exercised in this review. The supplied
disposable-VM test and README acceptance procedure remain required before relying
on a deployment. CI results are separate from these local checks.

This is a source-publication review, not a penetration test or a guarantee that
all vulnerabilities or sensitive information have been identified. In particular,
the root collector's broad read access, sampled coverage, local mutable evidence,
bounded delivery capacity and external Telegram/WHOIS data flows remain documented
design limitations. No software license or certification is implied by publication.
