# Sentinel security review - 26 September 2026

> Historical review: the decision, test counts, line references and findings below describe the initial implementation, not the current release. See the [remediation status](#020-remediation-status) and [current publication review](docs/publication-review.md). Original findings are retained for transparency; they are not all unresolved defects.

## Current validation update

On 26 September 2026, the project owner confirmed that Sentinel has been tested
on Ubuntu and is working. Earlier statements below about outstanding Linux
validation describe the evidence available during the historical review. The
confirmation does not specify which individual integration or failure-path
checks were run. See the [publication review](docs/publication-review.md) for
the distinction between deployment confirmation and local automated checks.

## 0.3.14 Telegram baseline approval

Baseline approval is now available to authorised Telegram users through a
same-user/chat digest confirmation within five minutes. The unprivileged process
stores the approved snapshot in its private runtime state and compares later
collector snapshots against it. The root collector still accepts no commands.
Historical statements below that approval is local-root-only apply to earlier
versions. Remote approval changes the trust model: an authorised Telegram account
or compromised service account can replace the reference. Reviews expose bounded
file and listener metadata, not file contents. Approval uses sampled observations,
not a synchronous re-scan. See README for local/Telegram baseline precedence.

## 0.3.15 Security-change lifecycle

Unchanged drift now updates a bounded persistent record rather than triggering
hourly warnings. Acknowledgement preserves baseline drift while suppressing its
pending notices. Scoped approval reconstructs the expected reference from the
complete difference list and applies only the selected current change; incomplete
or stale observations are refused. Approvals retain the Telegram trust model
above. PID metadata is retained for explanation but excluded from baseline
identity to avoid restart noise. No historical PID is inferred when absent.
Checks count observations, not separate incidents or uninterrupted coverage.

## Decision

Sentinel is a useful foundation for a supplementary VPS watchdog. It is **not currently supported by sufficient evidence for a government-assured deployment**, and two reproduced alert-delivery defects should be fixed before depending on it for critical notices. It is not an endpoint protection system, a complete audit system, or an implementation of an entire security standard.

This is a source/configuration review, not certification, penetration testing, or an authorization to operate. No application, installer, service, or uninstall behavior was changed during this review. Findings remain open. Earlier use of “production-ready” should be understood as an implementation objective, not a verified security assurance claim.

Government requirements vary with jurisdiction, data classification, system impact, contractual requirements and selected controls. It would be misleading to award this script a general government pass/fail or a percentage compliance score. The findings below concern this component; the organization and VPS may implement additional controls outside it.

## Scope and evidence

Reviewed `sentinel.py`, `sentinel.service`, `install.sh`, `uninstall.sh`, examples, README and tests in the current workspace. The current 25 tests were rerun successfully on macOS. Two additional isolated, in-memory probes reproduced notification failure cases. They sent no Telegram messages and modified no deployed service. No Linux VPS, production credentials, kernel security policy, supplier contract, account MFA, journal retention, or installed cryptographic module was inspected.

The line references below refer to this reviewed version. Priorities describe risk to this watchdog's intended role, not CVSS vulnerability scores.

## Implementation findings

### F1 - High: critical notices can be permanently lost behind routine observations

Evidence: `sentinel.py:433-460`, particularly `notified` set at line 446 before global rate limiting or successful enqueue; process disappearance/down transitions at lines 536-543.

A burst of five unfamiliar DNS names fills the shared one-minute notification budget. A subsequent process-disappearance notice is recorded but neither logged nor queued. It is already marked notified. An event using `once=True` will not be queued on a later observation either. A full outgoing queue has the same premature-notification-state problem. The main process-health logic additionally treats the down transition as completed, so it does not naturally retry it.

Reproduction: five DNS events at timestamp 10000; a `once=True` process event at 10001; re-observe that process event at 10100. Result: five queued DNS messages, **zero critical messages**, one suppressed notice, and a critical `notified` value of 10001. This does not require an attacker; an ordinary noisy startup can trigger it. A process capable of producing server DNS queries can also consume the budget deliberately.

Remediation: separate observed/queued/delivered state; reserve notification capacity for process, SSH and collector failures; retain a small bounded pending set; aggregate low-priority events. Distinguish intentional mute from delivery failure, and report delivery gaps on recovery. Add regression tests covering saturation, process transitions and queue exhaustion.

### F2 - High design risk: Internet-facing logic shares powerful host privileges

Evidence: `sentinel.service:10-14,40-44`; Telegram parsing, monitoring, and state mutation run in one Python process.

The service runs as root and retains `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`, and `CAP_NET_ADMIN`. The last capability exists to support a read-only UFW query, but capability enforcement does not restrict it to read-only firewall operations. The code behaves read-only; its privilege boundary does not guarantee read-only behavior if the process is compromised. Reading across user boundaries is also sensitive on a machine holding trading credentials.

The filesystem sandbox, capability reduction, syscall restrictions, no inbound listeners and fixed commands are valuable. They do not make this root process harmless after exploitation. This review did not identify or demonstrate a remote-code-execution exploit.

Remediation: separate the unprivileged Telegram/controller role from the smallest fixed-function privileged inspection mechanism. Remove `NET_ADMIN` from the network-facing process; consider reporting less UFW detail if that avoids a privileged helper. Reassess each remaining capability on Ubuntu. If the single-process constraint is retained, document the resulting risk explicitly rather than claiming strict least privilege.

### F3 - Medium: one failed recipient blocks other notices and command polling

Evidence: `sentinel.py:216-250`.

A failed `sendMessage` leaves `pending` in place and skips `getUpdates` through the common exception handler. A removed bot, blocked chat or other permanent destination error is retried as though it were a temporary network outage. Other recipients and commands are held behind that message until its five-minute expiry. Several such queued messages can extend the disruption.

Reproduction with a mocked permanent send failure: three iterations attempted `sendMessage` to chat 1 three times; chat 2 and `getUpdates` were never reached.

Remediation: distinguish permanent destination errors, rate limits and transient transport failures without logging secret-bearing exception strings. Retry per recipient with a cap/backoff, honor API retry delays, and continue polling commands independently. Report delivery degradation locally and to remaining reachable destinations.

### F4 - Medium: administrative actions are not meaningfully auditable

Evidence: `sentinel.py:610-639,807-816`.

Allow/remove logs say only “Known-domain configuration changed.” They omit actor, chat, target domain, action and result. Mute/unmute has no corresponding audit record. The dispatcher has sender/chat/update IDs but does not carry them into audit logging. All authorized users can modify detection rules and mute notices; there is no separate view-only role or fresh authentication for a sensitive action.

An attacker controlling an already authorized Telegram session could weaken monitoring. The ID checks correctly reject ordinary unauthorized senders; the gap is attributable administration and account/session assurance, not a demonstrated bypass of those checks.

Remediation: log timestamp, numeric actor/chat IDs, update ID, action, validated target, outcome and relevant before/after value for changes. Never log tokens or arbitrary message bodies. Consider separate operator/admin ID lists or optional local-only rule changes. Have organizational controls for Telegram account MFA/session revocation; the application cannot establish that assurance merely by seeing a sender ID.

### F5 - Medium: detection failure has no independent reporting path

Evidence: `sentinel.service:5-6,15-16`; `sentinel.py:773-799`.

systemd restarts failed processes, but there is no watchdog heartbeat tied to completion of monitoring cycles, no independent last-success observer, and no alert path independent of Telegram. A live-but-stalled process, prolonged Telegram outage or exhausted systemd start limit can leave the operator without alerts. The README acknowledges that a failed watchdog cannot alert through itself; that limitation must be addressed outside the component if operational requirements demand dependable monitoring.

Remediation: a systemd watchdog tied to healthy main-loop progress, stale-check visibility, and an existing external host-monitoring check with a separate notification route. This does not require a new web UI, database or remote shell in Sentinel.

### F6 - Medium assurance gap: release/update and target-platform evidence are incomplete

Evidence: `install.sh:83-94` and current delivery files/tests.

The installer runs/copies the supplied source as root. There is no release-signature or authenticated manifest verification in this package, no Sentinel version/build identity in status, and no supplied patch-support or vulnerability-response process. The immediate `systemctl is-active` check establishes process state, not collector readiness or Telegram delivery. The upgrade also ignores failure of the stop command before replacement.

No malicious package was found. These are missing assurance mechanisms and operational checks. The source must still be acquired through a trusted channel. “No third-party Python packages” reduces dependency count; Python, OpenSSL, systemd and the OS remain dependencies.

Remediation: versioned releases with verifiable provenance through a trusted channel, defined update/support ownership, Ubuntu 24.04 CI/integration tests, and a readiness/acceptance check. Fail an upgrade if the running service cannot be stopped. Test DNS observation on the actual resolver setup, process churn, secret permissions, UFW under the sandbox, prolonged outages, flood behavior, failed upgrades and uninstall on disposable Linux systems.

## Coverage and operational limitations

These are not all defects: some are deliberate consequences of a small passive watchdog. Do not claim that Sentinel implements controls outside its scope.

- DNS observation covers systemd-resolved only. Encrypted DNS or an alternate resolver can bypass it. A running collector is not proof of complete DNS coverage.
- Network inspection is sampled, so brief connections and unconnected UDP can be missed. Recent shared-IP DNS correlation is a hint and can suppress an unfamiliar destination notice; it is not hostname/process attribution.
- Processes are selected by mutable `/proc/PID/comm` text (`sentinel.py:343`). This supports ordinary health checks but is not executable identity or integrity verification. A local process can use a matching name, and a compromised process can change its name.
- Retained JSON observations and the journal are local evidence. The ring buffers intentionally evict records. Sentinel does not establish protected remote audit retention, trusted time, or resistance to a host-root attacker. It should not replace the host's audit trail.
- Telegram receives host names, source/destination IPs, usernames and domain observations. The organization must approve this data flow, supplier, retention, account controls and jurisdiction. A Telegram bot token is not a government identity-assurance mechanism. This review makes no universal claim that government use of Telegram is prohibited or permitted.
- TLS verification is present through Python's default HTTPS handling. There is no evidence that the deployed cryptographic module/configuration is FIPS validated. FIPS requirements apply only where the selected policy requires them.
- Environment-file permissions and hidden input are useful. Token rotation, host backups, swap/crash-dump exposure, support access and disk encryption still require deployment-level assessment. No such host assessment occurred.
- Uninstall deletes dedicated files, not historical shared logs, Telegram messages or provider snapshots. It does not perform cryptographic sanitization or revoke a Telegram token.

## Standards mapping

These are relevant control objectives and gaps, **not formal compliance determinations**. Applicable baselines, implementation groups and inherited controls must be selected first.

| Framework/reference | Relevance | Assessment of Sentinel |
| --- | --- | --- |
| NIST SP 800-53 Rev. 5: AC-6 | Least privilege | Partial hardening; F2 needs resolution or justified acceptance. |
| NIST SP 800-53: AU-3, AU-5, AU-9 | Audit content, failures and protection | F1/F3/F4; independent retention and protection not demonstrated. |
| NIST SP 800-53: SI-4, CA-7 | Monitoring and ongoing assessment | Limited observations; F5 and documented blind spots. |
| NIST SP 800-53: SA-11, SI-2 | Security testing and flaw remediation | Unit tests exist; Linux evidence and patch ownership incomplete. |
| NIST SSDF, SP 800-218 | Secure development, release protection and vulnerability response | Useful implementation safeguards; F6 prevents a mature lifecycle claim. |
| UK Cyber Essentials v3.3 | Organizational/infrastructure baseline | Sentinel cannot establish certification. Host patching, access control, secure configuration, firewall and malware-protection evidence must be assessed separately. |
| UK government Secure by Design (Home Office guidance) | Risk-driven design, threat modelling, least privilege, secure development | Some alignment; no completed assurance case or independent acceptance evidence. |
| CIS Controls v8.1, Control 8 | Audit collection, retention and review | F4 and local/evicting history do not independently provide an enterprise audit process. |
| ISO/IEC 27001:2022 | Organizational information-security management system | A script cannot establish ISMS certification; it can be an assessed component in scope. |
| FIPS 140-3, where required | Cryptographic-module assurance | Unverified; HTTPS alone does not establish validated-module use. |

Official sources consulted:

- [NIST SP 800-53 Rev. 5 and release updates](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST Risk Management Framework](https://csrc.nist.gov/projects/risk-management/about-rmf)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final)
- [NCSC Cyber Essentials requirements v3.3, April 2026](https://www.ncsc.gov.uk/files/cyber-essentials-requirements-for-it-infrastructure-v3-3.pdf)
- [Home Office Secure by Design guidance](https://engineering.homeoffice.gov.uk/principles/secure-by-design/)
- [CIS Controls v8.1 audit-log assessment guidance](https://cas.docs.cisecurity.org/en/latest/source/Controls8/)
- [ISO/IEC 27001](https://www.iso.org/standard/27001)
- [NIST FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final)

## Proportionate next steps

1. Fix F1 and F3 and add failure-path regression tests. These are concrete defects, not compliance paperwork.
2. Reduce the privilege exposed to Telegram processing; decide explicitly whether simpler operation outweighs the residual root-process risk.
3. Add attributable administrative audit records and an independent check that monitoring is still progressing.
4. Establish trusted releases and validate the complete installation on Ubuntu 24.04, including a bounded flood/outage soak test. Keep the current tests but do not mistake their passing for system-level assurance.
5. For an actual government deployment, establish data classification, approved messaging/hosting, system boundaries, applicable control baseline, evidence, inherited controls and accountable risk acceptance with the relevant security authority.

These changes can preserve the small-watchdog purpose. Enterprise controls such as centralized audit retention and external availability monitoring should normally reuse the organization's existing services rather than turn Sentinel into another platform.


## 0.2.0 remediation status

- **F1 implemented, regression-tested locally:** persistent bounded pending notices; separate critical/routine budgets; reserved capacity and priority eviction; delivery receipts distinct from queueing and settlement; restart retry tests. Capacity exhaustion is explicit, not a guarantee of lossless monitoring under arbitrary load.
- **F2 implemented, Linux verification outstanding:** fixed root collector with one-way stdout IPC and no secret environment or request interface; permanent main-process UID drop before Telegram handling. NET_ADMIN removed entirely. UFW reporting deliberately reduced to saved configuration. Actual Linux UID/capability assertions are included in the disposable integration test.
- **F3 implemented, regression-tested locally:** independent poll/send threads, per-job retries, permanent-recipient handling, retry_after support and priority handling under sender-buffer saturation.
- **F4 implemented, regression-tested locally:** durable administrative changes accompanied by attributable audit records. Separate read-only roles and external account MFA/retention policies remain deployment decisions.
- **F5 partially addressed:** progress-dependent systemd watchdog, notify readiness and a local freshness health check added. Existing external monitoring must still be configured by the operator; no independent service or notification channel is fabricated here.
- **F6 partially addressed:** release version, integrity manifest with optional independently trusted pin, fail-on-stop-error upgrade, and a disposable Ubuntu integration test added. No signing authority was invented. Linux integration, real delivery validation and operational support ownership remain outstanding.

The local regression suite was expanded. See the publication review for the current test count. Government acceptance, supplier approval, information classification and organizational assurance remain outside what this code change can establish.

## 0.3.0 monitoring extensions

Added local-root-approved hash inventory for security files and saved UFW state, system listeners, sampled package/download tools, dpkg log/database observations, expected process count/restart storms, scoped maintenance, filesystem inode checks, kernel OOM events, clock/reboot status and `/selftest`. These features do not establish certification or government-standard compliance. Baseline approval cannot be performed remotely through Telegram. The root collector still has no incoming command channel or Telegram token.

`ProtectHome=read-only` deliberately allows the root collector to hash authorized_keys in fixed locations. This broadens root read visibility compared with the earlier hidden-home sandbox; no private-key contents are intentionally collected. Inventory limits and failures are surfaced. Root compromise can alter observations, the baseline and journal; this is not independent tamper-resistant evidence. UFW live kernel state, short-lived processes, offline journal gaps and other network namespaces remain limitations.

Automated regression tests cover the new logic; Linux sandbox behavior, real event collection and real Telegram delivery have not been validated on the macOS development host. Perform the documented disposable-VM acceptance checks before production use.

### Ubuntu systemd privilege-drop startup correction

With explicit `User=root` and this sandbox, CAP_SETUID can be present in the bounding set but absent from effective/permitted sets. systemd v255's exec-invoke.c drops CAP_SETUID in its explicit user transition path while keeping temporary seccomp setup privileges. The unit now uses the default root identity of a system service, omitting `User=root`, so Sentinel can perform its own permanent UID transition. The capability ceiling, NoNewPrivileges and syscall restrictions remain unchanged. No ambient capabilities are added. The existing Linux integration test verifies the main UID and zero effective/permitted capabilities after startup; live confirmation of this correction remains required.

### DNS monitor socket access correction

The service requires access to `/run/systemd/resolve/io.systemd.Resolve.Monitor` is mode 0600, owned by systemd-resolve. Connecting to an AF_UNIX socket requires write permission; CAP_DAC_READ_SEARCH alone cannot bypass that check. The collector capability ceiling now includes CAP_DAC_OVERRIDE. This is broader filesystem DAC bypass and increases collector compromise risk, although ProtectSystem=strict and the existing writable-path restrictions remain enforced. No resolver socket permissions, networking settings or NET_ADMIN capability are changed. The main process drops effective/permitted capabilities before Telegram starts. Confirm DNS observation and privilege dropping in live acceptance after applying this correction.

### Automatic WHOIS enrichment (0.3.9)

The unprivileged process now sends public destination IPs to IANA and a fixed set of regional WHOIS registries. Plain-text WHOIS is unauthenticated registration evidence and cannot establish trust or service identity. Untrusted fields are sanitized, bounded and presented only as data. Referrals are restricted to fixed registry hostnames; personal contact fields and arbitrary links are not displayed. A bounded daemon worker, cache, rate limit and send deadline isolate lookup failure from collector, polling and other alert delivery. No new root capability or installed dependency is introduced.
