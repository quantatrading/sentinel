# Sentinel 0.3.17

A small, passive watchdog for Ubuntu 24.04 Gunbot VPS hosts. Python standard library only. Telegram is the UI; there is no listener, web server, database, packet capture, firewall change, trading action, or remote command facility.

Start with [installation](#install-on-the-vps), then read the [configuration reference](docs/configuration.md) and [operations and troubleshooting guide](docs/operations.md). Developers should read [CONTRIBUTING.md](CONTRIBUTING.md). See [SECURITY.md](SECURITY.md) for privacy and reporting guidance, and [the publication review](docs/publication-review.md) for review scope and validation.

Download `sentinel-0.3.17.tar.gz` and its `.sha256` file from
[GitHub Releases](https://github.com/quantatrading/sentinel/releases/latest).
Place both in the same directory on your Ubuntu server:

```bash
sha256sum --check --strict sentinel-0.3.17.tar.gz.sha256
tar -xzf sentinel-0.3.17.tar.gz
cd sentinel-0.3.17
sha256sum --check --strict SHA256SUMS
sudo ./install.sh
```

Read the [installation prerequisites](#install-on-the-vps) before running the
installer. Alternatively, clone the repository with
`git clone https://github.com/quantatrading/sentinel.git` and run the installer
from that directory. Review the source before running it as root. Checksums
detect changed files; they do not authenticate the publisher.

The Python runtime uses only the standard library. Installation and monitoring require Ubuntu 24.04 with systemd; macOS can run the logic tests. This repository currently has no open-source license; publication does not select a redistribution license.

## Mechanisms and scope

| Observation | Mechanism | Limits |
| --- | --- | --- |
| Server DNS | `resolvectl --json=short monitor` | Completed local queries through systemd-resolved only; includes cache hits. Not all server traffic. No PID attribution. |
| Gunbot identity | `/proc/PID/comm`, `/proc/PID/stat` | Matches exact process name; tracks boot ID, PID and start ticks to distinguish PID reuse. No Gunbot cmdline, environment, executable contents or config reads. Interpreter selectors are inspected separately for tool detection. |
| Gunbot connections | Socket inode links in `/proc/PID/fd` matched to `/proc/net/{tcp,tcp6,udp,udp6}` | Host network namespace; sampled every 30s. TCP established/SYN-sent and connected UDP. Short-lived connections and unconnected UDP can be missed. |
| CPU, RAM, uptime, load | `/proc`, `os.getloadavg()` | Process CPU is percent of one CPU; first sample unavailable. RAM uses MemAvailable; process memory is RSS. |
| Filesystems | `statvfs` on configured `monitored_paths` | Disk and inode thresholds; defaults to `/`. Add paths on each volume you want monitored. |
| SSH | `journalctl -o json -f --since '24 hours ago' _COMM=sshd` | Available journal only; standard OpenSSH Accepted/Failed messages. Counts approximate 24h in minute buckets; partial while replaying. |
| Firewall configuration | Root collector reads `/etc/ufw/ufw.conf` and `/etc/default/ufw` | Reports saved enabled/default policy only; **live kernel status is unverified**. No network-administration capability. |
| Telegram | HTTPS Bot API long polling with TLS verification | Dedicated bot required; do not share it with Gunbot, another poller or a webhook. |

Ubuntu 24.04 ships systemd 255. The monitor's structured output and CNAME history are defined by the [systemd v255 resolvectl implementation](https://github.com/systemd/systemd/blob/v255/src/resolve/resolvectl.c) and [monitor interface](https://github.com/systemd/systemd/blob/v255/src/shared/varlink-io.systemd.Resolve.Monitor.c). Telegram requests follow the [official Bot API](https://core.telegram.org/bots/api).

DNS over HTTPS/TLS inside applications and applications bypassing systemd-resolved are invisible. No resolver settings are changed. Check your actual Gunbot resolver path during acceptance testing. A running collector does not prove complete coverage.

DNS answers create **60-second, in-memory correlation hints**, not IP allowlists. No reverse DNS is performed. Shared CDN IPs and concurrent queries mean correlation cannot prove which hostname a process contacted. `/network` labels a connection “recent known DNS (shared-IP hint)” or “unknown/unattributed”. Unattributed IPs generate one cautious notification per retained observation. They do not prove literal direct-IP use, compromise, or exfiltration. Existing long-lived connections at first startup can alert because their DNS lookup predates monitoring.

TCP connections using a Gunbot listening port are excluded as likely inbound. This is a heuristic; shared listeners, inherited sockets and unusual source-port reuse limit attribution. IPv4 and IPv6 are supported on little-endian Ubuntu VPS architectures. Containers and separate network namespaces are outside scope.

## Install on the VPS

Sentinel has been tested on Ubuntu and confirmed working by the project owner. The public-source review also passed all 74 automated logic tests on macOS. The acceptance checks below help verify each new deployment against its own resolver, process and Telegram configuration.

Prerequisites: Ubuntu 24.04, systemd running, Python 3, journalctl, resolvectl, systemd-analyze, useradd, sha256sum, and an already-active systemd-resolved. The installer checks these and installs no packages. It does not enable a resolver or adjust networking.

1. Copy this directory to the VPS. Create a **dedicated** Telegram bot through BotFather. Start a private conversation with it. Obtain your numeric chat ID and sender user ID through your trusted Telegram setup; avoid pasting tokens into URLs or shell history. Both IDs are required. For groups, configure the group chat ID and each allowed human sender ID separately.
2. From this directory, run:

   ```bash
   sudo ./install.sh
   ```

   On first install the wizard asks for the server name, bot token (hidden), allowed chat/user IDs, and management IPs/CIDRs. For a private chat, it offers the chat ID as the default user ID. Only api.telegram.org is known by default; no domain suffixes are approved. Default thresholds are applied automatically. You do not need to copy or edit JSON or environment files. The wizard writes directly to the protected installation locations, without an extra prepared secret file.

   The installer prints its actions, validates input, creates root-owned locations, installs the unit and uninstaller, and enables/starts Sentinel. It creates the dedicated `sentinel-watchdog` system account with no login shell or home directory. Existing installations are upgraded without prompting or overwriting configuration. A failed service stop aborts the upgrade; state ownership is migrated to the dedicated account. If a partial installation has only one configuration file, restore the missing file or uninstall and retry.
3. Send `/status` and `/security` to the bot. Check startup diagnostics with:

   ```bash
   sudo journalctl -u sentinel.service -n 30 --no-pager
   ```

An empty management-IP list treats every new successful SSH source as unfamiliar. Domain rules can be changed using `/allow` and `/remove`. The wizard validates formats locally; real Telegram delivery is verified after startup.

For automated installs or custom thresholds, the previous prepared-file option remains available: `sudo ./install.sh /root/sentinel.json /root/sentinel.env`. Copy/edit the example files first, keep the environment file root-owned mode 0600, and protect or remove these extra copies yourself. Secrets use unquoted `KEY=value`; comma-separated numeric IDs, at most ten chats/users. No shell expansion is performed.

Installed paths:

| Path | Ownership/mode | Purpose |
| --- | --- | --- |
| `/opt/sentinel/sentinel.py`, `sentinel_checks.py`, `sentinel_whois.py`, `sentinel_baseline.py`, `sentinel_incidents.py` | root:root 0644 | Application, read-only inside the service |
| `/opt/sentinel/uninstall.sh` | root:root 0755 | Removal tool, available without the downloaded source |
| `/etc/sentinel/` | root:root 0700 | Secret directory |
| `/etc/sentinel/sentinel.env` | root:root 0600 | Telegram token and authorised IDs |
| `/var/lib/sentinel/` | sentinel-watchdog 0700 | Only persistent writable application directory |
| `/var/lib/sentinel/sentinel.json` | sentinel-watchdog 0600 | Configuration plus `runtime` state |
| `/run/sentinel/` | root:sentinel-watchdog 0770 | Private health status; maintained by systemd |

For upgrades, copy the new files and run `sudo ./install.sh` without arguments. Existing config/state and secrets are preserved. Only Sentinel is restarted. To edit JSON manually, stop Sentinel first, edit and validate it, then start again; otherwise its next atomic save may overwrite your manual edit. `/allow` and `/remove` are the normal way to change rules while running.

```bash
sudo systemctl stop sentinel
sudoedit /var/lib/sentinel/sentinel.json
sudo python3 -I /opt/sentinel/sentinel.py --config /var/lib/sentinel/sentinel.json --check-config
sudo systemctl start sentinel
```

## Security baseline and additional checks

Installation starts monitoring, but drift comparison needs a reviewed baseline.
You can now approve it entirely through Telegram:

1. Send `/baseline review`. The bot shows the sampled file/listener metadata and
   a confirmation command containing its digest.
2. Use `/baseline review 2` and subsequent pages to inspect additional entries.
   Approval accepts the whole inventory, including pages you have not opened.
3. If the setup is expected, send the exact `/baseline approve DIGEST` command
   in the same chat, from the same authorised user, within five minutes.
4. Send `/baseline` to confirm the approved state.

Approval is rejected if the sampled inventory changes, is unavailable or stale,
or the review has expired. Files are sampled every 60 seconds and listeners
approximately every 10 seconds: this approves the latest complete observation,
not a fresh on-demand scan or a declaration that the server is secure. No file
contents are sent; the review contains paths, hashes, ownership, modes and
listener metadata. These details may be sensitive, so use a trusted chat.

Telegram approvals are saved with actor/chat IDs in the service-owned mode-0600
configuration/state file and audited before acknowledgement. All authorised
Telegram users can approve or replace a baseline. An attacker with access to an
authorised account or the service account can therefore change this reference.
The root collector remains read-only with no incoming command channel.

Local-root approval is also available:

```bash
sudo python3 -I /opt/sentinel/sentinel.py --baseline
sudo python3 -I /opt/sentinel/sentinel.py --accept-baseline DIGEST
```

Local approval freshly inspects the inventory and stores its reference at
`/etc/sentinel/baseline.json`. A Telegram approval takes precedence while that
local baseline digest remains unchanged. A subsequent local approval with a
**different digest** clears the Telegram override on the next collector sample.
Upgrades preserve both references; uninstall removes them. Review changes before
replacing either baseline.

The inventory hashes contents and permissions/ownership of SSH server configuration, authorized keys for root and direct `/home/*` users, sudo configuration, passwd/group, cron definitions, local systemd units and UFW configuration/rules. It reports additions, changes and removals without sending file contents. Nonstandard home directories are not covered. Symlinks are fingerprinted without following their targets; symlinked parent directories are marked rather than traversed. Limits are 512 files, 2 MiB per file, 16 MiB total and four nested directory levels; incomplete scans report unavailable rather than becoming an empty baseline. Files are sampled every 60 seconds.

TCP listeners and bound UDP endpoints are sampled approximately every 10 seconds and compared by protocol, address, port and owner name/UID. A loopback-to-wildcard change alerts. PID changes alone do not create drift. UDP ephemeral ports and service socket churn may create noise; these are observations, not proof of internet exposure. Other network namespaces and changes between samples are outside coverage. Saved UFW drift is read-only: Sentinel never invokes UFW or changes rules. Live-only nftables/iptables changes are not detected.

`npm`, `npx`, `pip`, `apt`, `apt-get`, `dpkg`, `curl` and `wget` process observations include tool, PID and UID, never URLs or full arguments. For Python/Node wrappers only the interpreter and module/script selector are read. Very short-lived, renamed or unusual wrappers may be missed, and process presence does not prove an installation or download. New dpkg install/upgrade/remove/purge records are also read, and its package database fingerprint is sampled every minute. Historical dpkg records are not replayed at startup; an offline change is detectable through a previously persisted database fingerprint, without necessarily identifying individual actions. npm/pip have no durable transaction-log coverage.

Set `expected_gunbot_instances` (default 1), `monitored_paths` (default `["/"]`), `thresholds.inode_percent` (90) and `thresholds.restart_starts_10m` (5) using the stopped-service configuration procedure above. Restart-storm alerts count new sampled Gunbot identities over ten minutes; starts between process checks can be missed. Maintenance suppresses only Gunbot lifecycle notices; security, tool, resource and reboot alerts continue unless globally muted.

Kernel OOM journal records alert from the time the collector starts. No deliberate OOM or restart is triggered. Clock status uses `timedatectl`'s reported synchronization state, with unknown reported as unavailable. Ubuntu's `/run/reboot-required` marker triggers a reboot-needed notice; its absence is not a universal guarantee that no restart is needed. Sentinel never reboots the server.

`/selftest` tests private state writes and collector freshness. Receiving the reply confirms Telegram delivery; it does not prove that every collector has observed a real event. `/selftest`, `/health` and `/baseline` expose unavailable checks. For authorized-key inventory the service uses `ProtectHome=read-only` rather than hiding home directories; the root collector therefore has broader read visibility, restricted in code to the fixed inventory. Private keys are not intentionally read. This tradeoff should be considered when reviewing collector compromise risk.

## Understand and approve a security change

Baseline changes now have a stable eight-character reference and a lifecycle.
A new difference generates one orange warning. Further unchanged observations
update the same record to **persistent**, including its first/last observation,
check count and elapsed duration; they do not generate hourly warnings. Pending
network deliveries can still retry until settled. Persistent reports use an
informational presentation without another ACTION REQUIRED heading.

```text
/sentinel
/sentinel investigate 432DE676
/sentinel acknowledge 432DE676
/sentinel approve 432DE676
```

Use the reference from your own alert; `432DE676` is only an example.
`/sentinel [page]` lists records, 20 per page. Investigation explains the before
and after state. **Acknowledge** records that an authorised operator has reviewed
the change, leaves the reference baseline unchanged, and stops pending warnings.
**Approve** accepts only that current difference into the reference; other file
or listener differences still require review. Neither command changes firewall,
process or service configuration. Mutations are saved before acknowledgement and
audited with actor, chat, operation and reference.

A stale or changed observation cannot be approved. Incomplete change lists cannot
be individually approved because that could accidentally accept other changes.
Use full `/baseline review` only when you intend to review and replace the whole
reference. All authorised Telegram users may acknowledge or approve changes.

Listener reports preserve baseline process names, UIDs and PIDs, including
multiple observed owners. An old baseline without PID metadata reports **PID not
recorded**; Sentinel cannot reconstruct a missing historical PID. PID metadata is
informational and excluded from the baseline digest/comparison so an ordinary
process restart does not itself create drift. Addresses, ports and owner
name/UID changes still do. An observed listener does not prove external reachability.

Records survive restart. A return to the expected state resolves an active
change; a later recurrence creates a new reference. Approving a removal makes
that absence expected, so the listener returning becomes a new addition.
Unchanged legacy drift counters migrate without hourly re-alerts; use `/sentinel`
for the new references, since old arbitrary message references are not recoverable.

At most 256 change records are retained; closed records are evicted first. If all
slots are active, Sentinel reports capacity exhaustion and remaining differences
are still available through `/baseline`. Counts represent sampled observations,
not independent incidents; file metadata can be cached between scans. Elapsed
duration can include downtime or missing samples. Unavailable observations do not
resolve a change. None of these states establishes that the server is secure.

## Telegram commands

| Command | Result |
| --- | --- |
| `/status` | Host resources, process count, collector status, last check, retained observation count |
| `/network` | Up to 25 currently sampled connections, IP/port/PID and DNS hints |
| `/security` | UFW saved configuration (live state unverified), SSH counts, unknown-domain/unattributed-IP counts, collector health and rate suppression |
| `/processes` | Up to 25 processes with PID, runtime, sampled CPU, RSS and listening ports |
| `/recent` | Recent observations with first/last/count and recent alert details, bounded to one message |
| `/known` | Domain rules, bounded to one message |
| `/allow api.example.com` | Add an exact domain to Sentinel only |
| `/allow *.example.com` | Add a suffix rule, matching subdomains but not the bare suffix |
| `/remove domain` | Remove the corresponding exact/suffix rule |
| `/mute 1h` | Suppress anomaly notifications for 1 minute-7 days; `s`, `m`, `h`, `d` supported |
| `/unmute` | Resume future notifications; muted observations remain in history |
| `/selftest` | State write/read probe, collector freshness, delivery and coverage status |
| `/listeners` | System TCP listeners and bound UDP endpoints, owners and available PID |
| `/sentinel [page]` | Tracked change references and lifecycle status |
| `/sentinel investigate REF` | Before/after evidence, process owners, duration and checks |
| `/sentinel acknowledge REF` | Mark reviewed without changing the baseline |
| `/sentinel approve REF` | Accept only this currently observed difference |
| `/baseline` | Approved baseline status, observed digest and first 15 changes |
| `/baseline review [page]` | Review sampled file/listener metadata and obtain an approval command |
| `/baseline approve DIGEST` | Accept the reviewed inventory in the same chat within five minutes |
| `/updates` | Recent tool/package observations and reboot-required status |
| `/health` | Configured filesystems, inode use, clock and reboot status |
| `/maintenance 1h` | Suppress Gunbot lifecycle/count/restart notices only; expires automatically |
| `/maintenance off` | End maintenance and resume lifecycle checks |
| `/management [page]` | Trusted SSH source IPs/CIDRs, 50 per page |
| `/management add <IP/CIDR>` | Add a trusted SSH source immediately |
| `/management remove <IP/CIDR>` | Remove an exact trusted SSH source rule |
| `/help` | Command list |

`api.telegram.org` is always known even if removed from JSON. Original query names are used across CNAME chains, avoiding notification loops through Telegram's resolver aliases. There are no active DNS probes or reverse lookups in normal monitoring.

Both chat and sender IDs must match the protected environment file. Anonymous admins, sender-chat identities, bots, channel posts and edited messages are not accepted. Commands older than five minutes are ignored. Use a dedicated bot: the application does not remove pre-existing webhooks or change bot settings. Token/API errors are never printed because exception URLs can contain credentials. HTTPS proxy environment variables are deliberately ignored.

## Alerts, persistence and resource bounds

- Two consecutive missing samples trigger a process-disappearance event. If all instances remain absent, there is one down alert; a fresh empty installation alerts on its first check. Recovery is reported when processes reappear. Planned restarts are indistinguishable from failures: use `/maintenance 1h` for planned Gunbot maintenance. Permission/read failures report degraded monitoring and do not mark processes dead.
- Unknown DNS events retain first seen, last seen, and observation count. Repeat notices default to a one-hour cooldown. IP notifications occur once while that IP observation remains retained. Counts for IPs are sample counts, not connection counts.
- New successful SSH sources alert when the event is less than two minutes old. Historical log replay populates counts without replaying old login alerts. The failure threshold defaults to 30 failures per approximate ten minutes. Collector reconnection rebuilds counts to avoid replay duplication.
- Critical and routine notices have separate dispatch budgets of five per minute each. At most 200 event notices are persisted; routine DNS/IP notices are limited to 100, reserving capacity for process, SSH, health and collector failures. Critical notices may evict routine notices at capacity. Overflow is counted as a delivery gap and exposed through `/security`; this bounded system cannot guarantee every notice under an unlimited critical-event flood.
- Pending alerts are saved before sending. Enqueueing does not mark an event delivered. Telegram success receipts update delivery state per recipient. Once every intended recipient is delivered, intentionally muted, removed or permanently failed, the event is settled for cooldown purposes. The `notified` timestamp records successful delivery only; `settled` is separate. Legacy cooldowns migrate without being claimed as successful deliveries.
- Polling and delivery use independent threads. A permanently invalid/blocked destination is recorded as a delivery gap and a bounded warning is sent to other configured chats; it does not block other chats or command polling. Transient sends retry with bounded backoff; Telegram 429 retry delays are respected. Critical jobs can displace routine jobs even from a saturated sender buffer; displaced jobs remain in persistent state for retry.
- Up to 2,000 retained event keys, 100 recent alerts, 2,000 short-lived DNS correlations, 256 process identities, 10,000 SSH cursors and approximately 1,441 minute buckets. Inactive observations expire after seven days by default. Evidence is bounded and may be evicted; it is not a forensic archive.
- The one-way collector stream is capped at 1 MiB per record. Queues: 50 commands, 100 outgoing jobs, 100 sender-buffer jobs and 500 receipts. More than 65,536 socket inodes or 2,000 candidate connections marks inspection unavailable. No packet capture files or ordinary DNS traffic logs.
- Dirty state flushes before dispatch, at most every five seconds during activity; commands flush before acknowledgement and shutdown flushes remaining changes. A crash can lose recent observations before that flush. Already-persisted pending notices survive restart. A crash after Telegram accepted a send but before the receipt was persisted can produce a duplicate: delivery is at-least-once best effort, not exactly-once.
- Atomic state writes retain 0600 mode and fsync/replace semantics. Temporary files are cleaned up after restart. Malformed configuration fails safely; malformed runtime resets observations while preserving valid configuration. Restore backups according to your own policy.
- Muting continues observation recording, suppresses new notices and cancels queued anomaly sends as they are processed. Muted notices are not replayed. Replies remain available. Permanent failures and overflow remain visible in the persistent delivery-gap count; they are not presented as delivered.
- Administrative changes record actor/chat/update IDs, action, validated domain target, outcome, mute before/after and whether configuration changed. Raw commands and tokens are not logged. This journal is still subject to host retention and protection policies; it is not tamper-proof evidence.
- Unit budgets remain 5% of one CPU, 128 MiB and 16 tasks, with low scheduling priority. Core dumps are disabled for the unit. Sustained floods can delay observations. Resource consumption and collector coverage still need measurement on the target host.

## Privileges and isolation

One systemd service starts a fixed-function root collector, then permanently changes the main process to the `sentinel-watchdog` account before starting Telegram threads. Supplementary groups are cleared and Linux drops effective/permitted capabilities on the UID transition. The main process only writes Sentinel's state and runtime directories.

The root collector receives no Telegram token, no incoming commands and no writable request channel. It observes DNS/SSH and kernel OOM journal events, inspects process/socket metadata, hashes fixed security files and the dpkg database, tails dpkg action records, and reads saved UFW configuration. Its only IPC output is a pipe to the unprivileged main process. Changing the local configured process name takes effect only at service restart; the value is validated and never interpreted as shell syntax.

The unit no longer grants `NET_ADMIN`, and neither process can administer networking through that capability. The root collector holds CAP_DAC_OVERRIDE to connect to the resolver-owned private monitor socket, in addition to powerful process-inspection privileges; compromise of it remains a risk. It shares the reviewed source file but never executes Telegram handling. This is privilege separation, not a claim that the collector is a complete sandbox against hostile kernel/OS input.

The application files and secret environment file remain root-owned. The dedicated user cannot modify them. The unit prohibits new privileges and incoming IP binds, restricts filesystems/kernel controls, and disables core dumps. Fixed subprocess argument arrays and minimal child environments remain in use. There is no Gunbot service dependency or remediation. systemd terminates Sentinel's entire cgroup on failure, including its root collector; the unprivileged main does not attempt to signal root children.

`Type=notify` readiness follows the first fresh collector snapshot. A main-loop heartbeat refreshes the 90-second systemd watchdog only while snapshots remain fresh. A stalled main process or collector therefore stops heartbeats and triggers a service restart. This is local recovery, not an independent outage notification service.

For your existing external monitoring, run `sudo python3 -I /opt/sentinel/sentinel.py --health-check`. It exits nonzero for a missing/stale local progress record and prints polling/delivery status for the monitor to assess. Configure that external monitor and an independent notification channel separately; none is provisioned or contacted automatically.

## Verification and VPS acceptance

Run logic tests without Telegram credentials or Linux privileges:

```bash
python3 -m unittest discover -s . -v
python3 sentinel.py --config sentinel.json.example --check-config
bash -n install.sh
```

The tests cover config/domain validation, suffix boundaries, auth, duplicates, cooldowns, mute/unmute including queued notices, persistence/permissions, interrupted atomic writes, damaged runtime, bounded growth/rate limits, SSH parsing/dedupe/CIDRs, IPv4/IPv6 inode attribution and listener exclusion, PID reuse, process loss/recovery, permission failure, Telegram outage/redaction, and Telegram CNAME loop protection.

Before relying on it, perform these checks on an Ubuntu 24.04 staging VPS or carefully on your VPS:

1. Run `sudo systemd-analyze verify /etc/systemd/system/sentinel.service`; inspect `sudo systemctl status sentinel` and its journal. Send `/status` and `/security`; confirm both collectors stay running and UFW output clearly says live state is unverified; compare saved configuration and actual status manually with `sudo ufw status verbose`. Verify the actual DNS path from `/etc/resolv.conf` and `resolvectl status`.
2. Use `resolvectl query example.com` and confirm one unknown-domain notice, then repeat it to check count increments without another notice. Use `/allow example.com`, repeat, then `/remove example.com`. Send repeated `/status` commands and confirm Telegram's own DNS stays quiet.
3. Send `/mute 1m`, query a new test domain, and check `/recent` records it with no anomaly notification. Unmute; command replies should still work throughout.
4. Compare `/processes` and `/network` with local `ps`/`ss`. Do not kill a trading process to test this. On staging, temporarily configure the process name to `sleep`, run `sleep 300`, then terminate that test process and start another; verify loss/recovery before restoring the Gunbot name.
5. Use an existing SSH session from an unlisted management IP to verify source detection; add its approved IP/CIDR in config if appropriate. Compare the rolling counts with the retained sshd journal. No need to create a password attack against production.
6. Restart **Sentinel only** and confirm domain rules/mute/history survive. From an unauthorised account/chat confirm commands have no effect. Test a bad token on staging and verify monitoring continues, no token appears in logs, and restoring it recovers.
7. Inspect `sudo ss -lntup` and Sentinel's unit/cgroup: it adds no listening port. Observe CPU/RSS with normal traffic and initial journal replay. Confirm Gunbot PIDs/trading continue unchanged when Sentinel stops.

To disable: `sudo systemctl disable --now sentinel`. This leaves configuration/state for recovery and does not affect Gunbot. Protect Telegram account access, rotate the token if exposed, and retain your usual external VPS monitoring: a crashed watchdog cannot alert through itself.


## Uninstall and remove remaining copies

Run the installed removal tool:

```bash
sudo /opt/sentinel/uninstall.sh
```

It prints the deletion plan and asks you to type `REMOVE`. It stops/disables Sentinel, verifies it is stopped, then deletes the application (including the uninstaller), token, configuration, history, state, runtime files, installed unit and Sentinel-specific unit overrides. It reloads systemd and clears Sentinel's failed status. No packages were installed. The dedicated system account is deleted only when Sentinel’s installer created it, identified by its root-owned marker. The installer creates no firewall or DNS rules to undo.

To inspect the plan without changes, use `sudo /opt/sentinel/uninstall.sh --dry-run`. For unattended removal, use `sudo /opt/sentinel/uninstall.sh --yes`. Symlinked installation directories and mounted content are refused before deletion. If using an older install without the installed removal tool, run `sudo ./uninstall.sh` from this downloaded directory. The source copy can also be rerun after removal.

The following are separate from the installation and require your own cleanup if you want to retire all copies:

- Delete the downloaded Sentinel directory/archive and any prepared files such as `/root/sentinel.env` and `/root/sentinel.json`. The wizard creates no such prepared copies; older/manual installation instructions did.
- Revoke/delete the dedicated bot through BotFather if no longer needed, and remove its Telegram conversation/messages. Removing a local token file does not revoke the token or delete remote messages.
- Remove Sentinel copies from your own backups/snapshots according to your retention policy. File deletion does not guarantee forensic erasure from SSDs, VPS storage or provider snapshots.
- Historical entries may remain in the shared system journal and forwarded syslog. Sentinel does not erase shared logs. [journalctl vacuuming](https://www.freedesktop.org/software/systemd/man/255/journalctl.html) deletes archived journal files, not just one service's records; normal retention will expire those entries. Do not vacuum the whole journal merely to uninstall Sentinel.

The uninstaller removes the installed software and its dedicated data. It cannot promise removal of every historical trace from shared logs or third-party storage.


## Release integrity and support

This release identifies itself as 0.3.17 in `/status` and local health output. The installer verifies `SHA256SUMS` before installing source files. A checksum shipped beside a download detects damage but **does not authenticate that download**. You must obtain the source and expected manifest digest through a trusted channel.

For releases, run `python3 release.py` after review and tests. Publish its resulting manifest digest through an independently trusted channel. An optional `SENTINEL_EXPECTED_MANIFEST_SHA256` pin makes the installer fail on a manifest mismatch. Verify that pin/manifest using trusted tooling **before executing the installer**; a modified installer cannot be trusted to verify itself. No signing identity or third-party certification is asserted by this package.

The deployment owner must approve updates, track Ubuntu/Python/OpenSSL security fixes, retain rollback configuration and define a support/incident-response contact. This local project has no externally operated update or vulnerability-response service.

## Disposable Ubuntu integration test

On a clean Ubuntu 24.04 VM with systemd-resolved already active:

```bash
sudo env SENTINEL_TEST_DISPOSABLE=yes ./test_linux.sh
```

This refuses an existing Sentinel install. It uses a deliberately invalid token, verifies the actual main UID and zero effective/permitted capabilities, tests local readiness during Telegram failure, suspends only Sentinel's main process to exercise watchdog recovery, then uninstalls. It does not stop Gunbot, change networking, or create a container stack. A failed test may leave Sentinel installed for diagnosis; run its uninstaller when finished.

The project owner has confirmed successful testing on Ubuntu. This specific disposable-VM script was not run during the macOS public-source review, and its execution is not implied by that confirmation. Check real Telegram delivery, actual Gunbot DNS coverage and host resource consumption on each new deployment.

### Additional staging acceptance for 0.3.0

On a disposable Ubuntu VM, approve a reviewed baseline, start a temporary listener and confirm drift, then remove it. Change a harmless staged cron definition and verify its hash alert without contents. Exercise `/maintenance 1m` and expiry with a dummy monitored process, and `/selftest` with working Telegram credentials. Hold a curl/wget process long enough to span a sample and confirm no URL appears in messages. Verify a staged dpkg action, configured volume/inode thresholds, and a temporary reboot-required marker. Restore all staging fixtures. Do not create an actual OOM, alter production UFW rules or reboot production to test these alerts. Use these checks when validating a new deployment or changes to monitoring behaviour.

### Instance counting (0.3.1)

Matching Gunbot parent/child chains count as one instance. `/selftest` and `/status` distinguish instance count from process count. All matching processes remain monitored for network activity, disappearance and repeated starts. Grouping uses PPIDs from the same snapshot, not executable paths or command lines. Reparented workers or nonmatching intermediary parents can split a family; process-family count is an observation rather than proof of application health.

## Telegram reporting framework (0.3.5)

Every Telegram output uses a compact operational report: title, host and readable UTC creation time, a severity indicator, actions when needed, observations, then a short reference/version footer. Actions come before detail. Routine acknowledgements, help and informational replies have no generic action paragraph. This is a military-inspired house style, not an official military standard or classification system.

`/selftest` and `/status` summarise normal checks, with specific coverage descriptions for DNS (systemd-resolved lookups), SSH (available login journal) and kernel monitoring (new OOM events). `/health` retains individual checks and filesystem detail. `/network` shows unexplained endpoints first; correlation remains a hint. `/recent` avoids duplicating event summaries and alert bodies. Domain acknowledgements identify the affected rule, and maintenance replies include expiry or confirm it ended. `/help` explains every command with examples.

Colour is paired with readable labels; routine green/blue markers are removed from body lines so exceptions stand out. INFO/NOTICE indicate information, WARNING attention, and CRITICAL process disappearance, all-process absence or OOM. Severity is independent of queue priority and does not establish compromise. A collector starting during the initial 60-second grace period is described as initializing, not failed; prolonged startup still requires investigation. Receiving a report proves that message arrived, not that every configured destination received it.

References remain stable across retries and recipients. Timestamp is creation time rather than retry/delivery time. The message reserves space for actionable findings and marks omitted detail explicitly when approaching Telegram's length limit. Legacy queued alerts also receive the new presentation.

Example:

```text
SENTINEL · READINESS · EXAMPLE-SERVER
🟠 ATTENTION - 2 outstanding actions

ACTION REQUIRED
1. Use /baseline review; approve its digest only if the inventory is expected.
2. Schedule a controlled server reboot manually; Sentinel will not restart it.

OPERATIONAL STATUS
State write/read: PASS
Collector freshness: PASS - 7s since sample
Gunbot instances: 2 / expected 2
Matching Gunbot processes: 4
Alerts: 0 pending · 0 recorded delivery gaps

MONITORING
DNS monitor: RUNNING - systemd-resolved lookups only
SSH journal: RUNNING - available login journal
Kernel journal: RUNNING - new OOM events only
Checks passing: listeners tools, package inventory, package log, processes, resources.

Ref: A1B2C3D4 · 26 Sep 2026, 13:15 UTC · Sentinel 0.3.11
```

Run `/selftest`, `/status`, `/health`, `/help`, and an invalid command after upgrading to verify live rendering. Automated tests cover all supported command envelopes, actions-first layout, acknowledgements, startup grace, scope labels, legacy alert delivery, severity and UTF-16 message limits.

Version 0.3.6 uses ordinary hyphens instead of long dashes in output. The final Telegram formatter also normalizes long dashes in legacy queued messages and dynamic content.

Version 0.3.7 defaults to api.telegram.org only, displayed once in `/known`. Upgrades preserve existing saved domain rules. Review `/known` after upgrading and remove any unwanted earlier rules with `/remove domain` or `/remove *.suffix`. Explicitly approved custom domains remain supported.

Version 0.3.9 automatically queries WHOIS for public outbound-IP alerts and places registration data directly in the report. No click or user lookup is needed. It uses IANA referrals restricted to the five regional registries on TCP port 43, extracts bounded organisation/network/range/country fields, and never follows arbitrary referral hosts. Registry country is not server geolocation, and registration data is not proof of service identity or safety. Missing fields are labelled rather than inferred.

The lookup runs in a single background thread of the unprivileged Telegram process. Other alerts and polling continue while an IP alert waits up to four seconds for enrichment. Results are cached for 24 hours (failures five minutes), capped at 256 addresses; pending work is bounded to 16 and new requests to one per two seconds. Socket operations have timeouts and responses are capped at 64 KiB. Timeout/capacity/registry failures are shown directly in the alert, which is sent without enrichment. No WHOIS lookup is made for non-public/special-use addresses.

Automatic lookup discloses the queried destination IP to IANA and the responsible regional registry. It does not transmit the Telegram token, server label, PID or Gunbot configuration. Registry DNS lookups may themselves be observed by Sentinel; registry domains are not silently added to known-domain rules. Check Telegram rendering and installed-service behaviour after upgrades.

Version 0.3.10 combines the network alert heading into NETWORK OBSERVATION and removes the duplicate NETWORK body label, including in legacy queued alerts.

Version 0.3.11 displays the uppercase server label beside the report title and places the UTC creation timestamp on the footer line with Ref and version.

Version 0.3.12 supports management IP configuration entirely through Telegram. `/management` lists trusted SSH sources; `/management add <IP/CIDR>` and `/management remove <IP/CIDR>` change the list. Bare addresses become /32 (IPv4) or /128 (IPv6); CIDRs are normalized to their network address and displayed in the acknowledgement. Removal requires an exact normalized rule, not a host contained within a wider rule. Existing chat/user authorization applies; changes are saved before acknowledgement and audited with the actor, target, operation and outcome. These settings classify SSH alerts and do not modify firewall rules or grant SSH login access.

Version 0.3.13 removes the network-online boot dependency. Local monitoring starts after network.target without waiting for configured interfaces to become fully online; Telegram and collectors retry independently. This avoids delaying local monitoring behind systemd-networkd-wait-online when an interface is not ready. The correction does not disable or reconfigure the host network wait service. Verify startup on the next planned reboot; no production reboot is performed by the installer.

Version 0.3.14 adds Telegram baseline review and approval with digest confirmation, same-user/chat binding, five-minute expiry, freshness checks, persistent state and audit logging. The collector remains read-only.

Version 0.3.15 introduces persistent security-change records, scoped acknowledgement/approval, and listener PID history. Unchanged baseline drift no longer produces hourly warnings.

Version 0.3.16 separates security-file hashing health from listener scanning and baseline comparison. Failures include safe reason codes in alerts and `/health`. A dependent baseline check is marked blocked rather than reported as a second file-hashing failure. Incomplete scans remain unavailable.

Version 0.3.17 handles descriptor-link permission errors caused by confirmed process exits. Genuine denials retain the operation, PID and FD; `/health` preserves the last listener failure after recovery. See [intermittent errno 13](docs/operations.md#intermittent-errno-13-during-listener-inspection) for the evidence and remaining diagnostic limits.
