# Operations and troubleshooting

## First-run acceptance

1. Install on Ubuntu 24.04 with an already-active systemd-resolved.
2. Send `/selftest`, `/status`, `/security` and `/network` to the dedicated bot.
3. Send `/baseline review` in Telegram and inspect the inventory pages. If the
   setup is expected, send the supplied `/baseline approve DIGEST` command from
   the same user/chat within five minutes, then check `/baseline`. Local-root
   approval remains available; see the README for precedence.
4. Check the expected instance count, monitored filesystems and management IPs.
5. Follow the [VPS acceptance checks](../README.md#verification-and-vps-acceptance).
   Unit tests alone do not verify the service sandbox or actual event coverage.

## Daily use

Use `/sentinel` for tracked security changes and their references.
`/sentinel investigate REF` shows previous/current state and listener owners.
`/sentinel acknowledge REF` records review without accepting the change;
`/sentinel approve REF` accepts only that current difference. A repeated check
is not a new incident, and unchanged persistent drift does not send repeat
warnings. Use `/baseline review` only to replace the whole reference.

Use `/status` for a summary, `/recent` for retained events, `/network` for sampled
connections, and `/health` for filesystems, clock and reboot status. Unknown DNS
and IP observations warrant investigation; they do not prove compromise.
Approve a domain only after identifying why it is expected.

For planned Gunbot work, `/maintenance 1h` suppresses lifecycle notices only.
Use `/maintenance off` afterwards. `/mute 1h` suppresses all anomaly notices;
`/unmute` resumes future notices without replaying suppressed events.

## Diagnose locally

```bash
sudo systemctl status sentinel --no-pager
sudo journalctl -u sentinel.service -n 50 --no-pager
sudo python3 -I /opt/sentinel/sentinel.py --health-check
```

Journal and health output can reveal host details and account IDs. Redact before
sharing. Do not paste environment files, runtime JSON or raw baseline inventories
into a public issue.

| Symptom | Checks / action |
| --- | --- |
| Installer refuses OS or resolver | Confirm Ubuntu 24.04, running systemd and active systemd-resolved; resolve prerequisites before retrying |
| No Telegram replies | Check token, allowed chat **and** user IDs, start a chat with the bot, check outbound HTTPS and conflicting webhook/poller; HTTPS proxy environment variables are ignored |
| Telegram 401 / invalid token | Replace or rotate the token through BotFather; edit the protected environment file and restart |
| Delivery fails for one chat | Confirm bot membership and that the recipient has not blocked it; inspect delivery-gap count |
| DNS unavailable | Inspect systemd-resolved and journal errors; use the supplied unit; do not loosen resolver socket permissions |
| No DNS events from Gunbot | Check whether Gunbot uses systemd-resolved; application DoH/DoT and other resolvers are outside coverage |
| Unattributed IP at startup | Its DNS lookup may precede monitoring or use a shared address; investigate before approving rules |
| WHOIS unavailable | TCP 43 may be blocked, or the registry/rate/capacity limit reached; alerts still deliver without registration data |
| Baseline not approved | Use `/baseline review`; approve a digest only for an expected setup |
| Baseline drift | Use `/sentinel investigate REF`; acknowledge review or approve just that expected difference |
| Historical listener PID unavailable | Older baselines did not record PIDs; names/UIDs remain available. Do not infer a historical PID from current processes |
| Baseline approval rejected | Review again in the same chat/user; inventory may have changed, become stale or the five-minute review window may have expired |
| Wrong instance count | Compare process names and parent/child families; adjust `expected_gunbot_instances` only after inspection |
| Service stops safely | Use the logged error type, errno and code location; exception text is deliberately hidden to protect credentials |
| Start limit reached | Correct the cause, then `sudo systemctl reset-failed sentinel` and `sudo systemctl start sentinel` |

## Host checks unavailable

`listeners_tools` covers the system listener/owner inventory and sampled package
or download-tool processes. `security_files` covers hashing the selected security
files. Baseline comparison needs both inventories.

In 0.3.15 and earlier a listener failure also labelled `security_files` unavailable,
even when hashing succeeded. From 0.3.16, each check reports its own health and
baseline comparison is marked blocked by the missing input. Send `/health` for
the current status and the safe reason in a failed check. A warning's historical
first-seen timestamp and count do not establish uninterrupted failure.

Permission failures, inspection limits, files changing during hashing and invalid
inspection data require different remedies. Do not disable the service sandbox,
skip inaccessible processes or approve a new baseline to silence a failure.
Missing observations cannot establish whether a security change occurred.
For deeper diagnosis, use `sudo journalctl -u sentinel -n 50 --no-pager`; redact
host details before sharing. The safe diagnostic reason excludes raw exception
text, credentials and filesystem paths.

## Upgrade, backup and rollback

Before upgrading, stop Sentinel and take a protected backup of
`/etc/sentinel/` and `/var/lib/sentinel/`, preserving ownership and modes. These
contain credentials, baseline data and operational history. Store them outside
the repository with access limited to administrators. Start the service again
if the upgrade is deferred.

Download and review the complete new source tree and verify `SHA256SUMS`. Run
`sudo ./install.sh` with no prepared-file arguments. It preserves existing
configuration and restarts Sentinel. Confirm `/selftest` and inspect the journal.
Unit changes can legitimately cause baseline drift; review it.

There is no automatic rollback or downgrade compatibility guarantee. Keep the
previous source tree and matching protected configuration/state backup. To
recover, stop Sentinel, restore compatible configuration with its original
ownership/modes, run the previous installer, and validate delivery and coverage.
Do not use uninstall as an upgrade step: it deletes state and credentials.

## Availability and retirement

Use independent VPS monitoring for a failed host or Telegram outage. A local
health check indicates recent collector progress, not complete event coverage or
successful delivery to every destination.

`sudo systemctl disable --now sentinel` disables monitoring but keeps data.
`sudo /opt/sentinel/uninstall.sh --dry-run` previews removal; running without
`--dry-run` requests confirmation and removes dedicated installation data.
Revoke the bot separately when retiring it. Shared journals, Telegram messages,
downloads and external backups need separate retention decisions.
