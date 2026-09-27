# Configuration reference

The installer wizard creates `/etc/sentinel/sentinel.env` and
`/var/lib/sentinel/sentinel.json`. For unattended installation, copy the example
files into a protected directory, edit them, and run:

```bash
sudo chmod 600 /root/sentinel.env
sudo chown root:root /root/sentinel.env
sudo ./install.sh /root/sentinel.json /root/sentinel.env
```

The prepared environment file must not be a symlink. Remove or protect prepared
copies after installation. Never commit populated configuration or state.

## Telegram credentials

Use unquoted `KEY=value` lines, with no shell expansion:

| Variable | Meaning |
| --- | --- |
| `TELEGRAM_BOT_TOKEN` | Complete token for a dedicated bot created through BotFather |
| `TELEGRAM_CHAT_IDS` | 1–10 nonzero numeric destination chat IDs, comma-separated; group IDs can be negative |
| `TELEGRAM_USER_IDS` | 1–10 positive numeric sender user IDs, comma-separated |

Start a conversation with the bot before use. Both the chat and sender must be
allowed. Every allowed user can administer Sentinel in any allowed chat; there
is no view-only role. This includes `/sentinel acknowledge REF`, `/sentinel approve REF`,
`/baseline review` and `/baseline approve DIGEST`: any authorised user can replace the reference after reviewing it. Bots, anonymous sender-chat identities, channel posts and
edited messages are rejected. Updates older than five minutes are ignored.
Do not share the bot with another poller or webhook.

## JSON fields

Unknown fields are rejected. Numeric ranges below include both endpoints.

| Field | Default | Accepted value / effect |
| --- | --- | --- |
| `server_name` | Hostname | 1–64 letters, digits, spaces, dots, underscores or hyphens; must not be blank; sent in reports |
| `gunbot_process` | `gunthy-linux` | Exact Linux process name, 1–15 letters, digits, dots, underscores or hyphens |
| `known_domains` | Empty; wizard adds `api.telegram.org` | Up to 2,000 exact ASCII domain names; Telegram is always treated as known |
| `known_domain_suffixes` | `[]` | Up to 2,000 suffixes such as `example.com`, without `*.`; matches subdomains, not the bare domain |
| `known_management_ips` | `[]` | Up to 2,000 IPv4/IPv6 addresses or CIDRs; normalised to networks; classifies SSH sources only |
| `expected_gunbot_instances` | `1` | Integer 1–256; matching parent/child families count as one instance |
| `monitored_paths` | `["/"]` | 1–16 absolute paths, at most 256 characters each, no control characters or `..` components |
| `alert_cooldown_minutes` | `60` | 1–10,080; repeat observation notice cooldown |
| `check_seconds` | `30` | 10–3,600; main evaluation interval; collector sampling has its own cadence |
| `retention_days` | `7` | 1–30; inactive observation retention, also subject to capacity limits |
| `runtime` | Generated | Internal observations, queues, offsets, delivery state, change records and Telegram-approved baseline; do not hand-edit |

The `thresholds` object accepts:

| Field | Default | Range |
| --- | --- | --- |
| `disk_percent` | 90 | 1–100 |
| `memory_percent` | 90 | 1–100 |
| `inode_percent` | 90 | 1–100 |
| `load_per_cpu` | 2 | 0.1–100 |
| `ssh_failures_10m` | 30 | 1–1,000,000 |
| `restart_starts_10m` | 5 | 2–256 |

## Apply changes

Use Telegram `/allow`, `/remove` and `/management` commands for routine rule
changes. They save before acknowledgement. Rules do not modify DNS or firewalls.
For other settings, stop the service to avoid racing its state writes:

```bash
sudo systemctl stop sentinel
sudoedit /var/lib/sentinel/sentinel.json
sudo python3 -I /opt/sentinel/sentinel.py --config /var/lib/sentinel/sentinel.json --check-config
sudo systemctl start sentinel
```

Only start after validation succeeds. Preserve service-account ownership and
0600 mode. To change credentials, stop Sentinel, use
`sudoedit /etc/sentinel/sentinel.env`, preserve root ownership and 0600 mode,
then start the service. `--check-config` validates JSON, not Telegram access.
Confirm delivery with `/selftest` after either change.

## Local command line

| Option | Use |
| --- | --- |
| `--help` | Show options without starting monitoring |
| `--config PATH --check-config` | Validate a JSON file without starting collectors |
| `--setup` | First-install wizard; normally invoked by the installer, which creates directories |
| `--config PATH --env-file PATH --setup` | Wizard with explicit output paths; refuses existing files |
| `--health-check` | Check `/run/sentinel/health.json` freshness and process liveness; does not prove delivery |
| `--baseline` | Local Linux root: print security inventory and digest for review |
| `--accept-baseline DIGEST` | Local Linux root: approve only the matching current inventory |
| `--collect`, `--process NAME` | Internal collector interface; normally managed by the service |

Normal operation must start through `sentinel.service` on Linux.
