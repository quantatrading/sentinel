# Security and privacy

Sentinel is a supplementary, sampled watchdog. It is not an intrusion-prevention
system, a complete audit archive or a security certification. See the
[review](SECURITY_REVIEW.md) and [monitoring limits](README.md#mechanisms-and-scope).

## Data handling

Telegram receives report content including the configured server label, observed
domains, IP addresses, usernames and process/security metadata. Authorised users
can change rules, mute alerts, acknowledge security changes and approve either
a whole baseline or an individual difference. Scoped approval preserves other
differences; acknowledgement does not change the reference. Telegram baseline
approvals are stored in service-owned state and can be replaced by any authorised
user. A compromised operator or service account can alter this reference; it is
not a root-protected trust anchor. Reviews disclose file paths, hashes, modes,
ownership and listener metadata to the authorised chat, never file contents. Use a dedicated bot and protect operator accounts.

Public destination IP alerts automatically query IANA and a fixed regional
WHOIS registry over unencrypted TCP 43. This discloses the queried IP; registration
data is not authenticated or proof of identity. There is currently no configuration
switch to disable enrichment. Do not deploy where that data flow is unacceptable.

The fixed root collector hashes selected security files and inspects process and
socket metadata. It has broad read privileges. The Telegram process permanently
drops privileges, and the collector receives no bot token or command channel.
This boundary is not protection against a compromised host administrator.

Credentials, baseline data, runtime state, journals, screenshots and backups are
private deployment data. Keep populated files outside Git. `.gitignore` helps
prevent accidental additions but does not protect files already committed or
explicitly force-added. Rotate exposed credentials even after removing a file.

## Reporting

Use the repository's **Security → Report a vulnerability** private reporting
option when available. Do not open a public issue containing exploitation details,
credentials or private host data. If private reporting is unavailable, open a
minimal issue requesting a private contact, without sensitive details.

Include the affected version, a minimal sanitised reproduction and the expected
versus observed behaviour. There is no guaranteed response time or formal support
SLA. Operators are responsible for reviewing updates and maintaining OS dependencies.
