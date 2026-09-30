# Alerts after a firewall block

The monitor's Windows Firewall rule must be enabled, inbound, blocking the exact
source address, and enabled for every active Windows Firewall profile before
post-block grouping is allowed. Saved `blocked_ips.json` entries alone are not
proof. Policy results are cached for up to five seconds. Failed or unavailable
verification leaves normal alerting enabled.

The source, destination, endpoint ID, protocol and detector attack/signature
identify an incident. Matching observations after a confirmed local block update
the existing incident ID, `attempts_after_block` and `last_seen`. They do not
increase the dashboard incident count or trigger repeated sounds, emails,
Telegram messages or playbooks. This count measures detector observations, not
packets proven dropped. A different signature, destination or endpoint remains
separate. Correlated Snort/ML incidents retain both detection identities. A new
block lifecycle gets a new incident. Existing historical duplicates are retained.

Raw repeat observations are kept in SQLite `post_block_attempts` and appended to
the SHA-256 audit chain. Grouped incident state also survives a correlator restart
through the existing JSON feed. Clearing/resetting alert history clears this
evidence along with the other alert history.

## Scope and verification

These inbound rules protect the monitoring PC only. An alert for another victim
is not silently treated as blocked. Victims require their own enforcement or a
gateway; this change does not deploy remote firewall rules.

In **Incident Response & Firewall**, record a service-access test performed from
Kali against a monitoring-PC IP. Identify the service/port and observed result.
Successful access produces **Block ineffective (operator reported)** and disables
grouping for that source/target. Unreachability is recorded without claiming the
firewall caused it. The application does not probe a remote attacker or infer
successful compromise from captured packets. Removing/recreating a rule clears
the prior test results for that block lifecycle.

If a Windows network profile has its firewall disabled, enable it using Windows
Security and retry the block with administrator privileges. Do not treat a
software-only entry as OS enforcement. Restart the IDS engines after updating
the correlator and detector code; refresh the dashboard for the new fields.

## Regression checks

From the project root:

```powershell
py -3 -B -m unittest discover -s backend -p test_block_grouping.py -v
```

The suite uses a temporary database and mocks firewall changes and notifications;
it does not alter the live firewall, send test notifications, or reset real logs.
