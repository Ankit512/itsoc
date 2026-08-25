# Suspicious outbound connection (possible C2) response

Applies to rules: `suspicious_outbound`.

## What this pattern means

An internal host opened (or tried to open) a connection to a destination port
associated with malware command-and-control, crypto-mining pools, or remote
tunnelling. Even when the firewall blocked the attempt, the attempt itself is
the finding: something on that host chose to dial out. A blocked connection
protects the network, not the host — the process that made the attempt is
still running.

## Immediate steps

1. Identify the process behind the connection on the source host (socket
   owner at the logged time; on Linux `ss -tpn` / auditd, on Windows
   Sysmon event 3).
2. If the connection was ALLOWED: isolate the host from the network first,
   then investigate — an established C2 channel means interactive control.
3. If it was blocked: do not stand down; sweep the host for the initiating
   binary or scheduled task, and check for retries to other ports or
   destinations from the same host.
4. Check whether other hosts contacted the same destination IP — one dialer
   is an infection, several is a campaign.

## Evidence to preserve

The verbatim firewall/log lines for the attempt window, the destination IP
and port from the finding, the owning process name and hash once identified,
and the host's outbound connection log an hour either side.
