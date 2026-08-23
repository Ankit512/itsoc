# SSH brute-force / credential attack response

Applies to rules: `auth_bruteforce`, `auth_bruteforce_success`, `possible_break_in`.

## What this pattern means

A burst of failed password or login attempts from one source IP is an
automated credential-guessing attack against ssh. When a success follows the
failures from the same source within the compromise window, treat the account
as compromised — the auth success is the pivot point, not the failures.

## Immediate steps

1. Block the source IP at the firewall; do not rely on the attacker giving up.
2. If a success followed the failures: disable or lock the targeted account,
   rotate its credential, and invalidate its active sessions before anything else.
3. Review auth activity for the same user from other sources — password reuse
   makes one guessed credential a fleet-wide problem.
4. Check for username-spray shape (many users, one source): that changes the
   response from "protect one account" to "protect the auth surface".

## Evidence to preserve

Keep the raw auth log lines for the full failure window plus one hour either
side, and record the source IP, targeted usernames, and attempt count from the
finding itself — the rule's evidence is the verbatim log text.
