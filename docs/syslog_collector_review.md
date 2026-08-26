# Syslog collector rewrite — review vs the honesty model

*Reviewed 2026-08-26 (branch `feat/syslog-collector-fixes`, base `cb8c47c`) against
the properties the pre-pivot collector was valued for: source-reported severity
only, loopback-default bind, TCP support, store-contract docs.*

## What the rewrite gained

- **Multi-port concurrent listeners** (UDP 513/514/1514) with per-listener
  status: `received` / `stored` / `errors` / `lastError` / `lastSource` /
  `lastMessageAt`. The received-vs-stored gap makes store failures visible
  instead of silent.
- **Honest lifecycle**: idempotent `start()` for an unchanged config; partial
  bind failure rolls back every already-started listener and reports the real
  reason (permission-denied on <1024, address-in-use); `status()` reflects live
  thread state, never a cached "running".
- **Bounded memory**: counters only, no unbounded message list; 65,535-byte
  datagram cap.
- RFC5424 header parsing (crashed until this branch — see below).

## Honesty/safety properties: kept, dropped, fixed

| Property | Verdict |
|---|---|
| Source-reported severity only | **KEPT.** Severity comes strictly from the PRI (`pri % 8`); no PRI → empty severity. Never keyword-guessed (tested). Store passes it through verbatim (`console/store.py` honesty model). |
| Loopback-default bind | **KEPT.** Collector default `bind="127.0.0.1"`; the `/api/syslog/start` route also defaults to loopback and refuses any bind that isn't `127.0.0.1`/`localhost`/explicit `0.0.0.0` (honest 400, no silent coercion). |
| Raw verbatim / no fabricated evidence | **KEPT.** `raw` is the decoded wire text, PRI envelope included (tested down to the stored row). |
| RFC3164 envelope hostname | **WAS DROPPED — FIXED on this branch** (`cd829ac`). `host` had regressed to the sender IP for every RFC3164 event, presenting the relay as the origin on relayed streams. Now parsed with the same `normalize.RFC3164_RE` the file pipeline uses; sender-IP fallback only when the envelope names no host, labeled via `host_source: "envelope" | "sender-ip"`. |
| RFC5424 parsing | **WAS BROKEN — FIXED on this branch** (`cd829ac`). The header regex has 7 groups but was unpacked 6-ways: every RFC5424 datagram raised `ValueError` and was dropped as a listener "error" — a silent drop of a whole message class (and the intended mapping had `host` = the timestamp). |
| TCP support | **DROPPED.** The rewrite is UDP-only. The surface is honest about it (`protocol: "UDP"` everywhere), so nothing is faked — but reliable delivery / RFC 6587-framed relays are no longer servable. Not a quick fix (framing + connection lifecycle); recommendation below. |
| Store-contract docs | **KEPT.** Writes go through `store.insert_event` (dedup by `event_hash`); the contract and its severity-pass-through honesty model are documented in `console/store.py` and `docs/soc_command_center.md`. |

## Residual observations (not fixed here — deliberate)

1. **Default port set includes 513.** `start()` with no args binds 513/514/1514;
   UDP 513 is legacy who/rlogin territory, not syslog. The HTTP route only ever
   opens a single port (default 1514), so the web path is unaffected, and the
   loopback default bounds the exposure — but trimming `DEFAULT_PORTS` to
   `(514, 1514)` would be a one-line tightening. Behavior change → owner's call.
2. **`SO_REUSEADDR` on the UDP sockets.** UDP has no TIME_WAIT, so the flag buys
   nothing here — and on this platform it lets another local process bind the
   same port and split the stream. Loopback-only default keeps it local-attacker
   territory. Dropping the setsockopt is a one-liner; owner's call.
3. **`_store()` re-imports `store` and calls `init_db()` per datagram.** Both are
   idempotent, so this is a per-event perf nit, not an honesty gap.
4. Parse failures increment `errors` with `lastError` — visible, not silent. Fine.

## Recommendation

**KEEP the rewrite** with the two parse fixes landed on this branch. It preserves
the load-bearing honesty properties (source severity, loopback default, verbatim
raw, honest status/errors) and adds genuinely better observability. **HARDEN
selectively, at the owner's discretion:** (a) reinstate a TCP listener with RFC
6587 octet-counting/LF framing if relayed/reliable delivery still matters — this
is the one real capability regression left; (b) trim 513 from `DEFAULT_PORTS`;
(c) drop `SO_REUSEADDR`. None of (a)–(c) is forced here because each changes
behavior someone may rely on; all are small, reviewable diffs.
