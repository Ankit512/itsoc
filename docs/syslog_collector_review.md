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

## Hardening follow-up (2026-08-26)

Implemented and covered by collector tests:

1. `DEFAULT_PORTS` is now `(514, 1514)`. Port 513 is legacy who/rlogin, not a
   syslog default. Explicit caller-supplied ports remain supported.
2. UDP listeners no longer set `SO_REUSEADDR`. UDP has no TIME_WAIT, and allowing
   a second local process to share an endpoint can split the event stream.
3. The store module is cached and `init_db()` runs once during each collector
   start, before sockets accept traffic, rather than once per datagram. A failed
   initialization is reported honestly and prevents a listener from claiming it
   is running while persistence is unavailable.

TCP remains deliberately deferred. Adding it safely is not just another socket:
the collector currently keys listeners by port, and the API/UI/status contract
advertises UDP-only protocol fields. A compatible implementation needs listeners
keyed by `(protocol, port)`, bounded connection lifecycle, and RFC 6587 tests for
octet-counted frames split across reads, multiple frames in one read, LF-delimited
non-transparent framing, malformed/oversized length prefixes, disconnects with a
partial frame, stop/restart with active clients, and simultaneous UDP+TCP on the
same numeric port. Until those contracts exist, claiming TCP support would risk
silent truncation or message coalescing and would violate source honesty.

## Recommendation

**KEEP the rewrite** with the parse fixes and safe hardening above. It preserves
the load-bearing honesty properties (source severity, loopback default, verbatim
raw, honest status/errors) and adds genuinely better observability. **HARDEN
selectively:** reinstate TCP with RFC 6587 framing if relayed/reliable delivery
still matters, using the compatibility matrix above. This remains the one real
capability regression.
