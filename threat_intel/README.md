# Threat-intel enrichment (offline-first)

A **downstream, opt-in** step that takes the analyzer's flagged IPs, matches them
against threat-intel indicators, and resolves each match to a MITRE ATT&CK
technique. It turns *"outbound connection to 45.153.160.2:4444 blocked"* into
*"T1071 Application Layer Protocol — Command and Control, known C2 IP."*

This is an optional enrichment surface used by the SOC workspace and command-line
tools. It remains downstream of detection: `log_analyzer.py` and
`anomaly_detector.py` stay read-only and local, and threat-intel data can never
raise a rule verdict. Offline mode is the default and needs only Python's standard
library.

## The demo, end to end

Run from the repo root. Offline — no TAXII server, no `taxii2client`:

```bash
python3 log_analyzer.py --input sample-2.log --output demo_report
python3 threat_intel/export_iocs.py demo_report.json > demo_iocs.txt
python3 threat_intel/threat_detector.py --input demo_iocs.txt \
    --stix-bundle threat_intel/demo_threat_intel.json --output demo_threat_report
```

Expected result — 2 matches, both HIGH:

| Observed IOC | Matched indicator | Severity | MITRE ATT&CK |
|---|---|---|---|
| `203.0.113.44` | Known brute-force source IP | HIGH | **T1110** — Brute Force (Credential Access) |
| `45.153.160.2` | Known C2 callback IP | HIGH | **T1071** — Application Layer Protocol (Command and Control) |

(With a cold ATT&CK cache no technique resolves, so both drop to MEDIUM — the
`labelled_only` tier. That is the mapping working, not a bug.)

## Severity is rule-owned

A threat feed is untrusted external input. It must not be able to declare its
way to CRITICAL and thereby drive the console, so `severity_for()` maps in two
steps:

1. **Rule policy sets a ceiling** from evidence this repo can corroborate
   locally — whether the indicator carries a known-malicious label, and whether
   its ATT&CK relationship actually resolved to a technique:

   | Known-malicious label | ATT&CK technique resolved | Tier | Ceiling |
   |---|---|---|---|
   | yes | yes | `corroborated` | **high** |
   | yes | no | `labelled_only` | **medium** |
   | no | yes | `technique_only` | **medium** |
   | no | no | `uncorroborated` | **low** |

2. **The feed-declared level applies only if it is strictly lower.** The feed
   may de-escalate; it can never escalate. A feed shouting `"severity":
   "critical"` on an uncorroborated list entry still comes out **low**.

`TI_SEVERITY_CEILING` is `high`: **CRITICAL is unreachable from threat intel
alone.** A correlated IOC is an enrichment signal, not a verdict — CRITICAL
belongs to the rule engine in `anomaly_detector.py`, which owns verdicts
(CLAUDE.md §3/§5).

Every finding carries its own audit trail — `severity_tier`,
`severity_ceiling`, `feed_declared_severity`, `severity_source` — and the
Markdown report prints it, so a rule-policy assignment can never be mistaken
for a feed-sourced one. A feed that declares nothing is labelled
*"feed declared no level"* rather than quietly defaulting; a level word we do
not recognise is reported as unrecognised rather than coerced.

The first run downloads MITRE's ATT&CK bundle (~46 MB) to
`~/.cache/mitre_attack/`. Every later run is offline. Nothing refreshes that cache
automatically — re-run `python3 threat_intel/mitre_attack.py --refresh` when you
want current technique data.

Demo outputs (`demo_report.*`, `demo_iocs.txt`, `demo_threat_report.*`) are
gitignored; the commands above regenerate them.

## Smoke test

```bash
python3 threat_intel/test_threat_intel.py    # non-zero exit on failure
```

Network-free. It asserts IOC extraction and matching against the local demo
bundle. Technique resolution is a **bonus** check: with a warm ATT&CK cache it
verifies T1110/T1071; with a cold cache it reports `[SKIP]` and still passes,
rather than downloading 46 MB inside a test.

## Files

| File | Role |
|---|---|
| `export_iocs.py` | Reads the analyzer's `report.json` and emits a clean IOC list from each finding's `entities`. **Stdlib.** |
| `threat_detector.py` | Matches observed IOCs against threat intel, resolves ATT&CK, writes JSON + Markdown. |
| `taxii_client.py` | Live TAXII 2.x pull **plus** the stdlib STIX helpers (`extract_iocs`, `extract_technique_refs`) that offline mode uses. |
| `mitre_attack.py` | Downloads/caches MITRE ATT&CK and resolves technique IDs. **Stdlib** (`urllib`). |
| `demo_threat_intel.json` | Tiny local STIX bundle: 3 indicators, 2 ATT&CK relationships. |
| `test_threat_intel.py` | Network-free smoke test. |
| `requirements-taxii.txt` | **Live TAXII only.** Not needed offline. |

## Why an exporter instead of `--export-flagged`

`threat_detector.py`'s docstring describes a pipeline built on
`anomaly_detector.py --export-flagged`. That flag never existed in our validated
detector — it belonged to a rejected prototype. `export_iocs.py` replaces it from
the other end, reading the `entities` the analyzer already records, so the
validated detector needs no changes.

It reads entity keys in the order `ip → dest_ip → host`, matching `entity_of()` in
`tests/eval/run_eval.py`. Keep the two in step if either changes.

Exporting from `entities` rather than grepping the raw log matters: the IOC regexes
in `threat_detector.py` are deliberately permissive, so scanning a whole log
harvests every IP that appears anywhere. Only rule-flagged principals get exported
here.

`--ips-only` omits internal hostnames (a `critical_service_event` on `server-03`
exports `server-03`, which is your own asset name, not an indicator). Use it before
sending anything to a live or third-party feed.

## Live TAXII mode (not enabled)

Authentication is **token/cert, config-file only** (Stage-C guardrail 4). No
flag anywhere accepts a literal secret: anything on the command line is visible
to every user on the box via `ps`, and would land in shell history and CI logs.
Passing a secret-bearing flag is refused before argparse sees it, and the
refusal does not echo the value back.

```bash
pip install -r threat_intel/requirements-taxii.txt

# 1. Put the credential in a file, readable only by you.
cat > /etc/itsoc/taxii.json <<'JSON'
{ "token": "…", "client_cert": "/etc/itsoc/client.pem",
  "client_key": "/etc/itsoc/client.key", "verify_ssl": true }
JSON
chmod 600 /etc/itsoc/taxii.json

# 2. Point the run at the file, never at the secret.
python3 threat_intel/threat_detector.py --input demo_iocs.txt \
    --taxii-discovery-url https://your-taxii-server/taxii2/ \
    --taxii-collection-id COLLECTION_UUID \
    --taxii-config /etc/itsoc/taxii.json \
    --output threat_report
```

Equivalent routes, in precedence order:

| Route | How |
|---|---|
| token file | `--taxii-token-file /etc/itsoc/taxii.token` |
| config file | `--taxii-config /etc/itsoc/taxii.json` (`token` or `token_file`) |
| environment | `ITSOC_TAXII_TOKEN_FILE=/path` or `ITSOC_TAXII_TOKEN=…` |
| mutual TLS | `--taxii-client-cert PATH` `--taxii-client-key PATH` |

A group/world-readable credential file gets a visible `WARNING` on stderr. A
missing, empty, unreadable or malformed config/token/cert path is a hard error
with a non-zero exit — it never degrades quietly to an anonymous pull. An
unreachable or refusing TAXII server exits non-zero and writes **no** report,
because an empty report would read as a clean "no threats found". The token is
redacted in every string form of `TaxiiCredentials` and of the auth object, so
it cannot reach a log or a traceback.

Untested here, and a deliberate decision rather than a default: **live mode sends
your observed IOCs to a third party.** The project's constraint is that log data
stays local, so offline `--stix-bundle` is the supported path. Without
`taxii2client` installed, `TaxiiFeed` raises a clear install hint and the offline
path is unaffected.

## Known follow-ups (not addressed)

- **Live TAXII is still unwired and unexercised.** The auth surface is now
  token/cert config-file only and is unit-tested, but no real TAXII server has
  been contacted from this repo. Offline `--stix-bundle` remains the supported
  path.
- **Rule policy is coarse.** Four tiers keyed on label + technique. It ranks
  correctly and caps the feed, but it does not yet use indicator age,
  `valid_until`, or feed reputation.
- **`DOMAIN_RE` is permissive.** Feeding a raw log rather than an exported IOC list
  will extract noisy pseudo-domains. Another reason to use `export_iocs.py`.
- **ATT&CK cache never auto-refreshes**, and `offline=True` raises on a cold cache.
