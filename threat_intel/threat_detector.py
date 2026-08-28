#!/usr/bin/env python3
"""
threat_detector.py — Phase 2: Threat intelligence matching + MITRE ATT&CK mapping

Ties together:
  - taxii_client.py   — pulls indicators (IPs, domains, hashes, URLs) from a
                         TAXII 2.x threat-intel feed, plus any attack-pattern
                         relationships attached to them
  - mitre_attack.py    — resolves ATT&CK technique IDs/STIX refs to
                         human-readable name/tactic/description
  - your log data       — IPs/domains/hashes seen in your own logs (e.g. the
                         output of anomaly_detector.py or log_analyzer.py, or
                         any plain log file)

What it does:
  1. Pulls current threat-intel indicators from a TAXII collection
  2. Extracts IOCs (IP/domain/hash/URL) you were actually seen talking to,
     from a log file or a plain IOC list
  3. Matches your observed IOCs against the threat-intel indicators
  4. For every match, resolves the associated MITRE ATT&CK technique
     (tactic + technique name) when the feed provides that relationship
  5. Writes a JSON + Markdown report ranking matches by severity

This is READ-ONLY — it does not block, isolate, or take any action. It's
built to sit downstream of anomaly_detector.py in a pipeline:

    anomaly_detector.py  --export-flagged flagged.log
    threat_detector.py   --input flagged.log --taxii-discovery-url ... 

Severity is RULE-OWNED. A threat feed is untrusted external input: it may
propose a level, and that proposal can only ever LOWER the severity a match
gets. See RULE_SEVERITY_POLICY below.

Usage (live TAXII server) — auth is token/cert, config-file only. No flag
accepts a literal secret; a token on the command line is visible in `ps`:
  python threat_detector.py \\
      --input suspicious_ips.log \\
      --taxii-discovery-url https://your-taxii-server/taxii2/ \\
      --taxii-collection-id COLLECTION_UUID \\
      --taxii-config /etc/itsoc/taxii.json \\
      --output threat_report

Usage (offline / demo mode — no TAXII server, use a local STIX bundle file):
  python threat_detector.py \\
      --input suspicious_ips.log \\
      --stix-bundle local_threat_intel.json \\
      --output threat_report
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from mitre_attack import MitreAttackMapper
from taxii_client import (
    CredentialError,
    TaxiiFeed,
    add_auth_arguments,
    credentials_from_args,
    extract_iocs,
    extract_technique_refs,
    reject_secret_bearing_argv,
)


# ---------------------------------------------------------------------------
# Extracting observed IOCs from your own log/IOC input file
# ---------------------------------------------------------------------------

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")


def extract_observed_iocs(path: Path):
    """Pull candidate IP/domain/hash values out of a plain-text log or IOC
    list. This is intentionally permissive — false positives here are cheap
    since they just won't match anything in the threat-intel set."""
    observed = defaultdict(set)
    with open(path, "r", errors="replace") as f:
        text = f.read()

    for ip in IP_RE.findall(text):
        observed["ipv4"].add(ip)
    for h in SHA256_RE.findall(text):
        observed["sha256"].add(h.lower())
    for h in MD5_RE.findall(text):
        # avoid double-counting substrings of sha256 matches
        if h.lower() not in observed["sha256"]:
            observed["md5"].add(h.lower())
    for d in DOMAIN_RE.findall(text):
        # filter out things that are actually IPs matched by the domain regex
        if not IP_RE.fullmatch(d):
            observed["domain"].add(d.lower())

    return observed


# ---------------------------------------------------------------------------
# Matching + enrichment
# ---------------------------------------------------------------------------

def match_and_enrich(observed_iocs, threat_iocs, technique_links, mitre_mapper):
    """Cross-reference observed IOCs against threat-intel IOCs. For each
    match, attach MITRE ATT&CK context if a relationship exists."""
    findings = []

    # index threat intel by (type, value) for O(1) lookup
    threat_index = defaultdict(list)
    for ioc in threat_iocs:
        threat_index[(ioc["ioc_type"], ioc["value"].lower())].append(ioc)

    for ioc_type, values in observed_iocs.items():
        for value in values:
            key = (ioc_type, value.lower())
            matches = threat_index.get(key)
            if not matches:
                continue
            for match in matches:
                techniques = []
                for attack_pattern_id in technique_links.get(match["stix_id"], []):
                    rec = mitre_mapper.lookup_by_stix_id(attack_pattern_id)
                    if rec:
                        techniques.append({
                            "technique_id": rec["technique_id"],
                            "name": rec["name"],
                            "tactics": rec["tactics"],
                            "url": rec["url"],
                        })

                finding = {
                    "observed_value": value,
                    "ioc_type": ioc_type,
                    "threat_intel_name": match.get("name", ""),
                    "threat_intel_labels": match.get("labels", []),
                    "threat_intel_stix_id": match["stix_id"],
                    "valid_from": match.get("valid_from"),
                    "mitre_techniques": techniques,
                }
                finding.update(severity_detail(match, techniques))
                findings.append(finding)

    findings.sort(key=lambda f: -SEVERITY_RANK.get(f["severity"], -1))
    return findings


# ---------------------------------------------------------------------------
# Severity — RULE-OWNED (CLAUDE.md §5, Stage-C guardrail 1)
# ---------------------------------------------------------------------------
#
# The old mapping flattened almost everything to CRITICAL and let the feed's
# own labels drive the console. A threat feed is untrusted external input: it
# must not be able to declare its way to CRITICAL.
#
# The mapping below is rule-owned in two parts:
#
#   1. RULE POLICY sets a CEILING from evidence *we* can corroborate locally —
#      whether the indicator carries a known-malicious label AND whether the
#      ATT&CK relationship in the bundle actually resolved to a technique.
#      Nothing the feed writes can raise that ceiling.
#   2. The FEED-DECLARED level is then applied only if it is strictly BELOW the
#      ceiling. In other words the feed may de-escalate, never escalate.
#
# CRITICAL is unreachable from threat intel alone (TI_SEVERITY_CEILING). A
# correlated IOC is an enrichment signal, not a verdict; CRITICAL stays with
# the rule engine in anomaly_detector.py, which owns verdicts.

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

#: Hard cap on anything threat intel can produce. Rules own CRITICAL.
TI_SEVERITY_CEILING = "high"

#: Labels that count as a known-malicious assertion (STIX 2.1 indicator_types
#: / STIX 2.0 labels). Rule-owned vocabulary, not read from the feed.
MALICIOUS_LABELS = frozenset({"malicious-activity", "compromised"})

#: (known-malicious label?, resolved ATT&CK technique?) -> (tier, ceiling)
RULE_SEVERITY_POLICY = {
    (True, True):   ("corroborated",   "high"),    # labelled AND technique-linked
    (True, False):  ("labelled_only",  "medium"),  # feed says bad, nothing corroborates it
    (False, True):  ("technique_only", "medium"),  # technique link, no malicious label
    (False, False): ("uncorroborated", "low"),     # a bare list entry
}

#: Level words we accept from a feed. Anything else is reported as
#: unrecognised rather than silently coerced.
_DECLARED_ALIASES = {
    "critical": "critical", "crit": "critical", "severe": "critical",
    "high": "high",
    "medium": "medium", "moderate": "medium", "med": "medium",
    "low": "low", "informational": "low", "info": "low",
}


def feed_declared_severity(threat_ioc):
    """The level the FEED claims, as (normalised, raw).

    Read from an explicit ``severity`` / ``x_severity`` property, or from a
    ``severity:<level>`` label. Returns (None, None) when the feed declares
    nothing — we do NOT infer one, and we do not read numeric confidence
    scores, because turning a 0-100 confidence into a severity word would be
    inventing data the feed never stated.

    (normalised, raw) with normalised=None but raw set means the feed declared
    something we do not recognise; callers surface that rather than ignore it.
    """
    raw = threat_ioc.get("feed_severity")
    if raw is None:
        for label in threat_ioc.get("labels") or []:
            text = str(label).strip().lower()
            if text.startswith("severity:"):
                raw = text.split(":", 1)[1].strip()
                break
    if raw is None:
        return None, None
    raw = str(raw).strip()
    if not raw:
        return None, None
    return _DECLARED_ALIASES.get(raw.lower()), raw


def severity_detail(threat_ioc, techniques):
    """Full, auditable severity decision for one threat-intel match.

    Returns the severity plus *why*: the rule tier, the ceiling that tier
    imposes, what the feed declared, and which of the two won. The report
    prints this so a reader can always tell a rule-policy assignment from a
    feed-supplied one — no severity ever looks more sourced than it is.
    """
    labels = {str(l).strip().lower() for l in (threat_ioc.get("labels") or [])}
    malicious = bool(labels & MALICIOUS_LABELS)
    tier, ceiling = RULE_SEVERITY_POLICY[(malicious, bool(techniques))]

    # Belt and braces: the policy table can never exceed the TI hard cap.
    if SEVERITY_RANK[ceiling] > SEVERITY_RANK[TI_SEVERITY_CEILING]:
        ceiling = TI_SEVERITY_CEILING

    declared, declared_raw = feed_declared_severity(threat_ioc)

    if declared_raw is None:
        severity = ceiling
        source = "rule-policy (feed declared no level)"
    elif declared is None:
        severity = ceiling
        source = (f"rule-policy (feed level {declared_raw!r} unrecognised, ignored)")
    elif SEVERITY_RANK[declared] < SEVERITY_RANK[ceiling]:
        severity = declared
        source = "feed-declared (below rule ceiling)"
    else:
        severity = ceiling
        source = f"rule-capped (feed declared {declared_raw!r})"

    return {
        "severity": severity,
        "severity_tier": tier,
        "severity_ceiling": ceiling,
        "feed_declared_severity": declared_raw,
        "severity_source": source,
    }


def severity_for(threat_ioc, techniques):
    """Rule-mapped severity for a threat-intel match: the feed-declared level
    capped by rule policy. Never returns 'critical' — see TI_SEVERITY_CEILING."""
    return severity_detail(threat_ioc, techniques)["severity"]


# ---------------------------------------------------------------------------
# Report writing
# ---------------------------------------------------------------------------

def write_reports(findings, output_prefix, stats):
    report = {
        "summary": stats,
        "total_matches": len(findings),
        "findings": findings,
    }
    json_path = f"{output_prefix}.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    md_lines = [
        "# Threat Intelligence Match Report", "",
        f"**Observed IOCs scanned:** {stats['observed_ioc_count']}  ",
        f"**Threat-intel indicators loaded:** {stats['threat_intel_count']}  ",
        f"**Matches found:** {len(findings)}", "",
    ]

    if not findings:
        md_lines.append("No matches against current threat intelligence.\n")
    else:
        counts = defaultdict(int)
        for f in findings:
            counts[f["severity"]] += 1
        md_lines.append(
            f"> Severity is rule-owned: rule policy sets a ceiling from locally "
            f"corroborated evidence and the feed's declared level applies only if it is "
            f"lower. Threat intel alone never reaches CRITICAL "
            f"(ceiling: {TI_SEVERITY_CEILING.upper()}).\n")
        md_lines.append("## Severity breakdown\n")
        for sev in ["critical", "high", "medium", "low"]:
            if counts.get(sev):
                md_lines.append(f"- **{sev.upper()}**: {counts[sev]}")
        md_lines.append("\n## Matches\n")

        for f in findings:
            md_lines.append(f"### [{f['severity'].upper()}] {f['observed_value']} ({f['ioc_type']})")
            md_lines.append(f"- **Matched threat-intel indicator:** {f['threat_intel_name'] or f['threat_intel_stix_id']}")
            md_lines.append(f"- **Labels:** {', '.join(f['threat_intel_labels']) or 'n/a'}")
            md_lines.append(
                f"- **Severity basis:** {f.get('severity_source', 'n/a')} — rule tier "
                f"`{f.get('severity_tier', 'n/a')}` (ceiling {f.get('severity_ceiling', 'n/a')}); "
                f"feed declared: {f.get('feed_declared_severity') or 'nothing'}")
            if f["mitre_techniques"]:
                for t in f["mitre_techniques"]:
                    tactics = ", ".join(t["tactics"]) or "n/a"
                    md_lines.append(f"- **MITRE ATT&CK:** {t['technique_id']} — {t['name']} (Tactic: {tactics})")
                    md_lines.append(f"  - {t['url']}")
            else:
                md_lines.append("- **MITRE ATT&CK:** no technique relationship provided by this feed")
            md_lines.append("")

    md_path = f"{output_prefix}.md"
    with open(md_path, "w") as f:
        f.write("\n".join(md_lines))

    return json_path, md_path


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def load_stix_objects_offline(bundle_path):
    with open(bundle_path, "r") as f:
        bundle = json.load(f)
    return bundle.get("objects", bundle) if isinstance(bundle, dict) else bundle


def run(args):
    observed_path = Path(args.input)
    if not observed_path.exists():
        print(f"ERROR: input file not found: {args.input}")
        sys.exit(1)

    print("Loading MITRE ATT&CK technique database...")
    mitre_mapper = MitreAttackMapper()
    print(f"  {mitre_mapper.technique_count()} techniques loaded.")

    print("Loading threat intelligence...")
    if args.stix_bundle:
        stix_objects = load_stix_objects_offline(args.stix_bundle)
        print(f"  Loaded {len(stix_objects)} STIX objects from local bundle {args.stix_bundle}")
    elif args.taxii_discovery_url:
        try:
            creds = credentials_from_args(args)
        except CredentialError as exc:
            # A bad cert/token path fails HERE, loudly, before any network call —
            # never by quietly downgrading to an anonymous pull.
            print(f"ERROR: TAXII credentials: {exc}")
            sys.exit(2)
        print(f"  TAXII auth: {creds.describe()}")
        if not creds.has_auth():
            print("  NOTE: no token or client certificate resolved — this pull is "
                  "anonymous. Supply --taxii-config / --taxii-token-file if the "
                  "server requires auth.")
        try:
            feed = TaxiiFeed(
                discovery_url=args.taxii_discovery_url,
                collection_id=args.taxii_collection_id,
                credentials=creds,
            )
            stix_objects = list(feed.pull_objects(added_after=args.added_after))
        except RuntimeError as exc:
            print(f"ERROR: {exc}")
            sys.exit(2)
        except Exception as exc:                       # noqa: BLE001 — surface it
            # Unreachable/refused/TLS-failed server: fail visibly with a non-zero
            # exit. We do NOT fall through to an empty report, which would look
            # like a clean "no threats found".
            print(f"ERROR: TAXII pull from {args.taxii_discovery_url} failed: "
                  f"{type(exc).__name__}: {exc}")
            print("       No report written — this is a feed failure, not a clean result.")
            sys.exit(3)
        print(f"  Pulled {len(stix_objects)} STIX objects from TAXII collection {args.taxii_collection_id}")
    else:
        print("ERROR: provide either --stix-bundle (offline) or --taxii-discovery-url + --taxii-collection-id (live)")
        sys.exit(1)

    threat_iocs = extract_iocs(stix_objects)
    technique_links = extract_technique_refs(stix_objects)
    print(f"  Extracted {len(threat_iocs)} indicator IOCs, {len(technique_links)} with ATT&CK links")

    print(f"Scanning {args.input} for observed IOCs...")
    observed = extract_observed_iocs(observed_path)
    observed_count = sum(len(v) for v in observed.values())
    print(f"  Found {observed_count} candidate IOCs in input "
          f"({', '.join(f'{k}:{len(v)}' for k, v in observed.items())})")

    findings = match_and_enrich(observed, threat_iocs, technique_links, mitre_mapper)

    stats = {
        "observed_ioc_count": observed_count,
        "threat_intel_count": len(threat_iocs),
    }
    json_path, md_path = write_reports(findings, args.output, stats)

    print(f"\n{len(findings)} match(es) found.")
    print(f"  JSON report: {json_path}")
    print(f"  Markdown report: {md_path}")


if __name__ == "__main__":
    # Before argparse sees argv: refuse any secret-bearing flag, and refuse it
    # WITHOUT echoing the value (argparse's own error would print it).
    if reject_secret_bearing_argv() is not None:
        sys.exit(2)

    parser = argparse.ArgumentParser(description="Threat intel matching + MITRE ATT&CK mapping")
    parser.add_argument("--input", required=True, help="Log file or IOC list to scan for observed indicators")
    parser.add_argument("--output", default="threat_report", help="Output file prefix")

    # Live TAXII mode
    parser.add_argument("--taxii-discovery-url", default=None)
    parser.add_argument("--taxii-collection-id", default=None)
    parser.add_argument("--added-after", default=None, help="Only pull indicators added after this ISO timestamp")
    # Auth: token/cert, config-file only. Every flag below takes a PATH.
    add_auth_arguments(parser)

    # Offline mode
    parser.add_argument("--stix-bundle", default=None, help="Path to a local STIX bundle JSON file (offline mode)")

    args = parser.parse_args()
    run(args)
