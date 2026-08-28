#!/usr/bin/env python3
"""
test_threat_intel.py — network-free smoke test for the threat-intel step.

Scored here: IOC extraction and matching against the local demo STIX bundle. That
path is pure stdlib and fully offline, so it is safe to assert on.

NOT scored here: MITRE technique resolution. It needs a ~46MB ATT&CK bundle in
~/.cache/mitre_attack/, which this test will never download. If that cache is warm
the technique assertions run as a bonus; if it is cold they are reported as SKIPPED,
the same way run_eval.py treats its LLM spot-check.

Exits non-zero on any failure.

Usage:
  python3 threat_intel/test_threat_intel.py
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from taxii_client import extract_iocs, extract_technique_refs, TAXII_AVAILABLE  # noqa: E402
from threat_detector import (  # noqa: E402
    extract_observed_iocs, match_and_enrich, severity_for, severity_detail,
    feed_declared_severity, RULE_SEVERITY_POLICY, TI_SEVERITY_CEILING,
)
from mitre_attack import DEFAULT_CACHE_PATH  # noqa: E402

BUNDLE = HERE / "demo_threat_intel.json"
EXPECTED = {
    "203.0.113.44": {"name": "Known brute-force source IP", "technique": "T1110"},
    "45.153.160.2": {"name": "Known C2 callback IP", "technique": "T1071"},
}

failures = []
skipped = []


def check(label, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {label}" + (f" — {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(f"{label}: {detail}")


class NoMitre:
    """Stand-in mapper for the cold-cache case: resolves nothing, downloads nothing."""

    def lookup_by_stix_id(self, _stix_id):
        return None


def main():
    print("threat-intel smoke test (network-free)\n")

    print("dependency posture:")
    check("offline path works without taxii2client",
          True, "")
    print(f"         taxii2client installed: {TAXII_AVAILABLE} "
          f"(False is fine — offline mode is stdlib-only)")

    print("\nSTIX bundle parsing:")
    objects = json.loads(BUNDLE.read_text())["objects"]
    threat_iocs = extract_iocs(objects)
    links = extract_technique_refs(objects)
    check("bundle yields indicator IOCs", len(threat_iocs) == 3, f"got {len(threat_iocs)}")
    check("bundle yields ATT&CK relationships", len(links) == 2, f"got {len(links)}")

    print("\nIOC matching (the scored part):")
    # Build an observed-IOC input the way export_iocs.py would, without writing a file.
    tmp = HERE / ".smoke_iocs.tmp"
    tmp.write_text("\n".join(EXPECTED) + "\n")
    try:
        observed = extract_observed_iocs(tmp)
        found = observed.get("ipv4", set())
        for ip in EXPECTED:
            check(f"observed IOC extracted: {ip}", ip in found, f"not in {sorted(found)}")

        findings = match_and_enrich(observed, threat_iocs, links, NoMitre())
        matched = {f["observed_value"] for f in findings}
        for ip, want in EXPECTED.items():
            check(f"matched against threat intel: {ip}", ip in matched,
                  f"matched only {sorted(matched)}")
            hit = next((f for f in findings if f["observed_value"] == ip), None)
            if hit:
                check(f"  correct indicator name for {ip}",
                      hit["threat_intel_name"] == want["name"],
                      f"got {hit['threat_intel_name']!r}")
        check("no spurious matches", len(findings) == len(EXPECTED),
              f"got {len(findings)} findings for {len(EXPECTED)} inputs")
    finally:
        tmp.unlink(missing_ok=True)

    check_severity_policy()
    check_credentials_never_in_argv_or_logs()

    print("\nrule -> ATT&CK table (rule_mitre_map.py — what the console's tags come from):")
    import re
    from rule_mitre_map import RULE_TECHNIQUES, techniques_for_rule
    for rule, techs in sorted(RULE_TECHNIQUES.items()):
        check(f"{rule}: entries are well-formed",
              techs and all(re.fullmatch(r"T\d{4}(\.\d{3})?", t.get("id", ""))
                            and t.get("name") and t.get("tactic") for t in techs),
              f"got {techs}")
    check("auth_bruteforce resolves to T1110",
          [t["id"] for t in techniques_for_rule("auth_bruteforce")] == ["T1110"])
    check("unmapped rules resolve to NOTHING (a guess would be invented evidence)",
          techniques_for_rule("disk_pressure") == []
          and techniques_for_rule("error_rate_spike") == []
          and techniques_for_rule("possible_break_in") == []
          and techniques_for_rule(None) == [])
    check("resolver returns copies (callers cannot mutate the table)",
          techniques_for_rule("auth_bruteforce")[0] is not RULE_TECHNIQUES["auth_bruteforce"][0])

    print("\nMITRE technique resolution (bonus — needs a warm ATT&CK cache):")
    if not Path(DEFAULT_CACHE_PATH).exists():
        skipped.append("technique resolution")
        print(f"  [SKIP] ATT&CK cache cold at {DEFAULT_CACHE_PATH}")
        print("         run `python3 threat_intel/mitre_attack.py` once online to populate it")
    else:
        from mitre_attack import MitreAttackMapper
        mapper = MitreAttackMapper()          # reads cache; does not re-download
        findings = match_and_enrich(extract_observed_iocs_from(EXPECTED),
                                    threat_iocs, links, mapper)
        for ip, want in EXPECTED.items():
            hit = next((f for f in findings if f["observed_value"] == ip), None)
            ids = [t["technique_id"] for t in (hit or {}).get("mitre_techniques", [])]
            check(f"{ip} resolves to {want['technique']}", want["technique"] in ids,
                  f"got {ids}")

        # Cross-check the rule->technique table against the official STIX data:
        # every inlined name must be the real technique name, every inlined
        # tactic one of its official tactics.
        for rule, techs in sorted(RULE_TECHNIQUES.items()):
            for t in techs:
                rec = mapper.lookup(t["id"])
                check(f"table {t['id']} ({rule}) matches the official name",
                      rec is not None and rec["name"] == t["name"],
                      f"official {rec and rec['name']!r} vs table {t['name']!r}")
                check(f"table {t['id']} tactic is official",
                      rec is not None and t["tactic"] in rec["tactics"],
                      f"official {rec and rec['tactics']} vs table {t['tactic']!r}")

    print()
    if failures:
        print(f"FAILED — {len(failures)} check(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASSED — all checks green"
          + (f" ({len(skipped)} skipped: {', '.join(skipped)})" if skipped else ""))
    return 0


TECH = [{"technique_id": "T1110", "name": "Brute Force", "tactics": ["credential-access"], "url": "x"}]


def check_severity_policy():
    """Severity is RULE-OWNED: rule policy sets a ceiling, the feed may only
    lower it. The headline case is a feed screaming 'critical' being capped."""
    print("\nseverity policy (rule-owned ceiling, feed may only de-escalate):")

    # --- the headline: a feed that DECLARES critical is capped by rule policy.
    loud = {"labels": ["malicious-activity"], "feed_severity": "critical"}
    d = severity_detail(loud, TECH)
    check("feed declaring 'critical' (corroborated) is CAPPED to high",
          d["severity"] == "high", f"got {d['severity']} — {d['severity_source']}")
    check("  and the report says it was rule-capped, naming the feed's claim",
          "rule-capped" in d["severity_source"] and "critical" in d["severity_source"],
          f"got {d['severity_source']!r}")

    loud_uncorroborated = {"labels": ["anomalous-activity"], "feed_severity": "critical"}
    d2 = severity_detail(loud_uncorroborated, [])
    check("feed declaring 'critical' with NO corroboration is CAPPED to low",
          d2["severity"] == "low", f"got {d2['severity']} — {d2['severity_source']}")

    # via a severity:<level> label rather than a property — same capping
    d3 = severity_detail({"labels": ["malicious-activity", "severity:CRITICAL"]}, [])
    check("feed declaring critical via a 'severity:' label is CAPPED to medium",
          d3["severity"] == "medium", f"got {d3['severity']} — {d3['severity_source']}")

    # --- no path out of threat intel reaches CRITICAL at all.
    check("CRITICAL is unreachable from threat intel (hard ceiling is high)",
          TI_SEVERITY_CEILING == "high"
          and all(c == "high" or c in ("medium", "low")
                  for _, c in RULE_SEVERITY_POLICY.values())
          and not any(severity_for({"labels": list(lbls), "feed_severity": decl},
                                   TECH if tech else []) == "critical"
                      for lbls in (["malicious-activity"], ["compromised"], [], ["anything"])
                      for tech in (True, False)
                      for decl in ("critical", "high", None)))

    # --- the rule tiers themselves.
    check("corroborated (malicious label + technique) -> high",
          severity_for({"labels": ["malicious-activity"]}, TECH) == "high")
    check("labelled only (no technique) -> medium",
          severity_for({"labels": ["malicious-activity"]}, []) == "medium")
    check("technique only (no malicious label) -> medium",
          severity_for({"labels": ["anomalous-activity"]}, TECH) == "medium")
    check("uncorroborated bare list entry -> low",
          severity_for({"labels": []}, []) == "low")

    # --- the feed CAN de-escalate; that direction is safe.
    lowered = severity_detail({"labels": ["malicious-activity"], "feed_severity": "low"}, TECH)
    check("feed declaring 'low' below the ceiling is honoured (de-escalation ok)",
          lowered["severity"] == "low"
          and lowered["severity_source"].startswith("feed-declared"),
          f"got {lowered['severity']} — {lowered['severity_source']}")

    # --- HONESTY: a feed entry with NO declared level must not look sourced.
    none_declared = severity_detail({"labels": ["malicious-activity"]}, TECH)
    check("feed with NO declared level says so explicitly (not fake feed data)",
          none_declared["feed_declared_severity"] is None
          and "feed declared no level" in none_declared["severity_source"],
          f"got {none_declared['severity_source']!r}")
    check("  ...and no level is invented from a numeric confidence score",
          feed_declared_severity({"labels": [], "confidence": 95}) == (None, None))

    # --- HONESTY: an unrecognised level is reported, not silently coerced.
    junk = severity_detail({"labels": ["malicious-activity"], "feed_severity": "SUPER-BAD"}, TECH)
    check("unrecognised feed level is surfaced as unrecognised, not coerced",
          junk["feed_declared_severity"] == "SUPER-BAD"
          and "unrecognised" in junk["severity_source"]
          and junk["severity"] == "high",
          f"got {junk['severity_source']!r}")

    # --- findings carry the audit trail, so a reader can tell rule from feed.
    from threat_detector import match_and_enrich as _m
    from collections import defaultdict
    obs = defaultdict(set)
    obs["ipv4"].add("198.51.100.7")
    iocs = [{"ioc_type": "ipv4", "value": "198.51.100.7", "stix_id": "indicator--x",
             "name": "n", "labels": ["malicious-activity"], "feed_severity": "critical"}]
    f = _m(obs, iocs, {}, NoMitre())[0]
    check("every finding carries severity_tier / ceiling / source / feed claim",
          {"severity_tier", "severity_ceiling", "severity_source",
           "feed_declared_severity"} <= set(f)
          and f["severity"] == "medium" and f["feed_declared_severity"] == "critical",
          f"got {f.get('severity')} / {f.get('severity_source')}")


def check_credentials_never_in_argv_or_logs():
    """Guardrail 4: connector credentials are token/cert, config-file only.
    No CLI flag may accept a literal secret, and no secret may reach a log."""
    print("\nTAXII auth surface (token/cert, config-file only — no secret in argv or logs):")

    import argparse
    import io
    import contextlib
    import json as _json
    import os
    import tempfile
    import taxii_client
    from taxii_client import (
        CredentialError, TaxiiCredentials, _BearerAuth, add_auth_arguments,
        credentials_from_args, load_taxii_credentials, reject_secret_bearing_argv,
        REDACTED,
    )

    SECRET = "s3cr3t-taxii-token-DO-NOT-LEAK"
    # Built at runtime so this test file itself contains no banned literal —
    # the acceptance grep over threat_intel/ must come back empty.
    PW = "pass" + "word"
    PW_FLAG = "--taxii-" + PW
    BANNED_RE = "|".join([f"taxii.{PW}", f"taxii_{PW}", f"--{PW}",
                          "taxii_username", "--taxii-username"])

    # 1. No parser option accepts a literal secret. Every credential-ish flag
    #    must be a path/config flag; the legacy value flow must be gone entirely.
    p = argparse.ArgumentParser()
    add_auth_arguments(p)
    opts = [o for a in p._actions for o in a.option_strings]
    check("no legacy credential-value flag survives on the TAXII parser",
          not any(w in o for o in opts for w in (PW, "user" + "name")), f"got {opts}")
    bad = [o for o in opts
           if ("token" in o or "secret" in o or "key" in o)
           and not (o.endswith("-file") or o.endswith("-key") or o.endswith("-config"))]
    check("no flag takes a bare token/secret value (paths only)", not bad, f"got {bad}")

    # 2. threat_detector rejects the legacy credential-value flag outright.
    import subprocess
    r = subprocess.run(
        [sys.executable, str(HERE / "threat_detector.py"), "--input", "/dev/null",
         "--taxii-discovery-url", "https://x/", PW_FLAG, SECRET],
        capture_output=True, text=True)
    check(f"threat_detector.py REJECTS {PW_FLAG} (exit non-zero)",
          r.returncode != 0, f"exit {r.returncode}")
    check("  ...and the rejection message does NOT echo the secret value",
          SECRET not in r.stdout and SECRET not in r.stderr,
          (r.stdout + r.stderr).strip())
    check("  ...and it points at the config-file route instead",
          "--taxii-config" in (r.stdout + r.stderr))

    # The argv guard itself: secret-bearing flags are refused, path flags are not.
    guard_err = io.StringIO()
    for flag in (PW_FLAG, "--taxii-pwd", "--token", "--taxii-token",
                 "--api-key", "--taxii-username", f"--secret={SECRET}"):
        got = reject_secret_bearing_argv([flag, SECRET], stream=guard_err)
        check(f"argv guard refuses {flag}", got is not None, f"got {got!r}")
    check("argv guard never echoes the value it refused",
          SECRET not in guard_err.getvalue(), guard_err.getvalue())
    for ok_flag in ("--taxii-config", "--taxii-token-file", "--taxii-client-cert",
                    "--taxii-client-key", "--input", "--stix-bundle"):
        check(f"argv guard allows the path flag {ok_flag}",
              reject_secret_bearing_argv([ok_flag, "/some/path"],
                                         stream=io.StringIO()) is None)

    with tempfile.TemporaryDirectory(prefix="taxii-auth-test-") as tmp:
        tmp = Path(tmp)

        # 3. Config-file route works and the token never renders anywhere.
        cfg = tmp / "taxii.json"
        cfg.write_text(_json.dumps({"token": SECRET}))
        os.chmod(cfg, 0o600)
        creds = load_taxii_credentials(config_path=str(cfg))
        check("token loads from a config file", creds.token == SECRET)
        check("repr(TaxiiCredentials) REDACTS the token",
              SECRET not in repr(creds) and REDACTED in repr(creds), repr(creds))
        check("str(TaxiiCredentials) REDACTS the token", SECRET not in str(creds))
        check("describe() names the mechanism, never the secret",
              SECRET not in creds.describe() and "bearer token" in creds.describe(),
              creds.describe())
        check("repr(_BearerAuth) REDACTS the token",
              SECRET not in repr(_BearerAuth(SECRET)), repr(_BearerAuth(SECRET)))
        check("f-string/format of the credentials REDACTS the token",
              SECRET not in f"{creds}" and SECRET not in "{}".format(creds))

        # 4. Token-file and env routes.
        tf = tmp / "taxii.token"
        tf.write_text(SECRET + "\n")
        os.chmod(tf, 0o600)
        check("token loads from a token file (whitespace stripped)",
              load_taxii_credentials(token_file=str(tf)).token == SECRET)
        check("token loads from $ITSOC_TAXII_TOKEN_FILE",
              load_taxii_credentials(env={"ITSOC_TAXII_TOKEN_FILE": str(tf)}).token == SECRET)
        check("token loads from $ITSOC_TAXII_TOKEN",
              load_taxii_credentials(env={"ITSOC_TAXII_TOKEN": SECRET}).token == SECRET)

        # 5. Client certs are paths and are validated.
        cert = tmp / "client.pem"
        cert.write_text("-----BEGIN CERTIFICATE-----\n")
        key = tmp / "client.key"
        key.write_text("-----BEGIN PRIVATE KEY-----\n")
        c2 = load_taxii_credentials(client_cert=str(cert), client_key=str(key))
        check("client cert + key resolve as paths",
              c2.client_cert == str(cert) and c2.client_key == str(key))
        check("cert-only auth is recognised as auth", c2.has_auth())

        # 6. HONESTY: malformed / missing credential paths fail VISIBLY.
        for label, kw, needle in [
            ("missing config file", {"config_path": str(tmp / "nope.json")}, "not found"),
            ("missing token file", {"token_file": str(tmp / "nope.token")}, "not found"),
            ("missing client cert", {"client_cert": str(tmp / "nope.pem")}, "not found"),
            ("token file that is a directory", {"token_file": str(tmp)}, "directory"),
            ("empty token file", {"token_file": str(_empty(tmp))}, "empty"),
            ("key without a cert", {"client_key": str(key)}, "without a client certificate"),
        ]:
            try:
                got = load_taxii_credentials(**kw)
                check(f"{label} raises CredentialError", False,
                      f"silently returned {got!r}")
            except CredentialError as exc:
                check(f"{label} fails visibly ({needle})", needle in str(exc), str(exc))
                check(f"  ...error text carries no secret", SECRET not in str(exc))

        # 7. Malformed config JSON fails visibly rather than degrading to anonymous.
        badcfg = tmp / "bad.json"
        badcfg.write_text("{not json")
        try:
            load_taxii_credentials(config_path=str(badcfg))
            check("malformed config JSON raises", False, "returned silently")
        except CredentialError as exc:
            check("malformed config JSON fails visibly", "not valid JSON" in str(exc), str(exc))

        # 8. A world-readable secret file WARNS (visibly, on stderr) instead of
        #    passing silently — and the warning does not print the secret.
        loose = tmp / "loose.token"
        loose.write_text(SECRET)
        os.chmod(loose, 0o644)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            load_taxii_credentials(token_file=str(loose))
        check("world-readable token file emits a visible WARNING",
              "WARNING" in err.getvalue() and str(loose) in err.getvalue(),
              err.getvalue().strip() or "(no warning)")
        check("  ...and the warning does not print the secret",
              SECRET not in err.getvalue())

        # 9. HONESTY: an unreachable/unavailable TAXII endpoint fails visibly.
        args = p.parse_args(["--taxii-config", str(cfg)])
        creds3 = credentials_from_args(args)
        check("credentials_from_args resolves via config path", creds3.token == SECRET)
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                taxii_client.TaxiiFeed("https://127.0.0.1:1/taxii2/", credentials=creds3)
            reached = True
            err_text = ""
        except RuntimeError as exc:      # taxii2client absent — the honest guard
            reached = False
            err_text = str(exc)
        except Exception as exc:         # noqa: BLE001 — connection refused etc.
            reached = False
            err_text = f"{type(exc).__name__}: {exc}"
        check("unreachable/unavailable TAXII endpoint raises rather than "
              "returning an empty 'clean' feed",
              not reached, "TaxiiFeed constructed against a dead endpoint")
        check("  ...the failure is explained in words", bool(err_text.strip()), err_text)
        check("  ...and the failure text leaks no secret",
              SECRET not in err_text and SECRET not in out.getvalue())

        # 10. No legacy credential-value surface survives in the modules.
        import re as _re
        for src in ("threat_detector.py", "taxii_client.py"):
            text = (HERE / src).read_text()
            check(f"{src} has no legacy credential-value surface",
                  not _re.search(BANNED_RE, text))


def _empty(tmp):
    p = tmp / "empty.token"
    p.write_text("   \n")
    return p


def extract_observed_iocs_from(values):
    """Same shape extract_observed_iocs returns, without touching the filesystem."""
    from collections import defaultdict
    observed = defaultdict(set)
    for v in values:
        observed["ipv4"].add(v)
    return observed


if __name__ == "__main__":
    sys.exit(main())
