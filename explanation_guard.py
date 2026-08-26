#!/usr/bin/env python3
"""
explanation_guard.py — deterministic consistency guard for LLM explanations.

The non-negotiable principle: rules own verdicts; the LLM only explains. An
advisory explanation that hallucinates a host, IP, username, or rule fault-type
that does not match the deterministic finding erodes trust in the rule verdict.

This module is a FAST, DETERMINISTIC, OFFLINE check run before any model-
authored prose is shown to a user. It verifies three invariants:
  (a) grounding — every IP, quoted username, and host-like identifier named in
      the explanation must exist in the finding's deterministic evidence,
      entities, or title;
  (b) fault-type consistency — prose for one rule cannot read as an explanation
      of a different, incompatible rule (e.g. brute-force prose for a disk
      finding);
  (c) counts — best-effort: a number the prose attaches to a count noun
      ("7 failures", "12 attempts", "97%") must appear in the finding.

On failure the CALLER withholds the prose and shows UNVERIFIED_NOTE instead,
keeping every deterministic field intact. The guard never rewrites, trims, or
replaces an explanation — a fabricated substitute would violate the same rule
this module exists to enforce.

Accepts both finding shapes: the analyzer/report dict (rule_id, entities,
evidence, ...) and the console/adapter dict (type, host, chips, lines, ...).
Model-authored fields are excluded from the grounding corpus, so one piece of
prose can never vouch for another. stdlib only; anomaly_detector.py untouched.
"""

import re

# What the caller shows in place of withheld prose. Deliberately honest about
# being an absence, not an answer.
UNVERIFIED_NOTE = "unverified — possible mismatch, sent for review"

# Fields that carry model (or reviewer-facing model) prose. Never usable as
# grounding: an unchecked explanation must not certify the one being checked.
_MODEL_PROSE_KEYS = frozenset({
    "recommended_action", "explanation", "llmWhy", "llm_alone_why",
    "chunk_summary", "explanationGuardReasons", "explanation_guard_reasons",
})

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
# 'admin', "root" — the way both the canonical vocabulary and model prose quote
# a username. Curly quotes included because models emit them.
_QUOTED_RE = re.compile(r"[\'\"‘’“”]([A-Za-z0-9._$-]{1,64})"
                        r"[\'\"‘’“”]")
# server-01, db2.example.com — an identifier-shaped token. Requiring a digit or
# a dot keeps hyphenated English ("brute-force", "break-in") out of scope.
_HOSTLIKE_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:[-.][A-Za-z0-9]+)+\b")
# "7 failures", "12x", "5 attempts", "97%" — a number the prose presents as a
# measured quantity. Bare numbers (ports, years, RFC numbers) are not claims.
_COUNT_CLAIM_RE = re.compile(
    r"\b(\d+)\s*(?:%|x\b|times\b|failures?\b|failed\b|attempts?\b|events?\b|"
    r"occurrences?\b|logins?\b|lines?\b|errors?\b|percent\b)", re.IGNORECASE)

# Hyph/dotted tokens that pass the host shape but are prose, not identifiers.
_HOST_STOPLIST = frozenset({
    "rfc-3164", "rfc3164", "log4j", "http2", "ipv4", "ipv6", "sha-256", "md5",
    "utf-8", "x86-64", "top-10", "24x7",
})

# Rule vocabulary, mirrored from rule_context.predicate_for and the rules_syslog
# phrasings (CANON_FAIL/CANON_OK, BREAK_IN, detect_break_in_attempts rationale).
# `own` is anything that legitimately appears in prose about that rule;
# `distinctive` is vocabulary that points at THIS rule and (nearly) no other.
_RULE_VOCAB = {
    "auth_bruteforce": {
        "own": ("auth", "password", "login", "log in", "credential", "brute",
                "failure", "failed", "attempt", "ssh", "account"),
        "distinctive": ("brute", "password", "credential", "login"),
    },
    "auth_bruteforce_success": {
        "own": ("auth", "password", "login", "log in", "credential", "brute",
                "failure", "failed", "attempt", "ssh", "account", "success",
                "compromise", "accepted"),
        "distinctive": ("brute", "password", "credential", "compromise"),
    },
    "possible_break_in": {
        "own": ("reverse", "dns", "resolve", "break-in", "hostname", "ssh",
                "scan", "probe"),
        "distinctive": ("reverse", "dns", "break-in"),
    },
    "suspicious_outbound": {
        "own": ("outbound", "port", "connection", "egress", "traffic",
                "firewall", "blocked", "destination", "c2",
                "command-and-control", "irc", "tor", "metasploit"),
        "distinctive": ("outbound", "egress"),
    },
    "critical_service_event": {
        "own": ("service", "database", "pool", "exhaust", "down", "crash",
                "critical", "unavailable", "outage"),
        "distinctive": ("exhaust", "outage", "pool"),
    },
    "disk_pressure": {
        "own": ("disk", "storage", "capacity", "space", "full", "filesystem",
                "volume", "%"),
        "distinctive": ("disk", "storage", "filesystem"),
    },
    "error_rate_spike": {
        "own": ("error", "burst", "spike", "rate", "elevated", "window"),
        "distinctive": ("burst", "spike"),
    },
}


def _corpus(finding):
    """Every deterministic string/number in the finding, flattened to one text.

    Walks both finding shapes without knowing either schema; skipping the
    model-prose keys is the only shape knowledge it has.
    """
    parts = []

    def walk(value):
        if isinstance(value, dict):
            for key, sub in value.items():
                if key in _MODEL_PROSE_KEYS:
                    continue
                parts.append(str(key))
                walk(sub)
        elif isinstance(value, (list, tuple)):
            for sub in value:
                walk(sub)
        elif value is not None and not isinstance(value, bool):
            parts.append(str(value))

    walk(finding)
    return "\n".join(parts)


def _check_grounding(text, corpus, reasons):
    corpus_lower = corpus.lower()
    known_ips = set(_IP_RE.findall(corpus))

    for ip in sorted(set(_IP_RE.findall(text))):
        if ip not in known_ips:
            reasons.append(f"names IP {ip}, which is not in this finding's "
                           f"entities or evidence")

    for name in sorted({m.group(1) for m in _QUOTED_RE.finditer(text)}):
        if name.isdigit():
            continue
        if name.lower() not in corpus_lower:
            reasons.append(f"names '{name}', which is not in this finding's "
                           f"entities or evidence")

    for token in sorted({m.group(0) for m in _HOSTLIKE_RE.finditer(text)}):
        low = token.lower()
        if low in _HOST_STOPLIST or _IP_RE.fullmatch(token):
            continue
        if not any(c.isdigit() for c in token) and "." not in token:
            continue  # hyphenated English, not an identifier
        if low not in corpus_lower:
            reasons.append(f"names host-like '{token}', which is not in this "
                           f"finding's entities or evidence")


def _check_fault_type(text, rule_id, reasons):
    vocab = _RULE_VOCAB.get(rule_id)
    if not vocab:
        return  # unknown rule (e.g. LLM-surfaced finding): nothing to assert
    low = text.lower()
    if any(kw in low for kw in vocab["own"]):
        return  # the prose touches its own rule's vocabulary — consistent
    for other, other_vocab in _RULE_VOCAB.items():
        if other == rule_id:
            continue
        hit = next((kw for kw in other_vocab["distinctive"] if kw in low), None)
        if hit:
            reasons.append(f"prose reads as {other} ('{hit}') but the rule "
                           f"that fired is {rule_id}")
            return


def _check_counts(text, corpus, reasons):
    known_numbers = set(re.findall(r"\d+", corpus))
    for match in _COUNT_CLAIM_RE.finditer(text):
        if match.group(1) not in known_numbers:
            claim = " ".join(match.group(0).split())
            reasons.append(f"count \"{claim}\" does not match any number in "
                           f"this finding")


def verify_explanation(finding, explanation_text):
    """Deterministically check one explanation against its finding.

    Returns {"ok": bool, "reasons": [str]} — reasons empty when ok. Empty or
    non-string prose passes vacuously: there is nothing to mis-state, and the
    "no explanation" placeholders must keep rendering.
    """
    if not explanation_text or not isinstance(explanation_text, str):
        return {"ok": True, "reasons": []}
    if not isinstance(finding, dict):
        return {"ok": False, "reasons": ["no finding to verify against"]}

    corpus = _corpus(finding)
    rule_id = finding.get("rule_id") or finding.get("type")
    reasons = []
    _check_grounding(explanation_text, corpus, reasons)
    _check_fault_type(explanation_text, rule_id, reasons)
    _check_counts(explanation_text, corpus, reasons)
    return {"ok": not reasons, "reasons": reasons}
