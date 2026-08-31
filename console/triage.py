#!/usr/bin/env python3
"""
triage.py — advisory AI severity recommendation.

HARD LINE: this module NEVER writes `sev` / `ruleSev` / incident severity.
It returns an `aiTriage` object labelled advisory. The analyst decides.
Rules (frozen detector + Sigma + syslog extras) own the verdict.

The recommendation is deterministic so tests and air-gapped runs do not
need a model. When a finding already carries `llmSev` from a compare run,
that value is used as the recommendation (still not copied onto `sev`).
"""

from __future__ import annotations

import re

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
_VALID = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

_CBS_RE = re.compile(r"\bCBS[_E]|HRESULT|windows_cbs|servicing", re.I)
_BRUTE_RE = re.compile(r"brute|failed.?password|auth_fail|T1110|spray", re.I)
_MALWARE_RE = re.compile(r"malware|ransomware|trojan|sigma_itsoc_edr", re.I)


def _rule_sev(finding):
    return str(finding.get("sev") or finding.get("ruleSev") or "INFO").upper()


def _occ(finding):
    try:
        n = int(finding.get("occurrences") or 1)
    except (TypeError, ValueError):
        n = 1
    return n if n > 0 else 1


def _bump(sev, steps=1):
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    s = sev if sev in order else "INFO"
    return order[min(len(order) - 1, order.index(s) + steps)]


def _drop(sev, steps=1):
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    s = sev if sev in order else "INFO"
    return order[max(0, order.index(s) - steps)]


def recommend(finding, org_criticality=None):
    """One advisory triage object. Does not mutate the finding."""
    finding = finding or {}
    rule = _rule_sev(finding)
    if rule not in _VALID:
        rule_out = rule if rule else "INFO"
    else:
        rule_out = rule
    rec = rule_out if rule_out in _VALID else "INFO"
    cause = str(finding.get("ruleWhy") or finding.get("title") or "").strip()
    fp = ""
    next_steps = [
        "Read the verbatim evidence lines on this finding.",
        "The rule verdict is authoritative — do not replace it with this recommendation.",
    ]
    title = str(finding.get("title") or "")
    ftype = str(finding.get("type") or "")
    blob = f"{title} {ftype} {cause}"
    occ = _occ(finding)

    llm = finding.get("llmSev")
    llm_s = str(llm).upper() if llm else ""

    if _CBS_RE.search(blob):
        rec = rule_out if rule_out in _VALID else "HIGH"
        fp = "Windows servicing / CBS HRESULT — typically not an intrusion by itself."
        cause = cause or "CBS/CSI servicing noise; rule severity stands."
        next_steps.append("Confirm this is Component-Based Servicing, not credential abuse.")
    elif _MALWARE_RE.search(blob):
        rec = "CRITICAL" if rec in ("HIGH", "MEDIUM", "LOW", "INFO") else rec
        cause = cause or "EDR/malware signature matched — AI would treat as CRITICAL."
        next_steps.append("Isolate the host only after an analyst confirms the EDR event.")
    elif _BRUTE_RE.search(blob):
        if occ >= 20 and _SEV_RANK.get(rec, 9) > 0:
            rec = _bump(rec, 1)
            cause = (
                f"{occ} matching auth-failure lines. Rule verdict is {rule_out}; "
                f"AI would recommend {rec}."
            )
        else:
            cause = cause or f"Auth-failure cluster ({occ} line(s)). Rule verdict stands."
        next_steps.append("Check for a later auth success from the same source.")
    elif org_criticality in ("crown-jewel", "critical", "high") and rec in ("MEDIUM", "LOW"):
        rec = _bump(rec, 1)
        cause = (
            f"Asset criticality {org_criticality}: AI would raise the "
            f"recommendation from {rule_out} to {rec}. Verdict unchanged."
        )

    if llm_s in _VALID:
        rec = llm_s
        cause = (finding.get("llmWhy") or cause
                 or "Compare-run model rating reused as the advisory recommendation.")

    agrees = rec == rule_out
    note = (
        "AI recommends — analyst decides. This does not change the rule verdict "
        f"({rule_out})."
    )
    return {
        "advisory": True,
        "ruleSeverity": rule_out,
        "aiSeverity": rec,
        "confidence": "medium" if not agrees else "high",
        "agrees": agrees,
        "cause": cause[:400],
        "stage": "",
        "falsePositiveHint": fp,
        "priority": rec,
        "nextSteps": next_steps[:6],
        "note": note,
    }


def attach(finding, org_criticality=None):
    """Return a shallow copy with aiTriage set; `sev` is copied unchanged."""
    f = dict(finding or {})
    sev = f.get("sev")
    f["aiTriage"] = recommend(f, org_criticality=org_criticality)
    f["sev"] = sev
    return f


def triage_state(state):
    """Advisory triage for every finding on the run. Never edits `sev`."""
    findings = list((state or {}).get("findings") or [])
    items = []
    disagreements = 0
    for f in findings:
        t = recommend(f)
        if t["ruleSeverity"] != (f.get("sev") or f.get("ruleSev")):
            # Finding sev is source of truth; recommend() already used it.
            pass
        if not t["agrees"]:
            disagreements += 1
        items.append({
            "id": f.get("id"),
            "title": f.get("title"),
            "ruleSeverity": t["ruleSeverity"],
            "aiSeverity": t["aiSeverity"],
            "agrees": t["agrees"],
            "advisory": True,
        })
    return {
        "advisory": True,
        "count": len(items),
        "disagreements": disagreements,
        "items": items,
        "note": (
            "AI recommends — analyst decides. Rule verdicts are unchanged. "
            "aiSeverity is never copied onto sev."
        ),
    }
