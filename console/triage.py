#!/usr/bin/env python3
"""
triage.py — the ADVISORY second opinion, now LEARNED (card E7a).

HARD LINE (unchanged, and now enforced further down the stack): this module
NEVER writes `sev` / `ruleSev` / incident severity / priority / runbook
eligibility / any execution state. It returns an `aiTriage` object labelled
advisory. Rules (frozen detector + Sigma + syslog extras) own the verdict; the
analyst decides.

WHAT CHANGED IN E7a
-------------------
The deterministic pseudo-AI that used to keyword-match a finding's prose and
"recommend" a band is GONE. It was a plausible-looking constant, and a
plausible-looking constant is the exact thing this product refuses to ship.

In its place: `console/triage_model.py` scores a locally-trained classifier over
the ONE shared rule-owned feature vector. Two outcomes, both honest.

  * A model is loaded  -> an advisory severity opinion, a NUMERIC confidence,
    and an explicit agrees / disagrees status against the rule verdict.
    Disagreement is information for the human, never a gate.
  * No scikit-learn, no artifact, or a corrupt one -> the UNAVAILABLE state:
    `aiSeverity` is None, `confidence` is None, `agrees` is None, and the reason
    is named. Nothing is guessed. Every rule verdict, incident and case file is
    untouched by this either way.

The feature vector deliberately cannot see the rule verdict, so `agrees` is a
real second opinion rather than an echo. See triage_model.FEATURE_KEYS.
"""

from __future__ import annotations

import triage_model


def _rule_sev(finding):
    return str(finding.get("sev") or finding.get("ruleSev") or "INFO").upper()


_NEXT_STEPS = (
    "Read the verbatim evidence lines on this finding.",
    "The rule verdict is authoritative — do not replace it with this opinion.",
)
_DISAGREE_STEP = ("The learned model disagrees with the rule band. That is a "
                  "prompt to look, not a reason to change the verdict.")
_UNAVAILABLE_STEP = ("No learned opinion is available on this installation — "
                     "triage on the rule verdict and the evidence alone.")


def recommend(finding, org_criticality=None):
    """One advisory triage object. Does not mutate the finding.

    `org_criticality` is the configured asset criticality for this finding's
    host — a rule-owned org-context fact, and one of the model's features.
    """
    finding = finding or {}
    rule = _rule_sev(finding)
    record = dict(finding)
    if org_criticality:
        record["criticality"] = org_criticality
    out = triage_model.predict(record, rule)

    steps = list(_NEXT_STEPS)
    if out["modelAvailable"] and out["status"] == "disagrees":
        steps.append(_DISAGREE_STEP)
    elif not out["modelAvailable"]:
        steps.append(_UNAVAILABLE_STEP)
    out["nextSteps"] = steps
    return out


def attach(finding, org_criticality=None):
    """Return a shallow copy with aiTriage set; `sev` is copied unchanged."""
    f = dict(finding or {})
    sev = f.get("sev")
    rule_sev = f.get("ruleSev")
    f["aiTriage"] = recommend(f, org_criticality=org_criticality)
    f["sev"] = sev
    f["ruleSev"] = rule_sev
    return f


def model_status():
    """Availability of the learned model, for the API/UI. No invented numbers."""
    return triage_model.status()


def triage_state(state):
    """Advisory triage for every finding on the run. Never edits `sev`.

    `available` is the model's real state, and `unavailable` counts the findings
    that carry no learned opinion — so a caller can render "N findings, no
    learned opinion for any of them" rather than an empty-looking agreement.
    """
    findings = list((state or {}).get("findings") or [])
    items = []
    disagreements = 0
    unavailable = 0
    for f in findings:
        t = recommend(f)
        if t["modelAvailable"]:
            if not t["agrees"]:
                disagreements += 1
        else:
            unavailable += 1
        items.append({
            "id": f.get("id"),
            "title": f.get("title"),
            "ruleSeverity": t["ruleSeverity"],
            "aiSeverity": t["aiSeverity"],
            "aiLabel": t["aiLabel"],
            "confidence": t["confidence"],
            "agrees": t["agrees"],
            "status": t["status"],
            "advisory": True,
        })
    status = triage_model.status()
    return {
        "advisory": True,
        "learned": True,
        "modelAvailable": bool(status["available"]),
        "modelReason": status["reason"],
        "modelProvenance": status["provenance"],
        "count": len(items),
        "disagreements": disagreements,
        "unavailable": unavailable,
        "items": items,
        "note": (
            "Learned second opinion — ADVISORY. Rule verdicts are unchanged. "
            "aiSeverity is never copied onto sev, and no model output reaches "
            "severity, priority, runbook eligibility or execution."
        ),
    }
