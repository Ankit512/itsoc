#!/usr/bin/env python3
"""
enrich.py — attach Sigma gap-fill findings + advisory AI triage to console state.

Called after adapter.adapt() (and on run reload). Idempotent:

  * Previous `sigma-*` findings are replaced, not stacked.
  * `sev` / `ruleSev` on every finding is snapshotted and restored.
  * `aiTriage` is additive advisory metadata.

E7a: `aiTriage` is now the LEARNED second opinion (console/triage_model.py).
When no model is installed it is the honest "model unavailable" state — the
findings, their `sev` and everything downstream are byte-identical either way.

Does not import anomaly_detector.py.
"""

from __future__ import annotations

import org_context
import sigma_match
import triage


def enrich_console_state(state):
    if not state or state.get("idle"):
        return state
    original = list(state.get("findings") or [])
    kept = [f for f in original if not str(f.get("id") or "").startswith("sigma-")]
    sevs = {id(f): (f.get("sev"), f.get("ruleSev")) for f in kept}
    extra = sigma_match.findings_from_events(state.get("events") or [], gap_fill=True)
    findings = kept + extra
    # Configured asset criticality is a rule-owned org-context fact and one of
    # the model's features. Resolved here, once, so train and inference see the
    # same value for the same host (org_context.py is stdlib-only config).
    org = org_context.load_org_context()
    attached = []
    for f in findings:
        before = (f.get("sev"), f.get("ruleSev"))
        crit = org.get_criticality(f.get("host")) if f.get("hostDerived") else None
        f["aiTriage"] = triage.recommend(f, org_criticality=crit)
        # Restore in case anything ever tried to write through.
        if id(f) in sevs:
            f["sev"], f["ruleSev"] = sevs[id(f)]
        else:
            f["sev"], f["ruleSev"] = before
        attached.append(f)
    state["findings"] = attached
    state["sigmaHits"] = [
        {"id": f.get("type"), "title": f.get("title"), "level": f.get("sev"),
         "count": f.get("occurrences"), "note": "Sigma rule-owned match."}
        for f in extra
    ]
    return state
