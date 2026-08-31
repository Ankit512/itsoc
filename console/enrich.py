#!/usr/bin/env python3
"""
enrich.py — attach Sigma gap-fill findings + advisory AI triage to console state.

Called after adapter.adapt() (and on run reload). Idempotent:

  * Previous `sigma-*` findings are replaced, not stacked.
  * `sev` / `ruleSev` on every finding is snapshotted and restored.
  * `aiTriage` is additive advisory metadata.

Does not import anomaly_detector.py.
"""

from __future__ import annotations

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
    attached = []
    for f in findings:
        before = (f.get("sev"), f.get("ruleSev"))
        f["aiTriage"] = triage.recommend(f)
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
