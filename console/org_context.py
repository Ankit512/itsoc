#!/usr/bin/env python3
"""
org_context.py — Organizational Context & Asset Criticality for itsoc.

Rule-owned, deterministic priority calculation based on asset business value.
Rules own severity, correlation, priority, and eligibility (Standing Guardrail 1).
Priority is an independent axis from severity:
  - Severity: Technical impact and confidence derived by detection rules.
  - Criticality: Asset business value configured by the organization (crown-jewel | standard | low).
  - Priority: Operational urgency (P1..P4) derived deterministically from (severity, criticality).

CRITICAL INVARIANT:
Priority calculation NEVER mutates severity. Severity remains byte-identical.
The LLM has NO input path to priority (no LLM/advisory parameters exist in the signature).
"""

import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOC_DIR = HERE / ".soc"
DEFAULT_SEED_FILE = HERE / "org_context.json"
STORE_CONFIG_FILE = SOC_DIR / "org_context.json"

CRITICALITY_LEVELS = ("crown-jewel", "standard", "low")
DEFAULT_CRITICALITY = "standard"

CRITICALITY_WEIGHTS = {
    "crown-jewel": 2.0,
    "standard": 1.0,
    "low": 0.5,
}

PRIORITY_RANKS = {
    "P1": 1,
    "P2": 2,
    "P3": 3,
    "P4": 4,
}

# (Severity, Criticality) -> Priority
PRIORITY_MATRIX = {
    ("CRITICAL", "crown-jewel"): "P1",
    ("CRITICAL", "standard"): "P1",
    ("CRITICAL", "low"): "P2",

    ("HIGH", "crown-jewel"): "P1",      # Crown-jewel elevates HIGH to P1
    ("HIGH", "standard"): "P2",
    ("HIGH", "low"): "P3",

    ("MEDIUM", "crown-jewel"): "P2",    # Crown-jewel elevates MEDIUM to P2
    ("MEDIUM", "standard"): "P3",
    ("MEDIUM", "low"): "P4",

    ("LOW", "crown-jewel"): "P3",       # Crown-jewel elevates LOW to P3
    ("LOW", "standard"): "P4",
    ("LOW", "low"): "P4",

    ("INFO", "crown-jewel"): "P4",
    ("INFO", "standard"): "P4",
    ("INFO", "low"): "P4",
}

DEFAULT_SEED = {
    "version": 1,
    "defaultCriticality": "standard",
    "assets": {
        "server-01": {
            "criticality": "crown-jewel",
            "owner": "infrastructure-core",
            "description": "Primary application host and authentication target"
        }
    }
}


class OrgContext:
    """Loaded organization context holding asset criticality and governance metadata."""

    def __init__(self, assets=None, source="default", note=None, valid=True, default_criticality=DEFAULT_CRITICALITY):
        self.assets = assets or {}
        self.source = source
        self.note = note
        self.valid = valid
        self.default_criticality = default_criticality if default_criticality in CRITICALITY_LEVELS else DEFAULT_CRITICALITY

    def get_criticality(self, asset_name):
        """Look up asset criticality. Untagged assets return 'standard', never guessed from name."""
        if not asset_name:
            return self.default_criticality
        entry = self.assets.get(str(asset_name).strip())
        if isinstance(entry, dict):
            crit = entry.get("criticality")
        elif isinstance(entry, str):
            crit = entry
        else:
            crit = None
        if crit in CRITICALITY_LEVELS:
            return crit
        return self.default_criticality

    def get_asset_context(self, asset_name):
        """Full metadata dict for an asset."""
        name = str(asset_name).strip() if asset_name else ""
        entry = self.assets.get(name)
        if isinstance(entry, dict):
            return {
                "name": name,
                "criticality": self.get_criticality(name),
                "owner": entry.get("owner"),
                "description": entry.get("description"),
                "tagged": True,
            }
        elif isinstance(entry, str) and entry in CRITICALITY_LEVELS:
            return {
                "name": name,
                "criticality": entry,
                "owner": None,
                "description": None,
                "tagged": True,
            }
        return {
            "name": name,
            "criticality": self.default_criticality,
            "owner": None,
            "description": None,
            "tagged": False,
        }

    def to_dict(self):
        """Serialize for API presentation."""
        return {
            "version": 1,
            "source": self.source,
            "valid": self.valid,
            "note": self.note,
            "defaultCriticality": self.default_criticality,
            "assets": self.assets,
        }


def _resolve_context_file(explicit_path=None):
    if explicit_path:
        return Path(explicit_path)
    if STORE_CONFIG_FILE.exists():
        return STORE_CONFIG_FILE
    if DEFAULT_SEED_FILE.exists():
        return DEFAULT_SEED_FILE
    return None


def load_org_context(path=None):
    """Load organizational context with honest degradation on missing or malformed configuration.
    
    Returns an OrgContext instance with a visible note if degraded.
    """
    target = _resolve_context_file(path)
    if not target or not target.exists():
        return OrgContext(
            assets=DEFAULT_SEED["assets"].copy(),
            source="default-seed",
            note="org_context.json not found — using default seed (server-01: crown-jewel, others: standard)",
            valid=True,
            default_criticality=DEFAULT_CRITICALITY,
        )

    try:
        raw = target.read_text(encoding="utf-8")
        data = json.loads(raw)
    except Exception as exc:
        return OrgContext(
            assets=DEFAULT_SEED["assets"].copy(),
            source=str(target),
            note=f"org_context.json malformed ({exc}) — degraded to default configuration",
            valid=False,
            default_criticality=DEFAULT_CRITICALITY,
        )

    if not isinstance(data, dict):
        return OrgContext(
            assets=DEFAULT_SEED["assets"].copy(),
            source=str(target),
            note="org_context.json root must be an object — degraded to default configuration",
            valid=False,
            default_criticality=DEFAULT_CRITICALITY,
        )

    raw_assets = data.get("assets")
    if not isinstance(raw_assets, dict):
        return OrgContext(
            assets=DEFAULT_SEED["assets"].copy(),
            source=str(target),
            note="org_context.json 'assets' key missing or invalid — degraded to default configuration",
            valid=False,
            default_criticality=DEFAULT_CRITICALITY,
        )

    # Normalize entries
    normalized = {}
    for name, entry in raw_assets.items():
        if isinstance(entry, dict):
            crit = str(entry.get("criticality") or DEFAULT_CRITICALITY).lower()
            if crit not in CRITICALITY_LEVELS:
                crit = DEFAULT_CRITICALITY
            normalized[name] = {
                "criticality": crit,
                "owner": entry.get("owner"),
                "description": entry.get("description"),
            }
        elif isinstance(entry, str):
            crit = entry.lower()
            if crit not in CRITICALITY_LEVELS:
                crit = DEFAULT_CRITICALITY
            normalized[name] = {
                "criticality": crit,
                "owner": None,
                "description": None,
            }

    return OrgContext(
        assets=normalized,
        source=str(target),
        note=None,
        valid=True,
        default_criticality=data.get("defaultCriticality", DEFAULT_CRITICALITY),
    )


def save_org_context(payload, path=None):
    """Save updated asset criticality mappings to disk."""
    if not isinstance(payload, dict):
        raise ValueError("payload must be a dictionary")

    target = Path(path) if path else (STORE_CONFIG_FILE if SOC_DIR.exists() else DEFAULT_SEED_FILE)
    target.parent.mkdir(parents=True, exist_ok=True)

    assets_in = payload.get("assets") if "assets" in payload else payload
    if not isinstance(assets_in, dict):
        raise ValueError("assets must be a mapping of asset name -> config")

    normalized = {}
    for name, entry in assets_in.items():
        if isinstance(entry, dict):
            crit = str(entry.get("criticality") or DEFAULT_CRITICALITY).lower()
            if crit not in CRITICALITY_LEVELS:
                raise ValueError(f"Invalid criticality '{crit}' for asset '{name}'. Must be one of {CRITICALITY_LEVELS}")
            normalized[str(name)] = {
                "criticality": crit,
                "owner": entry.get("owner"),
                "description": entry.get("description"),
            }
        elif isinstance(entry, str):
            crit = entry.lower()
            if crit not in CRITICALITY_LEVELS:
                raise ValueError(f"Invalid criticality '{crit}' for asset '{name}'. Must be one of {CRITICALITY_LEVELS}")
            normalized[str(name)] = {
                "criticality": crit,
                "owner": None,
                "description": None,
            }
        else:
            raise ValueError(f"Invalid asset entry for '{name}': {entry}")

    data = {
        "version": 1,
        "defaultCriticality": payload.get("defaultCriticality", DEFAULT_CRITICALITY),
        "assets": normalized,
    }

    target.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return load_org_context(str(target))


def derive_priority(severity: str, criticality: str) -> str:
    """Derive operational priority deterministically from rule severity and asset criticality.

    CRITICAL RULE-OWNED CONTRACT:
    - This function takes ONLY (severity, criticality).
    - It NEVER mutates severity.
    - No LLM / advisory parameters exist in this signature.
    """
    sev = str(severity or "INFO").upper()
    crit = str(criticality or DEFAULT_CRITICALITY).lower()
    if crit not in CRITICALITY_LEVELS:
        crit = DEFAULT_CRITICALITY
    return PRIORITY_MATRIX.get((sev, crit), "P4")


def derive_incident_priority(incident, members=None, org_ctx=None):
    """Compute rule-owned priority and effective criticality for an incident.

    Examines incident entity and member findings (target hosts/IPs).
    The highest asset criticality among involved targets determines the incident's criticality.

    Returns:
      {
        "priority": "P1" | "P2" | "P3" | "P4",
        "criticality": "crown-jewel" | "standard" | "low",
        "targetAsset": str,
        "rationale": str,
      }

    GUARANTEE: incident['severity'] is NEVER mutated.
    """
    if org_ctx is None:
        org_ctx = load_org_context()

    candidates = []
    entity = incident.get("entity")
    if entity and incident.get("entityKind") == "host":
        candidates.append(str(entity))

    for m in (members or []):
        host = m.get("host")
        if host and host not in (None, "", "—"):
            candidates.append(str(host))
        for chip in m.get("chips") or []:
            txt = str(chip.get("text", "")).strip()
            if txt:
                candidates.append(txt)

    if entity and str(entity) not in candidates:
        candidates.append(str(entity))

    # Find determining asset: prioritize explicitly tagged assets
    crit_order = {"crown-jewel": 0, "standard": 1, "low": 2}
    tagged_candidates = []
    for asset in candidates:
        ctx_info = org_ctx.get_asset_context(asset)
        if ctx_info.get("tagged"):
            tagged_candidates.append((asset, ctx_info["criticality"]))

    if tagged_candidates:
        tagged_candidates.sort(key=lambda item: crit_order.get(item[1], 1))
        best_asset, best_crit = tagged_candidates[0]
    else:
        best_asset = candidates[0] if candidates else (entity or "unassigned")
        best_crit = org_ctx.default_criticality

    sev = str(incident.get("severity") or "INFO").upper()
    priority = derive_priority(sev, best_crit)

    rationale = f"Priority {priority} derived from {sev} severity on {best_crit} asset ({best_asset})"
    if best_crit == "crown-jewel" and sev in ("HIGH", "MEDIUM", "LOW"):
        rationale += " [elevated by crown-jewel criticality]"
    elif best_crit == "low" and sev in ("CRITICAL", "HIGH", "MEDIUM"):
        rationale += " [de-escalated by low criticality]"

    return {
        "priority": priority,
        "criticality": best_crit,
        "targetAsset": best_asset,
        "rationale": rationale,
    }
