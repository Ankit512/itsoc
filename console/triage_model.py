#!/usr/bin/env python3
"""
triage_model.py — E7a. The learned second-opinion triage model: ONE shared
feature function, and the honest loader/predictor that renders its opinion.

THE WALL (restated where it is enforced, not only where it is written):
  * Nothing in this module writes `sev`, `ruleSev`, incident `severity`,
    `priority`, runbook eligibility, or any execution state. It returns an
    ADVISORY object and nothing else. The caller copies severity back.
  * `features()` reads ONLY rule-owned facts: which rules fired, how many
    distinct entities the parser actually observed, the timing of the observed
    lines, and the configured asset criticality. It can NOT read a disposition,
    another model's output, prose, a severity override, a priority, an
    eligibility decision or an execution state — see FORBIDDEN_KEYS, and the
    leakage test in tests/test_stage_e_wall.py that proves it by mutation.
  * `features()` deliberately does NOT read `sev` / `ruleSev` either. A second
    opinion that can see the first one is not a second opinion; excluding it is
    what makes `agrees` / `disagrees` carry information.

HONESTY:
  * If scikit-learn is not installed, or the model artifact is missing, or it
    fails its recorded integrity check, or it does not load, this module
    returns an UNAVAILABLE state with `aiSeverity=None` and `confidence=None`.
    It never invents a severity, a confidence or an agreement.
  * There is no deterministic pseudo-AI fallback any more. Either a real model
    answered, or the surface says so.

Import-time cost is stdlib only: scikit-learn is imported lazily, inside
`load_model()`. Nothing on the verdict / severity / priority / eligibility /
execution path imports this module (import-graph test, Stage E wall part F).
"""

from __future__ import annotations

import hashlib
import json
import pickle
import re
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Module-level so tests and the train CLI can point these at a temp dir.
MODEL_DIR = HERE / ".soc" / "models"          # gitignored (console/.soc/)
MODEL_NAME = "triage_v1.pkl"
PROVENANCE_NAME = "triage_v1.provenance.json"

# The three-class analyst taxonomy, adopted verbatim from E0's disposition
# vocabulary so a real closed incident is a training row without translation.
LABELS = ("confirmed", "false-positive", "benign-expected")

SEVERITY_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# How a predicted CLASS becomes the rendered advisory SEVERITY OPINION. Fixed,
# published, and applied outside the model — the model never emits a severity.
#   confirmed        -> "I agree this is real; the rule's band stands."
#   false-positive   -> "I would not raise this at all."
#   benign-expected  -> "Real pattern, expected here; I would note it, not page."
DOWNGRADE_FOR_LABEL = {"false-positive": "INFO", "benign-expected": "LOW"}


def advisory_severity(label, rule_severity):
    """The advisory severity opinion for a predicted class. Never writes."""
    rule = str(rule_severity or "INFO").upper()
    if label == "confirmed":
        return rule if rule in SEVERITY_ORDER else "INFO"
    return DOWNGRADE_FOR_LABEL.get(label, "INFO")


# --------------------------------------------------------------------------
# the feature schema — ONE function, used by train and by inference
# --------------------------------------------------------------------------
# Every key is numeric and every key is derived from a rule-owned fact. The
# tuple is the wire order of the vector: a model trained on one order can only
# be scored with the same order, so the order is data, not incidental.
FEATURE_KEYS = (
    # -- rule hits ---------------------------------------------------------
    "rule_family_auth",
    "rule_family_scan_or_exposure",
    "rule_family_malware_or_threat",
    "rule_family_error_or_resource",
    "rule_family_windows",
    "rule_family_other",
    "rule_count",
    "rule_is_detector_owned",
    "occurrences",
    "evidence_line_count",
    "mitre_technique_count",
    # -- observed entity counts (what the parser actually saw) -------------
    "entity_ip_count",
    "entity_user_count",
    "entity_host_count",
    "entity_port_count",
    "entity_distinct_count",
    # -- timing ------------------------------------------------------------
    "timeline_step_count",
    "observed_span_seconds",
    "events_per_minute",
    "has_observed_time",
    # -- asset criticality -------------------------------------------------
    "criticality_rank",
)

# Keys that must never reach `features()`. Setting any of them, to anything,
# must leave the feature vector byte-identical. Proven by mutation in
# tests/test_stage_e_wall.py part G and in tools/test_train_triage.py.
FORBIDDEN_KEYS = frozenset({
    # E0 disposition — the label, never an input
    "disposition", "dispositionReason", "dispositionAt", "dispositionHistory",
    # model / advisory output (including this module's own)
    "aiTriage", "aiSeverity", "aiConfidence", "aiAgrees", "aiLabel",
    "modelSeverity", "modelLabel", "modelConfidence", "advisory",
    "llmSev", "llmWhy", "llm", "modelFindings",
    "similarityNote", "precedentOpinion", "proposalDraft",
    # prose
    "title", "summary", "evidence", "rationale", "ruleWhy", "explanation",
    "narrative", "hypothesis", "rca", "prose", "notes", "note",
    "recommended_action", "predicate", "dispositionNote",
    # severity override / the rule verdict itself
    "sev", "ruleSev", "severity", "severityOverride", "sevOverride",
    "analystSeverity",
    # priority
    "priority", "priorityRationale", "priorityRank",
    # eligibility
    "eligible", "eligibility", "eligibleRunbooks", "ineligibleReason",
    # execution state
    "executed", "executionState", "approvals", "approvalState", "actionState",
})

_AUTH_RE = re.compile(r"auth|login|password|brute|credential|lockout|account", re.I)
_SCAN_RE = re.compile(r"scan|port|exposure|outbound|break_in|url_|vulnerab|nmap", re.I)
_THREAT_RE = re.compile(r"threat|malware|ransom|c2|exfil|persistence|privilege|lateral", re.I)
_ERROR_RE = re.compile(r"error|disk|resource|critical_service|burst|quorum|zookeeper", re.I)
_WINDOWS_RE = re.compile(r"^windows_|^sigma_", re.I)

_CRITICALITY_RANK = {"low": 0, "standard": 1, "crown-jewel": 2}

# Entity keys the parsers actually populate, grouped by what they observe.
_IP_ENTITY_KEYS = ("ip", "src_ip", "dest_ip", "dst_ip")
_USER_ENTITY_KEYS = ("user", "username", "account")
_HOST_ENTITY_KEYS = ("host", "hostname", "server")
_PORT_ENTITY_KEYS = ("port", "dest_port", "dst_port")

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _num(value, default=0.0):
    try:
        out = float(value)
    except (TypeError, ValueError):
        return default
    return out if out == out else default          # NaN -> default


def _rule_ids(record):
    """Every rule id this record says fired — both shapes, no prose."""
    ids = []
    for key in ("ruleIds", "rule_ids"):
        for value in record.get(key) or []:
            if value:
                ids.append(str(value))
    for key in ("type", "rule_id"):
        value = record.get(key)
        if value:
            ids.append(str(value))
    seen, out = set(), []
    for rid in ids:
        if rid not in seen:
            seen.add(rid)
            out.append(rid)
    return out


def _entities(record):
    ent = record.get("entities")
    return ent if isinstance(ent, dict) else {}


def _observed_values(record):
    """(ips, users, hosts, ports) actually observed by the parser.

    Two shapes are accepted, because two callers exist and they must not drift:
    a report/console FINDING carries `entities` + `host`; a stored INCIDENT
    carries `entityValues` + `entity`/`entityKind`. Both are rule-owned facts
    the parser produced. Nothing here is guessed from prose.
    """
    ent = _entities(record)
    ips, users, hosts, ports = set(), set(), set(), set()
    for key in _IP_ENTITY_KEYS:
        if ent.get(key):
            ips.add(str(ent[key]))
    for key in _USER_ENTITY_KEYS:
        if ent.get(key):
            users.add(str(ent[key]))
    for value in ent.get("usernames_sample") or []:
        if value:
            users.add(str(value))
    for key in _HOST_ENTITY_KEYS:
        if ent.get(key):
            hosts.add(str(ent[key]))
    for key in _PORT_ENTITY_KEYS:
        if ent.get(key):
            ports.add(str(ent[key]))
    if record.get("host") and record.get("hostDerived") is not False:
        hosts.add(str(record["host"]))

    # Incident shape: entityValues is the parser-observed value list E1 hoisted
    # onto the incident. Split by literal form only — an IPv4 quad is an IP.
    for value in record.get("entityValues") or []:
        text = str(value)
        (ips if _IPV4_RE.match(text) else hosts).add(text)
    entity = record.get("entity")
    if entity:
        kind = str(record.get("entityKind") or "")
        text = str(entity)
        if kind == "ip" or _IPV4_RE.match(text):
            ips.add(text)
        elif kind == "host":
            hosts.add(text)
    hosts.discard("—")
    return ips, users, hosts, ports


def _timeline_span_seconds(record):
    """Seconds between the earliest and latest OBSERVED stamp, or None.

    Stamps come from the timeline the rules built (`ts`), or from an incident's
    firstSeen/lastSeen. Parsed with a fixed ISO reader — no clock is read, so
    this stays deterministic and replayable.
    """
    stamps = []
    for step in record.get("timeline") or []:
        if isinstance(step, dict) and step.get("ts"):
            stamps.append(str(step["ts"]))
    for key in ("firstSeen", "lastSeen"):
        if record.get(key):
            stamps.append(str(record[key]))
    parsed = []
    for text in stamps:
        try:
            parsed.append(datetime.fromisoformat(text.replace("Z", "+00:00")))
        except ValueError:
            continue
    if len(parsed) < 2:
        return None
    return abs((max(parsed) - min(parsed)).total_seconds())


def _criticality(record):
    value = str(record.get("criticality") or "").strip().lower()
    return _CRITICALITY_RANK.get(value, _CRITICALITY_RANK["standard"])


def features(record):
    """The ONE feature function. Train and inference both call exactly this.

    `record` is a rule-owned projection: a report finding, a console finding or
    a stored incident. Only the keys documented above are read; every key in
    FORBIDDEN_KEYS is invisible to this function by construction (it is never
    named here, and the leakage test proves mutation of any of them cannot move
    a single feature).

    Returns {feature_key: float} with exactly FEATURE_KEYS as its keys.
    """
    record = record if isinstance(record, dict) else {}

    rule_ids = _rule_ids(record)
    blob = " ".join(rule_ids)
    fam_auth = 1.0 if _AUTH_RE.search(blob) else 0.0
    fam_scan = 1.0 if _SCAN_RE.search(blob) else 0.0
    fam_threat = 1.0 if _THREAT_RE.search(blob) else 0.0
    fam_error = 1.0 if _ERROR_RE.search(blob) else 0.0
    fam_windows = 1.0 if any(_WINDOWS_RE.search(r) for r in rule_ids) else 0.0
    fam_other = 0.0 if (fam_auth or fam_scan or fam_threat or fam_error
                        or fam_windows) else 1.0

    ips, users, hosts, ports = _observed_values(record)
    occurrences = max(_num(record.get("occurrences"), 1.0), 0.0) or 1.0
    lines = record.get("lines")
    line_count = float(len(lines)) if isinstance(lines, list) else 0.0
    if not line_count:
        line_count = float(record.get("findingCount") or 0)
    steps = record.get("timeline")
    step_count = float(len(steps)) if isinstance(steps, list) else 0.0
    mitre = record.get("mitre") or record.get("techniques") or []
    technique_count = float(len(mitre)) if isinstance(mitre, list) else 0.0

    span = _timeline_span_seconds(record)
    has_time = 1.0 if span is not None else 0.0
    span_value = float(span or 0.0)
    per_minute = occurrences / max(span_value / 60.0, 1.0)

    is_detector = 1.0 if str(record.get("source") or "") == "detector" else 0.0
    if str(record.get("prov") or "") == "RULE-CAUGHT":
        is_detector = 1.0

    return {
        "rule_family_auth": fam_auth,
        "rule_family_scan_or_exposure": fam_scan,
        "rule_family_malware_or_threat": fam_threat,
        "rule_family_error_or_resource": fam_error,
        "rule_family_windows": fam_windows,
        "rule_family_other": fam_other,
        "rule_count": float(len(rule_ids)),
        "rule_is_detector_owned": is_detector,
        "occurrences": occurrences,
        "evidence_line_count": line_count,
        "mitre_technique_count": technique_count,
        "entity_ip_count": float(len(ips)),
        "entity_user_count": float(len(users)),
        "entity_host_count": float(len(hosts)),
        "entity_port_count": float(len(ports)),
        "entity_distinct_count": float(len(ips) + len(users) + len(hosts) + len(ports)),
        "timeline_step_count": step_count,
        "observed_span_seconds": span_value,
        "events_per_minute": round(per_minute, 6),
        "has_observed_time": has_time,
        "criticality_rank": float(_criticality(record)),
    }


def feature_vector(record):
    """features() in FEATURE_KEYS order — the only shape a model ever sees."""
    computed = features(record)
    return [float(computed[key]) for key in FEATURE_KEYS]


# --------------------------------------------------------------------------
# artifact locations + integrity
# --------------------------------------------------------------------------

def model_path():
    return MODEL_DIR / MODEL_NAME


def provenance_path():
    return MODEL_DIR / PROVENANCE_NAME


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ModelUnavailable(RuntimeError):
    """Raised with the honest, user-facing reason. Never swallowed silently."""


def sklearn_version():
    """The installed scikit-learn version, or None. Import is lazy on purpose."""
    try:
        import sklearn                     # noqa: PLC0415 (lazy by design)
    except Exception:                      # pragma: no cover - env dependent
        return None
    return getattr(sklearn, "__version__", "unknown")


def load_model():
    """(estimator, provenance). Raises ModelUnavailable with a real reason.

    Every failure mode is named: no scikit-learn, no artifact, no provenance,
    a provenance/artifact hash mismatch (corrupt or swapped file), a feature
    schema the shipped code no longer speaks, or an unpicklable artifact.
    """
    if sklearn_version() is None:
        raise ModelUnavailable(
            "scikit-learn is not installed — the learned second opinion is "
            "optional and this installation does not have it.")
    path, prov_path = model_path(), provenance_path()
    if not path.is_file():
        raise ModelUnavailable(
            f"no trained model at {path} — run `python3 tools/train_triage.py` "
            "to train one locally.")
    if not prov_path.is_file():
        raise ModelUnavailable(
            f"model artifact has no provenance sidecar at {prov_path} — an "
            "unprovenanced model is not loaded.")
    try:
        provenance = json.loads(prov_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelUnavailable(f"provenance sidecar is unreadable: {exc}") from exc
    recorded = str(provenance.get("modelSha256") or "")
    actual = sha256_file(path)
    if not recorded or recorded != actual:
        raise ModelUnavailable(
            "model artifact failed its integrity check (provenance records "
            f"{recorded[:12] or 'nothing'}, file is {actual[:12]}) — refusing "
            "to load a corrupt or swapped model.")
    if tuple(provenance.get("featureKeys") or ()) != FEATURE_KEYS:
        raise ModelUnavailable(
            "model was trained on a different feature schema than this build "
            "speaks — retrain before it is used.")
    try:
        with open(path, "rb") as handle:
            estimator = pickle.load(handle)
    except Exception as exc:               # noqa: BLE001 - reported, not hidden
        raise ModelUnavailable(f"model artifact did not load: {exc}") from exc
    return estimator, provenance


# --------------------------------------------------------------------------
# advisory prediction
# --------------------------------------------------------------------------

_NOTE = ("Learned second opinion — ADVISORY. It never changes the rule verdict, "
         "the incident severity, the priority, runbook eligibility, or any "
         "action. The analyst decides.")


def unavailable(reason, rule_severity=None):
    """The honest 'model unavailable' advisory state. No severity is invented."""
    rule = str(rule_severity or "").upper()
    return {
        "advisory": True,
        "learned": True,
        "modelAvailable": False,
        "status": "unavailable",
        "ruleSeverity": rule,
        "aiSeverity": None,
        "aiLabel": None,
        "confidence": None,
        "agrees": None,
        "unavailableReason": str(reason),
        "modelProvenance": None,
        "note": ("Learned second opinion — ADVISORY — is UNAVAILABLE here. No "
                 "opinion is shown and none is guessed. Rule verdicts, "
                 "incidents and case files are entirely unaffected."),
    }


def predict_with(estimator, record, rule_severity, provenance=None):
    """One advisory opinion from an ALREADY-LOADED estimator. Pure.

    Split out from `predict()` so the rendering contract can be exercised
    without a trained artifact on disk, and so nothing here can reach the
    filesystem, the network or a clock.
    """
    rule = str(rule_severity or "INFO").upper()
    vector = [feature_vector(record)]
    try:
        classes = [str(c) for c in getattr(estimator, "classes_", LABELS)]
        if hasattr(estimator, "predict_proba"):
            probabilities = list(estimator.predict_proba(vector)[0])
            index = max(range(len(probabilities)), key=lambda i: probabilities[i])
            label = classes[index]
            confidence = round(float(probabilities[index]), 4)
        else:
            label = str(estimator.predict(vector)[0])
            raise ModelUnavailable(
                "the loaded estimator exposes no calibrated probability, so no "
                f"confidence can be reported honestly (predicted {label}).")
    except ModelUnavailable:
        raise
    except Exception as exc:               # noqa: BLE001 - reported, not hidden
        raise ModelUnavailable(f"model scoring failed: {exc}") from exc
    if label not in LABELS:
        raise ModelUnavailable(
            f"model returned an unknown class {label!r} — not rendered.")

    opinion = advisory_severity(label, rule)
    agrees = opinion == rule
    prov = None
    if isinstance(provenance, dict):
        prov = {key: provenance.get(key) for key in
                ("trainedAt", "seed", "datasetRows", "modelSha256",
                 "sklearnVersion")}
    return {
        "advisory": True,
        "learned": True,
        "modelAvailable": True,
        "status": "agrees" if agrees else "disagrees",
        "ruleSeverity": rule,
        "aiSeverity": opinion,
        "aiLabel": label,
        "confidence": confidence,
        "agrees": agrees,
        "unavailableReason": None,
        "modelProvenance": prov,
        "note": _NOTE,
    }


_CACHE = {"key": None, "estimator": None, "provenance": None, "error": None}


def reset_cache():
    """Drop the loaded model. Used by tests and after a retrain."""
    _CACHE.update({"key": None, "estimator": None, "provenance": None,
                   "error": None})


def _cache_key():
    path = model_path()
    try:
        stat = path.stat()
        return (str(path), stat.st_mtime_ns, stat.st_size)
    except OSError:
        return (str(path), None, None)


def _cached_model():
    key = _cache_key()
    if _CACHE["key"] != key:
        reset_cache()
        _CACHE["key"] = key
        try:
            _CACHE["estimator"], _CACHE["provenance"] = load_model()
        except ModelUnavailable as exc:
            _CACHE["error"] = str(exc)
    if _CACHE["error"]:
        raise ModelUnavailable(_CACHE["error"])
    return _CACHE["estimator"], _CACHE["provenance"]


def predict(record, rule_severity):
    """The advisory opinion for one record, or the honest unavailable state."""
    try:
        estimator, provenance = _cached_model()
        return predict_with(estimator, record, rule_severity, provenance)
    except ModelUnavailable as exc:
        return unavailable(str(exc), rule_severity)


def status():
    """Model availability for the UI/API, with no fabricated numbers."""
    try:
        _estimator, provenance = _cached_model()
    except ModelUnavailable as exc:
        return {
            "available": False,
            "reason": str(exc),
            "sklearn": sklearn_version(),
            "modelPath": str(model_path()),
            "provenance": None,
        }
    return {
        "available": True,
        "reason": None,
        "sklearn": sklearn_version(),
        "modelPath": str(model_path()),
        "provenance": provenance,
    }
