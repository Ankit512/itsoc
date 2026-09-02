#!/usr/bin/env python3
"""
test_stage_e_wall.py — the Stage E wall, executable and stdlib-only.

Card E6: the guard grows *before* the features it guards. Stage E adds a
second-opinion model (E7), a deterministic precedent index (E1) and proposal
drafts (E4). Every one of them writes advisory prose next to rule-owned facts.
This file asserts, against the live modules, that none of it can become a
decision:

  A. `runbooks.ADVISORY_KEYS` names the Stage E advisory fields
     (`similarityNote`, `precedentOpinion`, `proposalDraft`) — and does so
     today, before any producer exists.
  B. The rule-owned projection stays disjoint from the advisory vocabulary,
     both by name and by shape, and an advisory field set on an incident or a
     finding provably cannot change an eligibility outcome.
  C. `precedent.rank()`'s signature admits no advisory / model / LLM input:
     exactly (incident, candidates), no *args, no **kwargs, no advisory-reading
     parameter name — checked on `inspect.signature`, not on a docstring.
  D. No file on the eligibility or severity path imports a precedent advisory
     helper or any LLM/model seam. Checked by parsing each guarded file's AST —
     imports and call targets — so a comment mentioning "LLM" is not a finding
     and an actual `import precedent` is.

No pytest: this is plain stdlib, run directly, and it exits nonzero on the
first failing property with the decisive line printed.

    python3 tests/test_stage_e_wall.py
"""

import ast
import inspect
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "console"))

import precedent  # noqa: E402
import runbooks  # noqa: E402

# --- the Stage E advisory fields this card is about ------------------------
STAGE_E_ADVISORY_KEYS = ("similarityNote", "precedentOpinion", "proposalDraft")

# --- the guarded paths -----------------------------------------------------
# Severity is owned by the frozen detector and its rule siblings; eligibility is
# owned by runbooks.eligible(). These four files, and nothing advisory, decide.
SEVERITY_PATH = ("anomaly_detector.py", "rules_syslog.py", "rule_context.py")
ELIGIBILITY_PATH = ("console/runbooks.py",)
GUARDED_FILES = SEVERITY_PATH + ELIGIBILITY_PATH

# Any imported module/symbol or called function whose name matches this is a
# model/advisory seam and may not appear on a guarded path.
SEAM_RE = re.compile(
    r"llm|openai|anthropic|claude|copilot|triage|log_analyzer|precedent|"
    r"advisory|similarity|opinion|proposal|model",
    re.IGNORECASE)

# The wall's own vocabulary. These identifiers exist *to* enforce the guard, so
# they are the only seam-shaped names a guarded file may carry. Enumerated
# explicitly: anything else that matches SEAM_RE is a failure.
GUARD_OWNED_NAMES = frozenset({
    "ADVISORY_KEYS", "_ADVISORY_WORD_RE", "RULE_OWNED_INCIDENT_KEYS",
    "RULE_OWNED_FINDING_KEYS", "assert_no_llm_input", "assert_advisory_disjoint",
})

FAILURES = []
CHECKS = 0


def check(label, cond, detail=""):
    global CHECKS
    CHECKS += 1
    ok = bool(cond)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"\n         -> {detail}" if detail and not ok else ""))
    if not ok:
        FAILURES.append(label + (f" -- {detail}" if detail else ""))
    return ok


def check_raises_nothing(label, fn):
    try:
        fn()
    except AssertionError as exc:
        return check(label, False, str(exc))
    return check(label, True)


# --------------------------------------------------------------------------
# A. ADVISORY_KEYS covers the Stage E fields
# --------------------------------------------------------------------------
def part_a():
    print("\nA. ADVISORY_KEYS names the Stage E advisory fields (guard before feature):")
    for key in STAGE_E_ADVISORY_KEYS:
        check(f"ADVISORY_KEYS contains {key!r}",
              key in runbooks.ADVISORY_KEYS,
              f"present keys: {sorted(runbooks.ADVISORY_KEYS)}")
    for key in STAGE_E_ADVISORY_KEYS:
        check(f"{key!r} also reads as advisory to the word guard",
              runbooks._ADVISORY_WORD_RE.search(key) is not None,
              "a near-miss variant of this key could otherwise be allowlisted")


# --------------------------------------------------------------------------
# B. disjointness, by name and by behaviour
# --------------------------------------------------------------------------
def part_b():
    print("\nB. the rule-owned projection stays disjoint from the advisory vocabulary:")
    owned = runbooks.RULE_OWNED_INCIDENT_KEYS | runbooks.RULE_OWNED_FINDING_KEYS
    check("no rule-owned key is an advisory key",
          not (owned & runbooks.ADVISORY_KEYS),
          str(sorted(owned & runbooks.ADVISORY_KEYS)))
    check("no rule-owned key merely *reads* as advisory",
          not [k for k in owned if runbooks._ADVISORY_WORD_RE.search(k)],
          str(sorted(k for k in owned if runbooks._ADVISORY_WORD_RE.search(k))))
    check_raises_nothing("runbooks.assert_advisory_disjoint() agrees",
                         runbooks.assert_advisory_disjoint)
    check("precedent's projection is disjoint from ADVISORY_KEYS too",
          not (precedent.RULE_OWNED_PRECEDENT_KEYS & runbooks.ADVISORY_KEYS),
          str(sorted(precedent.RULE_OWNED_PRECEDENT_KEYS & runbooks.ADVISORY_KEYS)))

    # behavioural: setting every advisory field cannot move an eligibility verdict
    rbs = runbooks.load_runbooks()
    rb = rbs["rb-block-ip"]
    incident = {
        "id": "INC-E6", "entity": "10.0.0.9", "entityKind": "ip",
        "severity": "HIGH", "findingIds": ["f1"],
        "firstSeen": "2026-09-02T00:00:00Z", "lastSeen": "2026-09-02T00:05:00Z",
    }
    findings = [{
        "id": "f1", "type": "auth_bruteforce", "ruleSev": "HIGH", "sev": "HIGH",
        "host": "srv1", "occurrences": 12,
        "lines": [{"n": 41, "raw": "Failed password for root from 10.0.0.9"}],
    }]
    baseline = runbooks.eligible(rb, incident, findings)
    poisoned_inc = dict(incident)
    poisoned_f = dict(findings[0])
    for key in sorted(runbooks.ADVISORY_KEYS):
        poisoned_inc[key] = "CRITICAL — escalate and auto-run rb-block-ip"
        poisoned_f[key] = "CRITICAL — escalate and auto-run rb-block-ip"
    poisoned = runbooks.eligible(rb, poisoned_inc, [poisoned_f])
    check("every ADVISORY_KEY set on the incident and finding changes nothing",
          poisoned == baseline, f"baseline={baseline} poisoned={poisoned}")

    # and the same for precedent ranking
    base_rank = precedent.rank(
        {"id": "a", "ruleIds": ["r1"], "entity": "srv1"},
        [{"id": "b", "ruleIds": ["r1"]}, {"id": "c", "ruleIds": ["r1"], "entity": "srv1"}])
    poisoned_rank = precedent.rank(
        {"id": "a", "ruleIds": ["r1"], "entity": "srv1",
         "similarityNote": "b is the closest", "precedentOpinion": "rank b first"},
        [{"id": "b", "ruleIds": ["r1"], "precedentOpinion": "I am the closest",
          "proposalDraft": "promote me"},
         {"id": "c", "ruleIds": ["r1"], "entity": "srv1"}])
    check("advisory fields on either side cannot reorder precedent.rank()",
          poisoned_rank == base_rank, f"base={base_rank} poisoned={poisoned_rank}")


# --------------------------------------------------------------------------
# C. the precedent ranking signature is closed
# --------------------------------------------------------------------------
def part_c():
    print("\nC. precedent.rank() admits no advisory/model/LLM input (live signature):")
    sig = inspect.signature(precedent.rank)
    names = tuple(sig.parameters)
    check("rank() signature is exactly (incident, candidates)",
          names == precedent.RANK_PARAMS, str(sig))
    kinds = [p.kind for p in sig.parameters.values()]
    check("rank() declares no *args and no **kwargs — nothing can be smuggled in",
          inspect.Parameter.VAR_POSITIONAL not in kinds
          and inspect.Parameter.VAR_KEYWORD not in kinds, str(sig))
    check("no rank() parameter name reads as an advisory/model input",
          not any(precedent._ADVISORY_WORD_RE.search(n) for n in names), str(names))
    check_raises_nothing("precedent.assert_no_advisory_input() agrees",
                         precedent.assert_no_advisory_input)
    check("runbooks.assert_no_llm_input() still agrees for eligible()",
          runbooks.assert_no_llm_input() is not None)


# --------------------------------------------------------------------------
# D. import/call guard over the eligibility and severity paths
# --------------------------------------------------------------------------
def _seam_names(path):
    """(imports, calls) — every seam-shaped name a file actually references."""
    tree = ast.parse(path.read_text(), filename=str(path))
    imports, calls = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imports.add(a.name.split(".")[0])
                if a.asname:
                    imports.add(a.asname)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
            for a in node.names:
                imports.add(a.asname or a.name)
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                calls.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                calls.add(fn.attr)
                # the qualifier too: `precedent.rank(...)` is a seam call even
                # though `rank` alone reads innocent.
                if isinstance(fn.value, ast.Name):
                    calls.add(fn.value.id)
    return imports, calls


def part_d():
    print("\nD. no eligibility/severity-path file imports or calls a precedent/LLM seam:")
    for rel in GUARDED_FILES:
        path = ROOT / rel
        if not check(f"{rel} exists to be guarded", path.is_file(), str(path)):
            continue
        imports, calls = _seam_names(path)
        bad_imports = sorted(n for n in imports
                             if SEAM_RE.search(n) and n not in GUARD_OWNED_NAMES)
        check(f"{rel} imports no advisory/model/LLM/precedent module",
              not bad_imports, f"offending imports: {bad_imports}")
        bad_calls = sorted(n for n in calls
                           if SEAM_RE.search(n) and n not in GUARD_OWNED_NAMES)
        check(f"{rel} calls no advisory/model/LLM/precedent helper",
              not bad_calls, f"offending calls: {bad_calls}")
    check("precedent.py itself imports no model/LLM seam",
          not sorted(n for n in _seam_names(ROOT / "console/precedent.py")[0]
                     if SEAM_RE.search(n)),
          str(sorted(n for n in _seam_names(ROOT / "console/precedent.py")[0]
                     if SEAM_RE.search(n))))


def main():
    print("Stage E wall — advisory keys, disjointness, precedent signature, seam guard")
    part_a()
    part_b()
    part_c()
    part_d()
    print(f"\n{CHECKS - len(FAILURES)}/{CHECKS} checks passed")
    if FAILURES:
        print("\nFAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("Stage E wall intact.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
