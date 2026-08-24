#!/usr/bin/env python3
"""
tools/model_ab.py — A/B-benchmark candidate models on the EXISTING analyze path.

Runs log_analyzer.run() (never a reimplementation) against each candidate model
over the two benchmark logs, with schema-constrained structured output ON and
temperature 0, and records per model:

  - warm median latency per explanation call (call 1 pays the model load, so it
    is excluded from the median once there is more than one call)
  - schema-valid vs invalid reply counts, and whether the endpoint fell back
    from json_schema decoding (from the run's structured_output metadata)
  - findings counts by source — with the RULE findings ASSERTED identical
    across models: rules own severity and correlation, so a model swap that
    changes a rule verdict is a bug this tool must surface, never hide
  - every finding's explanation text, dumped for human eyeball comparison

This tool MEASURES; it never PICKS. Choosing a winner is a human decision made
from the report (tools/model_ab_report.md). The tool changes no defaults, no
detector logic, no analyzer logic — it drives the public entry points only.

A model that is not installed/reachable is reported honestly and skipped; an
unreachable endpoint yields a template report saying exactly that. No fake
numbers, ever.

Usage:
  python3 tools/model_ab.py llama3.1:8b qwen2.5:7b
  python3 tools/model_ab.py llama3.1:8b --base-url http://localhost:11434/v1
"""

import argparse
import json
import statistics
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import log_analyzer as la  # noqa: E402

SAMPLES = [ROOT / "samples" / "OpenSSH_2k.log", ROOT / "samples" / "Linux_2k.log"]
REPORT_PATH = ROOT / "tools" / "model_ab_report.md"

HOW_TO_PICK = """\
## Picking a winner (a human call — this tool only measures)

- Set the winner via the `LLM_MODEL` env var (e.g. in your `.env` /
  shell profile): `export LLM_MODEL=<model>` — every entry point
  (CLI `--model`, console, web) already follows it. The one sanctioned
  code default stays `llama3.1:8b` at log_analyzer.py:61.
- If the DEFAULT model is ever changed (a product decision, not this tool's):
  update the docs that name it (RUNBOOK.md, README.md, log_analyzer.py's
  docstring/comments) in the same change. The console's per-finding
  "Plain-language explanation" label and the run-manifest strip derive the
  model from run metadata, so they follow automatically — but any static
  design mockups under docs/design/ name it too.
- Rule findings are identical across models BY CONSTRUCTION (asserted below);
  compare models on explanation quality, latency, and schema reliability only.
"""


def list_models(base_url, api_key):
    """Model ids the endpoint offers, or None if the endpoint is unreachable."""
    req = urllib.request.Request(f"{base_url}/models",
                                 headers={"Authorization": f"Bearer {api_key}"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return [m.get("id") for m in json.loads(resp.read()).get("data", [])]
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return None


def metered_chat(stats):
    """Wrap la.chat_completion with timing + reply-shape accounting.

    Wrapping from outside (exactly like the test suite does) keeps the analyze
    path byte-identical to production — same prompts, same retries, same
    validation, same fallback behavior.
    """
    real = la.chat_completion

    def timed(base_url, api_key, model, system, user, timeout=300,
              response_schema=None):
        t0 = time.monotonic()
        reply = real(base_url, api_key, model, system, user, timeout=timeout,
                     response_schema=response_schema)
        stats["latencies"].append(time.monotonic() - t0)
        try:
            ok = la.validate_response(json.loads(la.strip_fences(reply)))
        except json.JSONDecodeError:
            ok = False
        stats["schema_valid" if ok else "schema_invalid"] += 1
        return reply

    return real, timed


def warm_median(latencies):
    """Median with the cold first call (model load) excluded when possible."""
    if not latencies:
        return None
    warm = latencies[1:] if len(latencies) > 1 else latencies
    return statistics.median(warm)


def rule_signature(report):
    """What the rules said, order-independent: the identity that must not move."""
    return sorted((f.get("rule_id") or "", f.get("summary") or "")
                  for f in report.get("findings", [])
                  if f.get("source") == "detector")


def run_one(model, sample, base_url, api_key):
    """One model x one sample through la.run(); returns the measurements dict."""
    # Fresh decoding state per run: structured output ON, temperature 0, and no
    # fallback stickiness carried over from a previous model.
    la.LLM_STRUCTURED_OUTPUT = True
    la.LLM_TEMPERATURE = 0.0
    la._STRUCTURED_FALLBACK["reason"] = None

    stats = {"latencies": [], "schema_valid": 0, "schema_invalid": 0}
    real, timed = metered_chat(stats)
    la.chat_completion = timed
    try:
        with tempfile.TemporaryDirectory(prefix="model-ab-") as tmp:
            prefix = str(Path(tmp) / "report")
            la.run(str(sample), prefix, 25, model, base_url, api_key)
            report = json.loads(Path(prefix + ".json").read_text())
    finally:
        la.chat_completion = real

    by_source = report.get("findings_by_source", {})
    explanations = [
        {"rule_id": f.get("rule_id"), "severity": f.get("severity"),
         "summary": f.get("summary"),
         "explanation": f.get("recommended_action") or "(none generated)"}
        for f in report.get("findings", []) if f.get("source") == "detector"
    ]
    return {
        "model": model,
        "sample": sample.name,
        "rule_findings": by_source.get("detector", 0),
        "llm_findings": by_source.get("llm", 0),
        "analyzer_errors": by_source.get("analyzer", 0),
        "structured_output": report.get("structured_output"),
        "schema_valid": stats["schema_valid"],
        "schema_invalid": stats["schema_invalid"],
        "calls": len(stats["latencies"]),
        "warm_median_s": warm_median(stats["latencies"]),
        "rule_signature": rule_signature(report),
        "explanations": explanations,
    }


def emit_report(rows, skipped, endpoint_note, rule_mismatches, out_path):
    lines = ["# Model A/B report", ""]
    lines.append(f"_Generated by tools/model_ab.py — structured output ON, "
                 f"temperature 0, chunk size 25. {endpoint_note}_")
    lines.append("")
    if skipped:
        lines.append("## Not measured")
        lines.append("")
        for model, why in skipped:
            lines.append(f"- `{model}` — {why}")
        lines.append("")
    if rows:
        lines.append("## Measurements")
        lines.append("")
        lines.append("| model | sample | rule findings | llm findings | analyzer errors "
                     "| schema-valid calls | schema-invalid calls | structured output "
                     "| warm median latency (s) |")
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for r in rows:
            med = f"{r['warm_median_s']:.2f}" if r["warm_median_s"] is not None else "n/a"
            lines.append(f"| `{r['model']}` | {r['sample']} | {r['rule_findings']} "
                         f"| {r['llm_findings']} | {r['analyzer_errors']} "
                         f"| {r['schema_valid']} | {r['schema_invalid']} "
                         f"| `{r['structured_output']}` | {med} |")
        lines.append("")
        if rule_mismatches:
            lines.append("## RULE-FINDING MISMATCH — BUG, DO NOT PICK A WINNER FROM THIS RUN")
            lines.append("")
            for m in rule_mismatches:
                lines.append(f"- {m}")
            lines.append("")
        else:
            lines.append("Rule findings were identical across all measured models "
                         "(asserted per sample) — rules own the verdicts; the model "
                         "only changes prose and latency.")
            lines.append("")
        lines.append("## Explanations, per model (for eyeball comparison)")
        lines.append("")
        for r in rows:
            lines.append(f"### `{r['model']}` — {r['sample']}")
            lines.append("")
            for e in r["explanations"]:
                lines.append(f"- **[{e['severity']}] {e['rule_id']}** — {e['summary']}")
                lines.append(f"  - {e['explanation']}")
            lines.append("")
    else:
        lines.append("## No measurements")
        lines.append("")
        lines.append("No candidate model was reachable when this report was generated, "
                     "so there are no numbers — this file is the honest template the "
                     "tool fills in when run with a live endpoint.")
        lines.append("")
    lines.append(HOW_TO_PICK)
    out_path.write_text("\n".join(lines))
    print(f"\nReport written: {out_path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("models", nargs="+", help="candidate model names, e.g. llama3.1:8b qwen2.5:7b")
    ap.add_argument("--base-url", default=la.LLM_BASE_URL)
    ap.add_argument("--api-key", default=la.LLM_API_KEY)
    ap.add_argument("--output", default=str(REPORT_PATH))
    args = ap.parse_args()

    available = list_models(args.base_url, args.api_key)
    rows, skipped, mismatches = [], [], []
    if available is None:
        endpoint_note = f"Endpoint {args.base_url} was NOT reachable."
        print(f"endpoint not reachable at {args.base_url} — nothing measured (honest skip)")
        skipped = [(m, f"endpoint {args.base_url} not reachable") for m in args.models]
    else:
        endpoint_note = f"Endpoint: {args.base_url}."
        baseline = {}  # sample name -> (model, rule_signature)
        for model in args.models:
            if model not in available:
                print(f"model not reachable: {model!r} is not offered by "
                      f"{args.base_url} — skipped (installed: {', '.join(available) or 'none'})")
                skipped.append((model, "not offered by the endpoint (`/models`)"))
                continue
            for sample in SAMPLES:
                if not sample.exists():
                    skipped.append((model, f"sample missing: {sample.name}"))
                    continue
                print(f"\n=== {model} × {sample.name} ===")
                row = run_one(model, sample, args.base_url, args.api_key)
                rows.append(row)
                key = sample.name
                if key not in baseline:
                    baseline[key] = (model, row["rule_signature"])
                elif row["rule_signature"] != baseline[key][1]:
                    msg = (f"{sample.name}: rule findings under `{model}` differ from "
                           f"`{baseline[key][0]}` — rules must not move with the model. "
                           f"This is a bug to investigate, not a model preference.")
                    print(f"BUG: {msg}")
                    mismatches.append(msg)

    emit_report(rows, skipped, endpoint_note, mismatches, Path(args.output))
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
