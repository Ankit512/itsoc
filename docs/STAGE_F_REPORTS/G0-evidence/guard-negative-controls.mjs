#!/usr/bin/env node

/**
 * Negative controls for the diff-visuals.mjs comparability guards.
 *
 * A guard nobody has watched fail is a claim, not a guard. This harness takes
 * the real committed manifests, applies ONE deliberate defect per control to a
 * COPY of them in a temporary directory outside the repository, and records
 * what diff-visuals.mjs did: its exit status, its verdict, and which guards
 * fired. Nothing in the repository is written or restored, so there is no
 * window in which the evidence tree is mutated.
 *
 * It also runs a positive control — the unmodified manifests — to show the
 * same command exits 0 and reports a real verdict, i.e. that the guards are
 * discriminating rather than simply always red.
 *
 * Usage:
 *   node docs/STAGE_F_REPORTS/G0-evidence/guard-negative-controls.mjs \
 *     --before before-frozen --after after-frozen
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const EVIDENCE_ROOT = path.dirname(SCRIPT_PATH);
const REPO_ROOT = path.resolve(EVIDENCE_ROOT, "../../..");
const DIFF_SCRIPT = path.join(EVIDENCE_ROOT, "diff-visuals.mjs");
const PROOF_PATH = path.join(EVIDENCE_ROOT, "guard-negative-control-proof.json");

function parseArgs(argv) {
  const out = { before: null, after: null };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--before") out.before = argv[++i];
    else if (argv[i] === "--after") out.after = argv[++i];
    else throw new Error(`Unknown argument: ${argv[i]}`);
  }
  if (!out.before || !out.after) throw new Error("--before and --after are required");
  return out;
}

const sha256 = (buffer) => createHash("sha256").update(buffer).digest("hex");
const clone = (value) => JSON.parse(JSON.stringify(value));

/**
 * Each control names the guard it targets and mutates the manifest COPY so that
 * exactly that guard should fire. The mutations are chosen to be otherwise
 * harmless: a comparison that ignored the guard would still find 48 readable
 * PNG pairs and would still print a pixel verdict — which is precisely the
 * false green being tested for.
 */
const CONTROLS = [
  {
    name: "capture-settings-report-payload",
    guard: "capture-settings",
    describes: "the two sides served different application data",
    mutate: (before) => { before.reportProvenance.report.sha256 = `${"0".repeat(63)}1`; },
  },
  {
    name: "capture-settings-viewport",
    guard: "capture-settings",
    describes: "the two sides were photographed at different viewport sizes",
    mutate: (before) => { before.captureSettings.viewport = { width: 1440, height: 900, deviceScaleFactor: 1 }; },
  },
  {
    name: "duplicate-id",
    guard: "duplicate-id",
    describes: "one manifest lists the same route/theme state twice",
    mutate: (before) => { before.captures.push(clone(before.captures[0])); },
  },
  {
    name: "missing-pair",
    guard: "missing-pair",
    describes: "a route/theme state exists on only one side",
    mutate: (before) => { before.captures = before.captures.filter((c) => c.id !== "dark:integrations"); },
  },
  {
    name: "route-matrix-short",
    guard: "route-matrix",
    describes: "the matrix is not 24 routes x 2 themes (a route was dropped from both sides)",
    mutate: (before, after) => {
      for (const manifest of [before, after]) {
        manifest.captures = manifest.captures.filter((c) => !c.id.endsWith(":settings"));
        manifest.summary.routeStates = 23;
      }
    },
  },
  {
    name: "route-matrix-single-theme",
    guard: "route-matrix",
    describes: "a whole theme is missing from both sides",
    mutate: (before, after) => {
      for (const manifest of [before, after]) {
        manifest.captures = manifest.captures.filter((c) => c.theme !== "light");
        manifest.summary.themes = ["dark"];
      }
    },
  },
  {
    name: "dimensions-declared",
    guard: "dimensions",
    describes: "a capture is not the expected 1500x1000 viewport",
    mutate: (before) => { before.captures[0].width = 1400; },
  },
  {
    name: "manifest-schema-version",
    guard: "manifest-schema",
    describes: "a pre-repair manifest schema that cannot prove what it photographed",
    mutate: (before) => { before.schemaVersion = 1; },
  },
  {
    name: "manifest-schema-unhashed-artifacts",
    guard: "manifest-schema",
    describes: "photographed artifacts recorded as bare paths, so the stylesheet is asserted not proven",
    mutate: (before) => {
      before.source.photographedTreeArtifacts = before.source.photographedTreeArtifacts.map((a) => a.path);
    },
  },
  {
    name: "manifest-schema-no-frozen-payload",
    guard: "manifest-schema",
    describes: "the manifest cannot say whether its run data was frozen",
    mutate: (before) => { delete before.reportProvenance.frozenPayload; },
  },
];

function runDiff({ manifestDir, before, after, inventory, diffDir }) {
  const result = spawnSync(process.execPath, [DIFF_SCRIPT], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      G0_MANIFEST_DIR: manifestDir,
      G0_BEFORE_LABEL: before,
      G0_AFTER_LABEL: after,
      G0_INVENTORY: inventory,
      G0_DIFF_DIR: diffDir,
      G0_ANNOTATIONS: path.join(manifestDir, "no-annotations.json"),
    },
  });
  if (result.error) throw result.error;
  const parsed = existsSync(inventory) ? JSON.parse(readFileSync(inventory, "utf8")) : null;
  return {
    exitStatus: result.status,
    verdict: parsed?.summary?.verdict ?? null,
    comparable: parsed?.comparison?.comparable ?? null,
    guardsFired: parsed?.blockers ? [...new Set(parsed.blockers.map((b) => b.guard))].sort() : [],
    blockerCount: parsed?.blockers?.length ?? 0,
    stderrHead: result.stderr.split("\n").filter(Boolean).slice(0, 4),
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const sourceManifests = Object.fromEntries([args.before, args.after].map((label) => {
    const file = path.join(EVIDENCE_ROOT, `${label}-manifest.json`);
    if (!existsSync(file)) throw new Error(`Missing manifest: ${file}`);
    return [label, { file, sha256: sha256(readFileSync(file)) }];
  }));

  const workDir = mkdtempSync(path.join(os.tmpdir(), "itsoc-g0-guard-"));
  const controls = [];
  let positive;
  try {
    // Positive control: untouched copies must still be accepted and must
    // produce a real pixel verdict. Without this the negative controls only
    // prove the script can say no.
    const cleanDir = path.join(workDir, "clean");
    mkdirSync(cleanDir, { recursive: true });
    for (const label of [args.before, args.after]) {
      writeFileSync(path.join(cleanDir, `${label}-manifest.json`), readFileSync(sourceManifests[label].file));
    }
    positive = {
      name: "positive-control-unmodified",
      expectation: "accepted; a real pixel verdict is computed",
      ...runDiff({
        manifestDir: cleanDir,
        before: args.before,
        after: args.after,
        inventory: path.join(workDir, "clean-inventory.json"),
        diffDir: path.join(workDir, "clean-diff"),
      }),
    };

    for (const control of CONTROLS) {
      const dir = path.join(workDir, control.name);
      mkdirSync(dir, { recursive: true });
      const before = JSON.parse(readFileSync(sourceManifests[args.before].file, "utf8"));
      const after = JSON.parse(readFileSync(sourceManifests[args.after].file, "utf8"));
      control.mutate(before, after);
      writeFileSync(path.join(dir, `${args.before}-manifest.json`), `${JSON.stringify(before, null, 2)}\n`);
      writeFileSync(path.join(dir, `${args.after}-manifest.json`), `${JSON.stringify(after, null, 2)}\n`);

      const outcome = runDiff({
        manifestDir: dir,
        before: args.before,
        after: args.after,
        inventory: path.join(workDir, `${control.name}-inventory.json`),
        diffDir: path.join(workDir, `${control.name}-diff`),
      });
      controls.push({
        name: control.name,
        targetedGuard: control.guard,
        defectInjected: control.describes,
        expectation: "non-zero exit, non-green verdict, targeted guard fires",
        ...outcome,
        targetedGuardFired: outcome.guardsFired.includes(control.guard),
        nonZeroExit: outcome.exitStatus !== 0,
        nonGreenVerdict: typeof outcome.verdict === "string" && !outcome.verdict.startsWith("ZERO VISUAL DELTA"),
      });
    }
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }

  const allBit = controls.every((c) => c.targetedGuardFired && c.nonZeroExit && c.nonGreenVerdict);
  const positiveAccepted = positive.exitStatus === 0 && positive.comparable === true;

  const proof = {
    schemaVersion: 1,
    kind: "itsoc-g0-visual-guard-negative-control-proof",
    generatedAt: new Date().toISOString(),
    subject: path.relative(REPO_ROOT, DIFF_SCRIPT),
    subjectSha256: sha256(readFileSync(DIFF_SCRIPT)),
    method: [
      "Each control copies the two real capture manifests into a temporary directory,",
      "injects exactly one defect into the copy, and runs diff-visuals.mjs against it via",
      "G0_MANIFEST_DIR. The repository evidence tree is never written to, so no restore step",
      "is needed and no window exists in which committed evidence is mutated.",
    ].join(" "),
    manifestsUnderTest: Object.fromEntries(
      Object.entries(sourceManifests).map(([label, v]) => [label, { path: path.relative(REPO_ROOT, v.file), sha256: v.sha256 }]),
    ),
    positiveControl: positive,
    negativeControls: controls,
    summary: {
      positiveControlAccepted: positiveAccepted,
      negativeControlCount: controls.length,
      allTargetedGuardsFired: allBit,
      guardsCovered: [...new Set(CONTROLS.map((c) => c.guard))].sort(),
      allGuardsProvenRedCapable: allBit && positiveAccepted,
    },
  };
  writeFileSync(PROOF_PATH, `${JSON.stringify(proof, null, 2)}\n`);
  console.log(JSON.stringify(proof.summary, null, 2));
  console.log(`proof: ${path.relative(REPO_ROOT, PROOF_PATH)}`);
  for (const control of controls) {
    console.log(`${control.targetedGuardFired && control.nonZeroExit ? "BIT " : "MISS"} ${control.name} exit=${control.exitStatus} guards=${control.guardsFired.join(",")}`);
  }
  if (!proof.summary.allGuardsProvenRedCapable) process.exitCode = 1;
}

main();
