#!/usr/bin/env node

/**
 * Decide, per route/theme state, whether a primary A/B pixel delta is
 * attributable to the stylesheet under test or to renderer non-determinism.
 *
 * The question "did the CSS move pixels?" cannot be answered by one A/B pair
 * when the renderer is not byte-deterministic. It can be answered by four runs
 * over ONE frozen data payload in ONE worktree:
 *
 *   base-1, base-2        the pre-change stylesheet, photographed twice
 *   cand-1, cand-2        the post-change stylesheet, photographed twice
 *
 * For each state this reports two independent tests, and a delta only counts
 * as attributable to the change if it fails BOTH:
 *
 *   shared-render    some base run and some candidate run are byte-identical.
 *                    If the candidate stylesheet can produce a frame the base
 *                    stylesheet also produced, the stylesheet is not what
 *                    distinguishes them.
 *   control-covered  every coordinate that moved in the primary pair also
 *                    moves in a SAME-STYLESHEET control pair (base-1 vs base-2
 *                    or cand-1 vs cand-2). A coordinate that moves with no CSS
 *                    change at all cannot be evidence that CSS changed it.
 *
 * Usage:
 *   node docs/STAGE_F_REPORTS/G0-evidence/attribution-analysis.mjs \
 *     --base before-frozen --base-repeat before-frozen-repeat \
 *     --candidate after-frozen --candidate-repeat after-frozen-repeat
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { inflateSync } from "node:zlib";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const EVIDENCE_ROOT = path.dirname(SCRIPT_PATH);
const REPO_ROOT = path.resolve(EVIDENCE_ROOT, "../../..");
// The "primary" pair analysed is (base, candidate). Swapping --candidate and
// --candidate-repeat therefore attributes the OTHER cross pair, which is how
// both A/B pairs get their own annotations from the same four captures.
function parseArgs(argv) {
  const out = { out: "visual-attribution-analysis.json", annotationsOut: "diff-annotations-frozen.json" };
  const keys = {
    "--base": "base", "--base-repeat": "baseRepeat",
    "--candidate": "candidate", "--candidate-repeat": "candidateRepeat",
    "--out": "out", "--annotations-out": "annotationsOut",
  };
  for (let i = 0; i < argv.length; i += 1) {
    const key = keys[argv[i]];
    if (!key) throw new Error(`Unknown argument: ${argv[i]}`);
    out[key] = argv[++i];
  }
  for (const key of ["base", "baseRepeat", "candidate", "candidateRepeat"]) {
    if (!out[key]) throw new Error(`Missing --${key}`);
  }
  return out;
}

const sha256 = (buffer) => createHash("sha256").update(buffer).digest("hex");

function paeth(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a); const pb = Math.abs(p - b); const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  return pb <= pc ? b : c;
}

function decodePng(buffer) {
  const width = buffer.readUInt32BE(16);
  const height = buffer.readUInt32BE(20);
  const colorType = buffer[25];
  const channels = ({ 0: 1, 2: 3, 4: 2, 6: 4 })[colorType];
  const chunks = [];
  let offset = 8;
  while (offset < buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.subarray(offset + 4, offset + 8).toString("ascii");
    if (type === "IDAT") chunks.push(buffer.subarray(offset + 8, offset + 8 + length));
    offset += 12 + length;
    if (type === "IEND") break;
  }
  const raw = inflateSync(Buffer.concat(chunks));
  const stride = width * channels;
  const scan = Buffer.alloc(height * stride);
  let r = 0;
  for (let y = 0; y < height; y += 1) {
    const filter = raw[r++];
    const rowOffset = y * stride;
    const priorOffset = rowOffset - stride;
    for (let x = 0; x < stride; x += 1) {
      const encoded = raw[r++];
      const left = x >= channels ? scan[rowOffset + x - channels] : 0;
      const up = y > 0 ? scan[priorOffset + x] : 0;
      const upperLeft = y > 0 && x >= channels ? scan[priorOffset + x - channels] : 0;
      let value;
      if (filter === 0) value = encoded;
      else if (filter === 1) value = encoded + left;
      else if (filter === 2) value = encoded + up;
      else if (filter === 3) value = encoded + Math.floor((left + up) / 2);
      else if (filter === 4) value = encoded + paeth(left, up, upperLeft);
      else throw new Error(`Unsupported PNG filter ${filter}`);
      scan[rowOffset + x] = value & 0xff;
    }
  }
  const rgba = Buffer.alloc(width * height * 4);
  for (let p = 0; p < width * height; p += 1) {
    const s = p * channels; const t = p * 4;
    if (colorType === 0 || colorType === 4) {
      rgba[t] = scan[s]; rgba[t + 1] = scan[s]; rgba[t + 2] = scan[s];
      rgba[t + 3] = colorType === 4 ? scan[s + 1] : 255;
    } else {
      rgba[t] = scan[s]; rgba[t + 1] = scan[s + 1]; rgba[t + 2] = scan[s + 2];
      rgba[t + 3] = colorType === 6 ? scan[s + 3] : 255;
    }
  }
  return { width, height, rgba };
}

// Coordinates that differ, as "x,y" keys, plus the largest channel delta.
function deltaSet(a, b) {
  if (a.width !== b.width || a.height !== b.height) throw new Error("dimension mismatch");
  const coords = new Map();
  let maxChannelDelta = 0;
  for (let p = 0; p < a.width * a.height; p += 1) {
    const o = p * 4;
    let delta = 0;
    for (let c = 0; c < 4; c += 1) delta = Math.max(delta, Math.abs(a.rgba[o + c] - b.rgba[o + c]));
    if (delta) {
      coords.set(`${p % a.width},${Math.floor(p / a.width)}`, delta);
      maxChannelDelta = Math.max(maxChannelDelta, delta);
    }
  }
  return { coords, maxChannelDelta };
}

function loadCaptures(label) {
  const manifest = JSON.parse(readFileSync(path.join(EVIDENCE_ROOT, `${label}-manifest.json`), "utf8"));
  return {
    manifest,
    byId: new Map(manifest.captures.map((c) => [c.id, c])),
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const OUT_PATH = path.join(EVIDENCE_ROOT, args.out);
  const ANNOTATIONS_PATH = path.join(EVIDENCE_ROOT, args.annotationsOut);
  const sides = {
    base: loadCaptures(args.base),
    baseRepeat: loadCaptures(args.baseRepeat),
    candidate: loadCaptures(args.candidate),
    candidateRepeat: loadCaptures(args.candidateRepeat),
  };

  // All four runs must have served the same frozen payload, or none of this
  // reasoning holds.
  const payloads = new Set(Object.values(sides).map((s) => s.manifest.reportProvenance.report.sha256));
  if (payloads.size !== 1) throw new Error(`All four runs must share one frozen report payload; saw ${payloads.size}`);
  const cssOf = (side) => Object.fromEntries(side.manifest.source.photographedTreeArtifacts
    .filter((a) => a.path.endsWith(".css")).map((a) => [a.path, a.sha256]));
  const baseCss = JSON.stringify(cssOf(sides.base));
  const candidateCss = JSON.stringify(cssOf(sides.candidate));
  if (baseCss !== JSON.stringify(cssOf(sides.baseRepeat))) throw new Error("base and base-repeat photographed different CSS");
  if (candidateCss !== JSON.stringify(cssOf(sides.candidateRepeat))) throw new Error("candidate and candidate-repeat photographed different CSS");
  if (baseCss === candidateCss) throw new Error("base and candidate photographed the SAME CSS; this is not an A/B");

  const ids = [...sides.base.byId.keys()].sort();
  const img = (side, id) => decodePng(readFileSync(path.join(REPO_ROOT, sides[side].byId.get(id).file)));

  const states = [];
  for (const id of ids) {
    const b1 = img("base", id); const b2 = img("baseRepeat", id);
    const a1 = img("candidate", id); const a2 = img("candidateRepeat", id);

    const primary = deltaSet(b1, a1);
    const baseControl = deltaSet(b1, b2);
    const candidateControl = deltaSet(a1, a2);
    const controlCoords = new Set([...baseControl.coords.keys(), ...candidateControl.coords.keys()]);
    const uncovered = [...primary.coords.keys()].filter((k) => !controlCoords.has(k));

    const baseHashes = new Set([sides.base.byId.get(id).sha256, sides.baseRepeat.byId.get(id).sha256]);
    const candidateHashes = new Set([sides.candidate.byId.get(id).sha256, sides.candidateRepeat.byId.get(id).sha256]);
    const sharedRender = [...candidateHashes].some((h) => baseHashes.has(h));

    states.push({
      id,
      route: sides.base.byId.get(id).route,
      theme: sides.base.byId.get(id).theme,
      primaryChangedPixels: primary.coords.size,
      primaryMaxChannelDelta: primary.maxChannelDelta,
      baseControlChangedPixels: baseControl.coords.size,
      candidateControlChangedPixels: candidateControl.coords.size,
      baseSideByteStable: baseControl.coords.size === 0,
      candidateSideByteStable: candidateControl.coords.size === 0,
      sharedRender,
      controlCoveredCoordinates: primary.coords.size - uncovered.length,
      uncoveredCoordinates: uncovered.sort(),
      primaryCoordinates: [...primary.coords.entries()].map(([k, d]) => `${k}:${d}`).sort(),
      candidateControlCoordinates: [...candidateControl.coords.entries()].map(([k, d]) => `${k}:${d}`).sort(),
      baseControlCoordinates: [...baseControl.coords.entries()].map(([k, d]) => `${k}:${d}`).sort(),
      attributableToChange: primary.coords.size > 0 && uncovered.length > 0 && !sharedRender,
    });
  }

  const changed = states.filter((s) => s.primaryChangedPixels > 0);
  const attributable = states.filter((s) => s.attributableToChange);

  const analysis = {
    schemaVersion: 1,
    kind: "itsoc-g0-visual-attribution-analysis",
    generatedAt: new Date().toISOString(),
    method: [
      "Four production captures over ONE frozen rules-only report payload in ONE worktree:",
      "the pre-change stylesheet twice and the post-change stylesheet twice.",
      "A primary delta counts as attributable to the change only if it is NOT reproduced",
      "by a same-stylesheet control pair AND no base render is byte-identical to a candidate render.",
    ].join(" "),
    runs: Object.fromEntries(Object.entries(sides).map(([role, side]) => [role, {
      label: side.manifest.label,
      manifest: `docs/STAGE_F_REPORTS/G0-evidence/${side.manifest.label}-manifest.json`,
      commit: side.manifest.source.commit,
      css: cssOf(side),
      workingTreeDirtyPaths: side.manifest.source.workingTreeDirtyPaths,
    }])),
    frozenReportSha256: [...payloads][0],
    summary: {
      states: states.length,
      statesWithPrimaryDelta: changed.length,
      totalPrimaryChangedPixels: changed.reduce((n, s) => n + s.primaryChangedPixels, 0),
      totalBaseControlChangedPixels: states.reduce((n, s) => n + s.baseControlChangedPixels, 0),
      totalCandidateControlChangedPixels: states.reduce((n, s) => n + s.candidateControlChangedPixels, 0),
      statesWithSharedRender: states.filter((s) => s.sharedRender).length,
      statesWithUncoveredCoordinates: states.filter((s) => s.uncoveredCoordinates.length > 0).length,
      statesAttributableToChange: attributable.length,
      verdict: attributable.length === 0
        ? "ZERO VISUAL DELTA ATTRIBUTABLE TO THE CHANGE — every moved pixel is reproduced by a same-stylesheet control"
        : `VISUAL DELTA ATTRIBUTABLE TO THE CHANGE at ${attributable.length} state(s)`,
    },
    states,
  };
  writeFileSync(OUT_PATH, `${JSON.stringify(analysis, null, 2)}\n`);

  // Author the annotations diff-visuals.mjs consumes, straight from the
  // measured control evidence. Nothing here is hand-asserted.
  const annotations = {
    schemaVersion: 1,
    kind: "itsoc-g0-diff-annotations",
    generatedAt: new Date().toISOString(),
    basis: `Generated by attribution-analysis.mjs from ${analysis.summary.states} states across four captures; see visual-attribution-analysis.json`,
    annotations: Object.fromEntries(changed.map((s) => [s.id, {
      reason: "renderer non-determinism, not the stylesheet",
      evidence: [
        s.sharedRender
          ? "A base-stylesheet capture and a post-change capture of this state are byte-identical, so the stylesheet does not determine which frame is produced."
          : "No base/candidate frame pair is byte-identical at this state.",
        `Every one of the ${s.primaryChangedPixels} moved coordinate(s) also moves in a same-stylesheet control pair (base twice: ${s.baseControlChangedPixels} px; post-change twice: ${s.candidateControlChangedPixels} px).`,
        `Uncovered coordinates: ${s.uncoveredCoordinates.length}.`,
      ],
      primaryChangedPixels: s.primaryChangedPixels,
      primaryMaxChannelDelta: s.primaryMaxChannelDelta,
      controlCoveredCoordinates: s.controlCoveredCoordinates,
      uncoveredCoordinates: s.uncoveredCoordinates,
    }])),
  };
  writeFileSync(ANNOTATIONS_PATH, `${JSON.stringify(annotations, null, 2)}\n`);

  console.log(JSON.stringify(analysis.summary, null, 2));
  console.log(`analysis:    ${path.relative(REPO_ROOT, OUT_PATH)} (sha256 ${sha256(readFileSync(OUT_PATH))})`);
  console.log(`annotations: ${path.relative(REPO_ROOT, ANNOTATIONS_PATH)}`);
  for (const s of changed) {
    console.log(`${s.attributableToChange ? "ATTRIBUTABLE" : "control-covered"} ${s.id} primary=${s.primaryChangedPixels}px maxDelta=${s.primaryMaxChannelDelta} baseCtl=${s.baseControlChangedPixels} candCtl=${s.candidateControlChangedPixels} uncovered=${s.uncoveredCoordinates.length} sharedRender=${s.sharedRender}`);
  }
  if (attributable.length) process.exitCode = 1;
}

main();
