#!/usr/bin/env node

/**
 * Compare the G0 before ("baseline") and after ("after") production captures
 * and emit a machine-readable diff inventory plus one side-by-side sheet per
 * theme. No dependency: PNG decode/encode is done here, and the two capture
 * manifests supply the provenance both sides were photographed under.
 *
 * Usage:
 *   node docs/STAGE_F_REPORTS/G0-evidence/diff-visuals.mjs
 *
 * Exit status is 0 whether or not pixels moved -- the inventory is the report,
 * and a non-zero changed count is a finding to explain, not a crash.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { deflateSync, inflateSync } from "node:zlib";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const EVIDENCE_ROOT = path.dirname(SCRIPT_PATH);
const REPO_ROOT = path.resolve(EVIDENCE_ROOT, "../../..");
const BEFORE_LABEL = process.env.G0_BEFORE_LABEL ?? "baseline";
const AFTER_LABEL = process.env.G0_AFTER_LABEL ?? "after";
const OUT_DIR = path.join(EVIDENCE_ROOT, process.env.G0_DIFF_DIR ?? "diff");
const INVENTORY_PATH = path.join(EVIDENCE_ROOT, process.env.G0_INVENTORY ?? "visual-diff-inventory.json");

function sha256(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

/* ---------- PNG ---------- */

function pngInfo(buffer) {
  if (buffer.subarray(0, 8).toString("hex") !== "89504e470d0a1a0a") throw new Error("Not a PNG");
  return {
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20),
    bitDepth: buffer[24],
    colorType: buffer[25],
    interlace: buffer[28],
  };
}

function paeth(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  return pb <= pc ? b : c;
}

function decodePng(buffer) {
  const info = pngInfo(buffer);
  if (info.bitDepth !== 8 || info.interlace !== 0 || ![0, 2, 4, 6].includes(info.colorType)) {
    throw new Error(`Unsupported PNG layout: ${JSON.stringify(info)}`);
  }
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
  const channels = ({ 0: 1, 2: 3, 4: 2, 6: 4 })[info.colorType];
  const stride = info.width * channels;
  const scanlines = Buffer.alloc(info.height * stride);
  let rawOffset = 0;
  for (let y = 0; y < info.height; y += 1) {
    const filter = raw[rawOffset++];
    const rowOffset = y * stride;
    const priorOffset = rowOffset - stride;
    for (let x = 0; x < stride; x += 1) {
      const encoded = raw[rawOffset++];
      const left = x >= channels ? scanlines[rowOffset + x - channels] : 0;
      const up = y > 0 ? scanlines[priorOffset + x] : 0;
      const upperLeft = y > 0 && x >= channels ? scanlines[priorOffset + x - channels] : 0;
      let value;
      if (filter === 0) value = encoded;
      else if (filter === 1) value = encoded + left;
      else if (filter === 2) value = encoded + up;
      else if (filter === 3) value = encoded + Math.floor((left + up) / 2);
      else if (filter === 4) value = encoded + paeth(left, up, upperLeft);
      else throw new Error(`Unsupported PNG filter ${filter}`);
      scanlines[rowOffset + x] = value & 0xff;
    }
  }
  const rgba = Buffer.alloc(info.width * info.height * 4);
  for (let pixel = 0; pixel < info.width * info.height; pixel += 1) {
    const source = pixel * channels;
    const target = pixel * 4;
    if (info.colorType === 0 || info.colorType === 4) {
      rgba[target] = scanlines[source];
      rgba[target + 1] = scanlines[source];
      rgba[target + 2] = scanlines[source];
      rgba[target + 3] = info.colorType === 4 ? scanlines[source + 1] : 255;
    } else {
      rgba[target] = scanlines[source];
      rgba[target + 1] = scanlines[source + 1];
      rgba[target + 2] = scanlines[source + 2];
      rgba[target + 3] = info.colorType === 6 ? scanlines[source + 3] : 255;
    }
  }
  return { width: info.width, height: info.height, rgba };
}

function crc32(buffer) {
  let c;
  const table = crc32.table ?? (crc32.table = (() => {
    const t = new Int32Array(256);
    for (let n = 0; n < 256; n += 1) {
      c = n;
      for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c;
    }
    return t;
  })());
  let crc = -1;
  for (let i = 0; i < buffer.length; i += 1) crc = (crc >>> 8) ^ table[(crc ^ buffer[i]) & 0xff];
  return (crc ^ -1) >>> 0;
}

function chunk(type, data) {
  const out = Buffer.alloc(data.length + 12);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, "ascii");
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
}

function encodePng({ width, height, rgba }) {
  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y += 1) {
    raw[y * (stride + 1)] = 0; // filter: none
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from("89504e470d0a1a0a", "hex"),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

/* ---------- comparison ---------- */

function comparePixels(a, b) {
  if (a.width !== b.width || a.height !== b.height) {
    return { dimensionsMatch: false, before: `${a.width}x${a.height}`, after: `${b.width}x${b.height}` };
  }
  let changedPixels = 0;
  let maxChannelDelta = 0;
  let minX = a.width; let minY = a.height; let maxX = -1; let maxY = -1;
  const mask = Buffer.alloc(a.width * a.height);
  for (let pixel = 0; pixel < a.width * a.height; pixel += 1) {
    const o = pixel * 4;
    let delta = 0;
    for (let ch = 0; ch < 4; ch += 1) delta = Math.max(delta, Math.abs(a.rgba[o + ch] - b.rgba[o + ch]));
    if (delta !== 0) {
      changedPixels += 1;
      maxChannelDelta = Math.max(maxChannelDelta, delta);
      mask[pixel] = 1;
      const x = pixel % a.width;
      const y = Math.floor(pixel / a.width);
      minX = Math.min(minX, x); minY = Math.min(minY, y);
      maxX = Math.max(maxX, x); maxY = Math.max(maxY, y);
    }
  }
  return {
    dimensionsMatch: true,
    width: a.width,
    height: a.height,
    changedPixels,
    totalPixels: a.width * a.height,
    changedRatio: changedPixels / (a.width * a.height),
    maxChannelDelta,
    changedBounds: changedPixels ? { minX, minY, maxX, maxY } : null,
    mask,
  };
}

/* ---------- side-by-side sheet ---------- */

const GUTTER = 16;
const HEADER = 0;

function paste(target, targetW, source, ox, oy) {
  for (let y = 0; y < source.height; y += 1) {
    const from = y * source.width * 4;
    const to = ((oy + y) * targetW + ox) * 4;
    source.rgba.copy(target, to, from, from + source.width * 4);
  }
}

function sideBySide(pairs, background) {
  // One row per route: before | after. Equal viewport on both sides.
  const cellW = pairs[0].before.width;
  const cellH = pairs[0].before.height;
  const width = cellW * 2 + GUTTER * 3;
  const height = HEADER + pairs.length * (cellH + GUTTER) + GUTTER;
  const rgba = Buffer.alloc(width * height * 4);
  for (let i = 0; i < width * height; i += 1) {
    rgba[i * 4] = background[0];
    rgba[i * 4 + 1] = background[1];
    rgba[i * 4 + 2] = background[2];
    rgba[i * 4 + 3] = 255;
  }
  pairs.forEach((pair, index) => {
    const y = HEADER + GUTTER + index * (cellH + GUTTER);
    paste(rgba, width, pair.before, GUTTER, y);
    paste(rgba, width, pair.after, GUTTER * 2 + cellW, y);
  });
  return { width, height, rgba };
}

/* ---------- main ---------- */

function loadManifest(label) {
  const file = path.join(EVIDENCE_ROOT, `${label}-manifest.json`);
  if (!existsSync(file)) throw new Error(`Missing capture manifest: ${file}`);
  return JSON.parse(readFileSync(file, "utf8"));
}

function loadAnnotations() {
  const file = path.join(EVIDENCE_ROOT, process.env.G0_ANNOTATIONS ?? "diff-annotations.json");
  if (!existsSync(file)) return {};
  return JSON.parse(readFileSync(file, "utf8")).annotations ?? {};
}

function main() {
  const annotations = loadAnnotations();
  const before = loadManifest(BEFORE_LABEL);
  const after = loadManifest(AFTER_LABEL);

  // The two sides are only comparable if they were photographed the same way.
  const settingsMismatch = [];
  const cmp = (label, a, b) => {
    if (JSON.stringify(a) !== JSON.stringify(b)) settingsMismatch.push(`${label}: ${JSON.stringify(a)} vs ${JSON.stringify(b)}`);
  };
  cmp("viewport", before.captureSettings.viewport, after.captureSettings.viewport);
  cmp("locale", before.captureSettings.locale, after.captureSettings.locale);
  cmp("timezone", before.captureSettings.timezone, after.captureSettings.timezone);
  cmp("browser.version", before.captureSettings.browser.version, after.captureSettings.browser.version);
  cmp("colorProfile", before.captureSettings.browser.colorProfile, after.captureSettings.browser.colorProfile);
  cmp("detector.sha256", before.detector.sha256, after.detector.sha256);
  cmp("report.sha256", before.reportProvenance.report.sha256, after.reportProvenance.report.sha256);

  mkdirSync(OUT_DIR, { recursive: true });

  const beforeById = new Map(before.captures.map((c) => [c.id, c]));
  const afterById = new Map(after.captures.map((c) => [c.id, c]));
  const ids = [...new Set([...beforeById.keys(), ...afterById.keys()])].sort();

  const entries = [];
  const pairsByTheme = { light: [], dark: [] };

  for (const id of ids) {
    const b = beforeById.get(id);
    const a = afterById.get(id);
    if (!b || !a) {
      entries.push({ id, status: !b ? "only-in-after" : "only-in-before", route: (b ?? a).route, theme: (b ?? a).theme });
      continue;
    }
    const beforeBuf = readFileSync(path.join(REPO_ROOT, b.file));
    const afterBuf = readFileSync(path.join(REPO_ROOT, a.file));
    const beforeImg = decodePng(beforeBuf);
    const afterImg = decodePng(afterBuf);
    const result = comparePixels(beforeImg, afterImg);

    let diffFile = null;
    if (result.dimensionsMatch && result.changedPixels > 0) {
      // Paint the changed pixels red over a dimmed "after" so a reviewer can
      // see WHERE it moved, not just that it did.
      const overlay = Buffer.from(afterImg.rgba);
      for (let pixel = 0; pixel < result.totalPixels; pixel += 1) {
        const o = pixel * 4;
        if (result.mask[pixel]) {
          overlay[o] = 255; overlay[o + 1] = 0; overlay[o + 2] = 0; overlay[o + 3] = 255;
        } else {
          overlay[o] = (overlay[o] * 0.35) | 0;
          overlay[o + 1] = (overlay[o + 1] * 0.35) | 0;
          overlay[o + 2] = (overlay[o + 2] * 0.35) | 0;
        }
      }
      const rel = path.join(`docs/STAGE_F_REPORTS/G0-evidence/${process.env.G0_DIFF_DIR ?? "diff"}`, `${a.theme}-${path.basename(a.file)}`);
      writeFileSync(path.join(REPO_ROOT, rel), encodePng({ width: result.width, height: result.height, rgba: overlay }));
      diffFile = rel;
    }

    entries.push({
      id,
      route: b.route,
      state: b.state,
      theme: b.theme,
      beforeFile: b.file,
      afterFile: a.file,
      beforeSha256: b.sha256,
      afterSha256: a.sha256,
      beforeCommit: b.sourceCommit,
      afterCommit: a.sourceCommit,
      dimensionsMatch: result.dimensionsMatch,
      dimensions: result.dimensionsMatch ? `${result.width}x${result.height}` : null,
      changedPixels: result.changedPixels ?? null,
      totalPixels: result.totalPixels ?? null,
      changedRatio: result.changedRatio ?? null,
      maxChannelDelta: result.maxChannelDelta ?? null,
      changedBounds: result.changedBounds ?? null,
      identical: result.dimensionsMatch && result.changedPixels === 0,
      shaIdentical: b.sha256 === a.sha256,
      diffOverlay: diffFile,
      deliberateDelta: result.dimensionsMatch && result.changedPixels === 0 ? null : (annotations[id] ?? null),
      dynamicRegions: { before: b.dynamicRegions, after: a.dynamicRegions },
      stability: { before: b.consecutiveStability, after: a.consecutiveStability },
    });

    pairsByTheme[b.theme].push({ id, before: beforeImg, after: afterImg });
  }

  const sheets = {};
  for (const theme of ["light", "dark"]) {
    if (!pairsByTheme[theme].length) continue;
    const background = theme === "dark" ? [24, 24, 27] : [228, 228, 231];
    const sheet = sideBySide(pairsByTheme[theme], background);
    const rel = `docs/STAGE_F_REPORTS/G0-evidence/${process.env.G0_DIFF_DIR ?? "diff"}/side-by-side-${theme}.png`;
    const buf = encodePng(sheet);
    writeFileSync(path.join(REPO_ROOT, rel), buf);
    sheets[theme] = {
      file: rel,
      sha256: sha256(buf),
      layout: "one row per route state; left column = before, right column = after",
      rows: pairsByTheme[theme].map((p) => p.id),
      dimensions: `${sheet.width}x${sheet.height}`,
    };
  }

  const changed = entries.filter((e) => e.identical === false);
  const unexplained = changed.filter((e) => !e.deliberateDelta);
  const inventory = {
    schemaVersion: 1,
    kind: "itsoc-g0-visual-diff-inventory",
    generatedAt: new Date().toISOString(),
    comparison: {
      before: { label: BEFORE_LABEL, commit: before.source.commit, manifest: `docs/STAGE_F_REPORTS/G0-evidence/${BEFORE_LABEL}-manifest.json` },
      after: { label: AFTER_LABEL, commit: after.source.commit, manifest: `docs/STAGE_F_REPORTS/G0-evidence/${AFTER_LABEL}-manifest.json` },
      captureSettingsMatch: settingsMismatch.length === 0,
      captureSettingsMismatches: settingsMismatch,
      viewport: before.captureSettings.viewport,
      sameRunData: before.reportProvenance.report.sha256 === after.reportProvenance.report.sha256,
      reportSha256: before.reportProvenance.report.sha256,
      productionRuntime: {
        before: { server: before.productionRuntime.serverImplementation, mockedApi: before.productionRuntime.mockedApi, mockup: before.productionRuntime.mockup },
        after: { server: after.productionRuntime.serverImplementation, mockedApi: after.productionRuntime.mockedApi, mockup: after.productionRuntime.mockup },
      },
    },
    summary: {
      routeStatesCompared: entries.length,
      themes: ["light", "dark"],
      identical: entries.filter((e) => e.identical).length,
      changed: changed.length,
      byteIdenticalPngs: entries.filter((e) => e.shaIdentical).length,
      totalChangedPixels: entries.reduce((sum, e) => sum + (e.changedPixels ?? 0), 0),
      deliberateDeltas: entries.filter((e) => e.deliberateDelta).length,
      unexplainedChanged: unexplained.length,
      verdict: unexplained.length === 0
        ? (changed.length === 0
            ? "ZERO VISUAL DELTA"
            : "ZERO VISUAL DELTA ATTRIBUTABLE TO THE CHANGE — every changed state is annotated with control evidence")
        : "VISUAL DELTA PRESENT — see entries[].changedBounds",
    },
    sideBySide: sheets,
    entries,
  };

  writeFileSync(INVENTORY_PATH, `${JSON.stringify(inventory, null, 2)}\n`);
  console.log(JSON.stringify(inventory.summary, null, 2));
  console.log(`inventory: ${path.relative(REPO_ROOT, INVENTORY_PATH)}`);
  for (const e of changed) {
    const tag = e.deliberateDelta ? "ANNOTATED" : "UNEXPLAINED";
    console.log(`${tag} ${e.id} route=${e.route} pixels=${e.changedPixels} bounds=${JSON.stringify(e.changedBounds)}`);
  }
}

main();
