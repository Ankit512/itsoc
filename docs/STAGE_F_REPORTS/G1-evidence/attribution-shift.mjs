#!/usr/bin/env node
/**
 * G1 visual-delta ATTRIBUTION. The comparator's verdict is "VISUAL DELTA
 * PRESENT" on 44 of 48 states, which for an information-architecture card is
 * the expected result — but "expected" is a claim, and a claim about a tree
 * gets measured (GUARDRAILS.md 6).
 *
 * This script measures WHERE the delta comes from, per region:
 *
 *   sidebar   x <  SIDEBAR_W          the regrouped nav
 *   header    x >= SIDEBAR_W, y < H   the tightened top bar
 *   content   x >= SIDEBAR_W, y >= H  the page itself, which G1 does not touch
 *
 * and then tests one specific hypothesis about the content region: that it is
 * not redrawn at all, only TRANSLATED upward by the number of pixels the header
 * lost (min-height 58px -> 52px, padding 10px -> 8px). For each candidate shift
 * it re-compares the content region of `after` against `before` displaced by
 * that many rows. A shift that drives the content delta to (near) zero is
 * evidence that no page content changed; the whole-page bounds in the inventory
 * are the header height propagating downward.
 *
 * No npm dependency: the PNG decoder is the one already committed in the graded
 * G0 harness (docs/STAGE_F_REPORTS/G0-evidence/capture-visuals.mjs), copied
 * verbatim rather than reimplemented.
 *
 * Usage: node docs/STAGE_F_REPORTS/G1-evidence/attribution-shift.mjs
 *   G1_ATTR_IN   inventory to measure (default visual-diff-inventory.json)
 *   G1_ATTR_OUT  where to write the per-region measurement
 */
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { inflateSync } from "node:zlib";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "../../..");
const SIDEBAR_W = 224;   // .is-app grid-template-columns first track
const HEADER_H = 58;     // pre-G1 .is-top min-height; the taller of the two
const SHIFTS = [0, 2, 4, 6, 8];

function pngInfo(buffer) {
  const signature = "89504e470d0a1a0a";
  if (buffer.subarray(0, 8).toString("hex") !== signature) throw new Error("Not a PNG");
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
  return { ...info, rgba };
}

function load(rel) {
  return decodePng(readFileSync(path.join(REPO_ROOT, rel)));
}

/** Changed pixels inside [x0,x1) x [y0,y1), with `after` read `shift` rows up. */
function regionDelta(a, b, x0, x1, y0, y1, shift = 0) {
  let changed = 0;
  let compared = 0;
  for (let y = y0; y < y1; y += 1) {
    const ay = y + shift;
    if (ay < 0 || ay >= a.height) continue;
    for (let x = x0; x < x1; x += 1) {
      const ao = (ay * a.width + x) * 4;
      const bo = (y * b.width + x) * 4;
      compared += 1;
      if (a.rgba[ao] !== b.rgba[bo] || a.rgba[ao + 1] !== b.rgba[bo + 1]
          || a.rgba[ao + 2] !== b.rgba[bo + 2] || a.rgba[ao + 3] !== b.rgba[bo + 3]) changed += 1;
    }
  }
  return { changed, compared, ratio: compared ? changed / compared : 0 };
}

const INVENTORY_IN = process.env.G1_ATTR_IN ?? "visual-diff-inventory.json";
const ATTR_OUT = process.env.G1_ATTR_OUT ?? "visual-attribution-shift.json";
const inventory = JSON.parse(readFileSync(path.join(HERE, INVENTORY_IN), "utf8"));
const results = [];
for (const entry of inventory.entries) {
  if (entry.identical) continue;
  const before = load(entry.beforeFile);
  const after = load(entry.afterFile);
  if (before.width !== after.width || before.height !== after.height) throw new Error(`size mismatch ${entry.id}`);
  const { width: W, height: H } = before;

  const sidebar = regionDelta(after, before, 0, Math.min(SIDEBAR_W, W), 0, H);
  const header = regionDelta(after, before, SIDEBAR_W, W, 0, Math.min(HEADER_H, H));
  const contentByShift = {};
  for (const shift of SHIFTS) {
    contentByShift[shift] = regionDelta(after, before, SIDEBAR_W, W, HEADER_H, H, shift);
  }
  const best = SHIFTS.reduce((lo, s) => (contentByShift[s].changed < contentByShift[lo].changed ? s : lo), SHIFTS[0]);
  results.push({
    id: entry.id,
    route: entry.route,
    theme: entry.theme,
    changedPixelsWholeFrame: entry.changedPixels,
    sidebarRegion: sidebar,
    headerRegion: header,
    contentRegionByUpwardShift: contentByShift,
    contentBestShiftPx: best,
    contentResidualAtBestShift: contentByShift[best].changed,
    contentResidualRatioAtBestShift: contentByShift[best].ratio,
  });
  console.log(`${entry.id.padEnd(28)} whole=${String(entry.changedPixels).padStart(7)} sidebar=${String(sidebar.changed).padStart(6)} header=${String(header.changed).padStart(6)} content@0=${String(contentByShift[0].changed).padStart(7)} content@${best}=${String(contentByShift[best].changed).padStart(7)}`);
}

const shifts = results.map((r) => r.contentBestShiftPx);
const out = {
  schemaVersion: 1,
  kind: "itsoc-g1-visual-attribution",
  generatedAt: new Date().toISOString(),
  method: {
    sidebarRegion: `x < ${SIDEBAR_W}`,
    headerRegion: `x >= ${SIDEBAR_W} and y < ${HEADER_H}`,
    contentRegion: `x >= ${SIDEBAR_W} and y >= ${HEADER_H}`,
    shiftTest: `content region of 'after' re-compared against 'before' displaced upward by ${SHIFTS.join("/")} px`,
    decoder: "verbatim pngInfo/paeth/decodePng from docs/STAGE_F_REPORTS/G0-evidence/capture-visuals.mjs",
  },
  summary: {
    statesMeasured: results.length,
    contentBestShiftPxDistinct: [...new Set(shifts)].sort((a, b) => a - b),
    contentResidualTotalAtBestShift: results.reduce((n, r) => n + r.contentResidualAtBestShift, 0),
    contentChangedTotalAtZeroShift: results.reduce((n, r) => n + r.contentRegionByUpwardShift[0].changed, 0),
  },
  results,
};
writeFileSync(path.join(HERE, ATTR_OUT), `${JSON.stringify(out, null, 2)}\n`);
console.log(`\nwrote docs/STAGE_F_REPORTS/G1-evidence/${ATTR_OUT}`);
console.log(JSON.stringify(out.summary, null, 2));
