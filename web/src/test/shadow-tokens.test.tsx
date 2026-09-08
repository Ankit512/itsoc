// @ts-expect-error node:fs type declarations not included in browser tsconfig
import fs from "node:fs";
// @ts-expect-error node:path type declarations not included in browser tsconfig
import path from "node:path";
// @ts-expect-error node:url type declarations not included in browser tsconfig
import { fileURLToPath } from "node:url";

import postcss, { type Rule } from "postcss";
import { describe, it, expect } from "vitest";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const srcRoot = path.resolve(__dirname, "..");

/**
 * Elevation must come from a theme-aware token, never a literal.
 *
 * A hardcoded shadow is authored against exactly one theme and is wrong in the
 * other: a navy `rgba(26,32,51,…)` disappears on a dark ground, and a black
 * `rgba(0,0,0,…)` reads as a smudge on a light one. Both directions existed in
 * this tree before this guard. Canonical `--elevation-*` roles are defined in
 * both themes; legacy `--shadow*` names are one-way compatibility aliases.
 *
 * Exemption: `inset` shadows are used as ring/fill affordances (e.g. the radio
 * dot), take their colour from a token already, and are not elevation.
 */

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === "dist") continue;
      out.push(...walk(full));
    } else if (/\.(tsx?|css)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

function selectorParts(selector: string): string[] {
  return selector.split(",").map((part) => part.replace(/\s+/g, "").trim());
}

function themeTokenValues(css: string, token: string, theme: "dark" | "light"): string[] {
  const values: string[] = [];
  postcss.parse(css).walkDecls(token, (decl) => {
    if (decl.parent?.type !== "rule") return;
    const selectors = selectorParts((decl.parent as Rule).selector);
    if (selectors.includes(`[data-theme="${theme}"]`)) values.push(decl.value.trim());
  });
  return values;
}

function tokenOccurrences(css: string, token: string): string[] {
  const values: string[] = [];
  postcss.parse(css).walkDecls(token, (decl) => {
    values.push(decl.value.trim());
  });
  return values;
}

describe("Elevation is tokenised, in both themes", () => {
  const files = walk(srcRoot).filter((f) => !f.includes(`${path.sep}test${path.sep}`));

  it("finds source files to scan (guards against a silently empty sweep)", () => {
    expect(files.length).toBeGreaterThan(20);
  });

  it("no source file hardcodes a box-shadow colour", () => {
    const offenders: string[] = [];

    for (const file of files) {
      const lines: string[] = fs.readFileSync(file, "utf-8").split("\n");
      lines.forEach((line: string, i: number) => {
        if (line.includes("inset")) return;

        // CSS: `box-shadow: 0 8px 24px rgba(...)` / `#abc`
        const css = /box-shadow\s*:\s*[^;]*(rgba?\(|#[0-9a-fA-F]{3})/.exec(line);
        // Tailwind arbitrary value: `shadow-[0_8px_24px_rgba(...)]`
        const tw = /shadow-\[[^\]]*(rgba?\(|%23|#[0-9a-fA-F]{3})/.exec(line);

        if (css || tw) {
          offenders.push(
            `${path.relative(srcRoot, file)}:${i + 1} — ${line.trim().slice(0, 120)}`,
          );
        }
      });
    }

    expect(
      offenders,
      `Hardcoded shadow colour(s). Use var(--shadow), var(--shadow-pop) or ` +
        `var(--shadow-modal) — each is defined in both theme blocks:\n${offenders.join("\n")}`,
    ).toEqual([]);
  });

  it("no non-inset component shadow bypasses the shared elevation/focus token scale", () => {
    const offenders: string[] = [];

    for (const file of files) {
      const lines: string[] = fs.readFileSync(file, "utf-8").split("\n");
      lines.forEach((line: string, i: number) => {
        const cssMatch = /box-shadow\s*:\s*([^;}]*)/.exec(line);
        if (cssMatch && !cssMatch[1].includes("inset")) {
          const value = cssMatch[1].trim();
          if (!/^var\(\s*--(?:elevation-|shadow|focus-ring|tour-glow)/.test(value) && value !== "none") {
            offenders.push(`${path.relative(srcRoot, file)}:${i + 1} — ${value}`);
          }
        }

        for (const match of line.matchAll(/shadow-\[([^\]]+)\]/g)) {
          if (!/^var\(--(?:elevation-|shadow|focus-ring)/.test(match[1])) {
            offenders.push(`${path.relative(srcRoot, file)}:${i + 1} — ` + "shadow-[" + match[1] + "]");
          }
        }
      });
    }

    expect(
      offenders,
      `Shadow geometry must resolve through the shared elevation/focus scale:\n${offenders.join("\n")}`,
    ).toEqual([]);
  });

  it("every elevation token is defined in both the light and the dark block", () => {
    const indexCss = fs.readFileSync(path.join(srcRoot, "index.css"), "utf-8");
    const itsocCss = fs.readFileSync(path.join(srcRoot, "styles/itsoc.css"), "utf-8");

    // Preserve the pre-G0 assertion until the canonical roles land. The new
    // ownership test below makes this compatibility branch insufficient on
    // its own, while keeping the original guard demonstrably intact.
    if (tokenOccurrences(itsocCss, "--elevation-card").length === 0) {
      for (const token of ["--shadow", "--shadow-pop", "--shadow-modal"]) {
        expect(
          tokenOccurrences(indexCss, token),
          `${token} must be defined twice in index.css (light + dark)`,
        ).toHaveLength(2);
      }
      expect(
        tokenOccurrences(itsocCss, "--shadow"),
        "--shadow must be defined twice in itsoc.css (light + dark)",
      ).toHaveLength(2);
      return;
    }

    for (const token of [
      "--elevation-card",
      "--elevation-popover",
      "--elevation-modal",
      "--elevation-rail",
      "--elevation-fab",
      "--focus-ring",
    ]) {
      expect(themeTokenValues(itsocCss, token, "dark"), `${token} dark ownership`).toHaveLength(1);
      expect(themeTokenValues(itsocCss, token, "light"), `${token} light ownership`).toHaveLength(1);
    }
  });

  it("gives legacy shadow aliases one authoritative owner", () => {
    const indexCss = fs.readFileSync(path.join(srcRoot, "index.css"), "utf-8");
    const itsocCss = fs.readFileSync(path.join(srcRoot, "styles/itsoc.css"), "utf-8");

    for (const [legacy, canonical] of [
      ["--shadow", "--elevation-card"],
      ["--shadow-pop", "--elevation-popover"],
      ["--shadow-modal", "--elevation-modal"],
    ] as const) {
      expect(tokenOccurrences(itsocCss, legacy), `${legacy} must be a single compatibility alias`).toEqual([
        `var(${canonical})`,
      ]);
      expect(tokenOccurrences(indexCss, legacy), `${legacy} must not have a competing index.css owner`).toEqual([]);
    }
  });
});
