// @ts-expect-error node:fs type declarations not included in browser tsconfig
import fs from "node:fs";
// @ts-expect-error node:path type declarations not included in browser tsconfig
import path from "node:path";
// @ts-expect-error node:url type declarations not included in browser tsconfig
import { fileURLToPath } from "node:url";

import { describe, it, expect } from "vitest";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const srcRoot = path.resolve(__dirname, "..");

/**
 * Elevation must come from a theme-aware token, never a literal.
 *
 * A hardcoded shadow is authored against exactly one theme and is wrong in the
 * other: a navy `rgba(26,32,51,…)` disappears on a dark ground, and a black
 * `rgba(0,0,0,…)` reads as a smudge on a light one. Both directions existed in
 * this tree before this guard. `--shadow` / `--shadow-pop` / `--shadow-modal`
 * are each defined in both theme blocks, so a token is correct in either.
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

  it("every elevation token is defined in both the light and the dark block", () => {
    const indexCss = fs.readFileSync(path.join(srcRoot, "index.css"), "utf-8");
    const itsocCss = fs.readFileSync(path.join(srcRoot, "styles/itsoc.css"), "utf-8");

    // index.css: shadcn/Tailwind layer. itsoc.css: the is-* shell.
    for (const tok of ["--shadow", "--shadow-pop", "--shadow-modal"]) {
      const hits = indexCss.split(`${tok}:`).length - 1;
      expect(hits, `${tok} must be defined twice in index.css (light + dark)`).toBe(2);
    }
    const itsocHits = itsocCss.split("--shadow:").length - 1;
    expect(itsocHits, "--shadow must be defined twice in itsoc.css (light + dark)").toBe(2);
  });
});
