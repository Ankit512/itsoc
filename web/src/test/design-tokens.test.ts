// @ts-expect-error node:fs type declarations are not included in the browser tsconfig
import fs from "node:fs";
// @ts-expect-error node:path type declarations are not included in the browser tsconfig
import path from "node:path";
// @ts-expect-error node:url type declarations are not included in the browser tsconfig
import { fileURLToPath } from "node:url";

import postcss, { type Declaration, type Rule } from "postcss";
import { describe, expect, it } from "vitest";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const srcRoot = path.resolve(__dirname, "..");
const webRoot = path.resolve(srcRoot, "..");
const tokenOwnerPath = path.join(srcRoot, "styles/itsoc.css");
const tailwindAdapterPath = path.join(srcRoot, "index.css");
const tailwindConfigPath = path.join(webRoot, "tailwind.config.ts");

type TokenDeclaration = {
  file: string;
  line: number;
  name: string;
  selector: string;
  value: string;
};

const REQUIRED_THEME_ROLES = [
  "--surface-canvas",
  "--surface-panel",
  "--surface-raised",
  "--surface-recessed",
  "--surface-track",
  "--data-fill-neutral",
  "--border-subtle",
  "--border-strong",
  "--border-input",
  "--text-primary",
  "--text-secondary",
  "--text-muted",
  "--text-faint",
  "--text-on-action",
  "--text-on-danger",
  "--text-on-severity",
  "--action-primary",
  "--action-primary-subtle",
  "--control-selected",
  "--text-on-selected",
  "--focus-ring-color",
  "--severity-critical",
  "--severity-high",
  "--severity-medium",
  "--severity-low",
  "--severity-info",
  "--status-success",
  "--status-warning",
  "--status-danger",
  "--elevation-card",
  "--elevation-popover",
  "--elevation-modal",
  "--elevation-rail",
  "--elevation-fab",
  "--focus-ring",
] as const;

const REQUIRED_CHANNELS = [
  "--surface-canvas-hsl",
  "--surface-panel-hsl",
  "--surface-raised-hsl",
  "--text-primary-hsl",
  "--text-on-action-hsl",
  "--control-selected-hsl",
  "--text-on-selected-hsl",
  "--border-subtle-hsl",
  "--border-input-hsl",
  "--compat-action-primary-hsl",
  "--compat-text-muted-hsl",
] as const;

const LEGACY_ALIASES = {
  "--bg": "--surface-canvas",
  "--pan": "--surface-panel",
  "--pan2": "--surface-raised",
  "--inset": "--surface-recessed",
  "--track": "--surface-track",
  "--fill": "--data-fill-neutral",
  "--bd": "--border-subtle",
  "--bd2": "--border-strong",
  "--ink": "--text-primary",
  "--ink2": "--text-secondary",
  "--mut": "--text-muted",
  "--mut2": "--text-faint",
  "--acc": "--action-primary",
  "--acc-ink": "--text-on-action",
  "--acc-weak": "--action-primary-subtle",
  "--crit": "--severity-critical",
  "--sev-critical": "--severity-critical",
  "--high": "--severity-high",
  "--sev-high": "--severity-high",
  "--med": "--severity-medium",
  "--sev-medium": "--severity-medium",
  "--low": "--severity-low",
  "--sev-low": "--severity-low",
  "--info": "--severity-info",
  "--ok": "--status-success",
  "--warn": "--status-warning",
  "--danger": "--status-danger",
  "--radius": "--shape-radius-sm",
  "--radius-sm": "--shape-radius-sm",
  "--radius-xs": "--shape-radius-xs",
  "--shadow": "--elevation-card",
  "--shadow-pop": "--elevation-popover",
  "--shadow-modal": "--elevation-modal",
  "--mono": "--font-family-mono",
  "--sans": "--font-family-sans",
} as const;

const TAILWIND_HSL_ADAPTERS = {
  "--background": "--surface-canvas-hsl",
  "--foreground": "--text-primary-hsl",
  "--card": "--surface-panel-hsl",
  "--card-foreground": "--text-primary-hsl",
  "--muted": "--surface-raised-hsl",
  "--muted-foreground": "--compat-text-muted-hsl",
  "--primary": "--compat-action-primary-hsl",
  "--primary-foreground": "--text-on-action-hsl",
  "--accent": "--control-selected-hsl",
  "--accent-foreground": "--text-on-selected-hsl",
  "--border": "--border-subtle-hsl",
  "--input": "--border-input-hsl",
  "--ring": "--compat-action-primary-hsl",
} as const;

const CANONICAL_THEME_PREFIXES = [
  "--surface-",
  "--data-fill-",
  "--border-",
  "--text-",
  "--action-",
  "--control-",
  "--focus-ring",
  "--severity-",
  "--status-",
  "--elevation-",
  "--compat-",
] as const;

function read(file: string): string {
  return fs.readFileSync(file, "utf-8");
}

function selectorOf(decl: Declaration): string {
  return decl.parent?.type === "rule" ? (decl.parent as Rule).selector : "";
}

function tokenDeclarations(css: string, file: string): TokenDeclaration[] {
  const declarations: TokenDeclaration[] = [];
  postcss.parse(css, { from: file }).walkDecls(/^--/, (decl) => {
    declarations.push({
      file,
      line: decl.source?.start?.line ?? 0,
      name: decl.prop,
      selector: selectorOf(decl),
      value: decl.value.trim(),
    });
  });
  return declarations;
}

function selectorParts(selector: string): string[] {
  return selector.split(",").map((part) => part.replace(/\s+/g, "").trim());
}

function isGlobal(decl: TokenDeclaration): boolean {
  return selectorParts(decl.selector).some(
    (part) =>
      part === ":root" ||
      part === ".dark" ||
      part === '[data-theme="dark"]' ||
      part === '[data-theme="light"]',
  );
}

function isTheme(decl: TokenDeclaration, theme: "dark" | "light"): boolean {
  return selectorParts(decl.selector).includes(`[data-theme="${theme}"]`);
}

function isBareRoot(decl: TokenDeclaration): boolean {
  const parts = selectorParts(decl.selector);
  return parts.length === 1 && parts[0] === ":root";
}

function groupByName(declarations: TokenDeclaration[]): Map<string, TokenDeclaration[]> {
  const grouped = new Map<string, TokenDeclaration[]>();
  for (const decl of declarations) {
    grouped.set(decl.name, [...(grouped.get(decl.name) ?? []), decl]);
  }
  return grouped;
}

function varTargets(value: string): string[] {
  return [...value.matchAll(/var\(\s*(--[a-zA-Z0-9_-]+)/g)].map((match) => match[1]);
}

function singleAliasTarget(value: string): string | undefined {
  return /^var\(\s*(--[a-zA-Z0-9_-]+)\s*\)$/.exec(value)?.[1];
}

function isCanonicalThemeName(name: string): boolean {
  return CANONICAL_THEME_PREFIXES.some((prefix) => name.startsWith(prefix));
}

function findCycles(graph: Map<string, Set<string>>): string[] {
  const cycles = new Set<string>();
  const visited = new Set<string>();
  const active = new Set<string>();
  const stack: string[] = [];

  const visit = (node: string) => {
    if (active.has(node)) {
      const start = stack.indexOf(node);
      cycles.add([...stack.slice(start), node].join(" -> "));
      return;
    }
    if (visited.has(node)) return;

    active.add(node);
    stack.push(node);
    for (const target of graph.get(node) ?? []) {
      if (graph.has(target)) visit(target);
    }
    stack.pop();
    active.delete(node);
    visited.add(node);
  };

  for (const node of graph.keys()) visit(node);
  return [...cycles].sort();
}

function hasPath(graph: Map<string, Set<string>>, from: string, to: string): boolean {
  const pending = [from];
  const visited = new Set<string>();
  while (pending.length) {
    const node = pending.pop()!;
    if (node === to) return true;
    if (visited.has(node)) continue;
    visited.add(node);
    pending.push(...(graph.get(node) ?? []));
  }
  return false;
}

function walk(dir: string, extensions: RegExp): string[] {
  const files: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === "dist" || entry.name === "test") continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...walk(full, extensions));
    else if (extensions.test(entry.name)) files.push(full);
  }
  return files;
}

function stripSourceComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

function lineAt(source: string, index: number): number {
  return source.slice(0, index).split("\n").length;
}

const tokenOwnerCss = read(tokenOwnerPath);
const tailwindAdapterCss = read(tailwindAdapterPath);
const tailwindConfig = read(tailwindConfigPath);
const ownerDeclarations = tokenDeclarations(tokenOwnerCss, tokenOwnerPath);
const adapterDeclarations = tokenDeclarations(tailwindAdapterCss, tailwindAdapterPath);
const allDeclarations = [...ownerDeclarations, ...adapterDeclarations];
const globalDeclarations = allDeclarations.filter(isGlobal);
const globalByName = groupByName(globalDeclarations);

function dependencyGraph(): Map<string, Set<string>> {
  const graph = new Map<string, Set<string>>();
  for (const decl of globalDeclarations) {
    const targets = graph.get(decl.name) ?? new Set<string>();
    for (const target of varTargets(decl.value)) targets.add(target);
    graph.set(decl.name, targets);
  }
  return graph;
}

describe("G0 semantic design-token source contract", () => {
  it("defines the complete canonical role set exactly once in both themes", () => {
    const dark = ownerDeclarations.filter((decl) => isTheme(decl, "dark") && isCanonicalThemeName(decl.name));
    const light = ownerDeclarations.filter((decl) => isTheme(decl, "light") && isCanonicalThemeName(decl.name));
    const darkByName = groupByName(dark);
    const lightByName = groupByName(light);
    const darkNames = [...darkByName.keys()].sort();
    const lightNames = [...lightByName.keys()].sort();
    const required = [...REQUIRED_THEME_ROLES, ...REQUIRED_CHANNELS];
    const errors: string[] = [];

    if (darkNames.length === 0) errors.push("dark canonical role set is empty");
    if (lightNames.length === 0) errors.push("light canonical role set is empty");
    for (const name of required) {
      if (!darkByName.has(name)) errors.push(`${name} missing from dark theme`);
      if (!lightByName.has(name)) errors.push(`${name} missing from light theme`);
    }
    for (const [name, declarations] of darkByName) {
      if (declarations.length !== 1) errors.push(`${name} has ${declarations.length} dark declarations`);
    }
    for (const [name, declarations] of lightByName) {
      if (declarations.length !== 1) errors.push(`${name} has ${declarations.length} light declarations`);
    }
    if (JSON.stringify(darkNames) !== JSON.stringify(lightNames)) {
      errors.push(
        `theme-role parity differs: dark-only=${darkNames.filter((name) => !lightByName.has(name)).join(",") || "none"}; ` +
          `light-only=${lightNames.filter((name) => !darkByName.has(name)).join(",") || "none"}`,
      );
    }

    const foreignCanonical = adapterDeclarations.filter(
      (decl) => isGlobal(decl) && isCanonicalThemeName(decl.name),
    );
    for (const decl of foreignCanonical) {
      errors.push(`${decl.name} is owned by index.css:${decl.line}, not styles/itsoc.css`);
    }

    expect(errors, "canonical theme contract violations").toEqual([]);
  });

  it("defines shared typography, spacing, and shape scales once on bare :root", () => {
    const shared = ownerDeclarations.filter(isBareRoot);
    const sharedByName = groupByName(shared);
    const errors: string[] = [];

    for (const name of ["--font-family-sans", "--font-family-mono"]) {
      if (sharedByName.get(name)?.length !== 1) errors.push(`${name} must be defined once on bare :root`);
    }

    for (const role of ["caption", "label", "body", "title"]) {
      for (const part of ["size", "line-height", "weight"]) {
        const name = `--type-${role}-${part}`;
        if (sharedByName.get(name)?.length !== 1) errors.push(`${name} must be defined once on bare :root`);
      }
    }

    const spacing = shared.filter((decl) => decl.name.startsWith("--space-"));
    if (new Set(spacing.map((decl) => decl.name)).size < 8) {
      errors.push("the shared spacing scale must contain at least eight --space-* steps");
    }
    if (new Set(spacing.map((decl) => decl.value)).size < 6) {
      errors.push("the shared spacing scale must preserve at least six distinct exact values");
    }

    const exactShapeValues = {
      "--shape-radius-xs": "4px",
      "--shape-radius-sm": "6px",
      "--shape-radius-md": "8px",
      "--shape-radius-lg": "12px",
    } as const;
    for (const [name, value] of Object.entries(exactShapeValues)) {
      if (sharedByName.get(name)?.length !== 1) errors.push(`${name} must be defined once on bare :root`);
      else if (sharedByName.get(name)?.[0].value !== value) errors.push(`${name} must preserve ${value}`);
    }
    if (sharedByName.get("--shape-radius-pill")?.length !== 1) {
      errors.push("--shape-radius-pill must be defined once on bare :root");
    }

    const sharedPrefixes = ["--font-family-", "--type-", "--space-", "--shape-"];
    for (const decl of ownerDeclarations) {
      if (sharedPrefixes.some((prefix) => decl.name.startsWith(prefix)) && !isBareRoot(decl)) {
        errors.push(`${decl.name} must be shared on bare :root, not ${decl.selector || "an at-rule"}`);
      }
    }

    expect(errors, "shared scale contract violations").toEqual([]);
  });

  it("keeps every legacy name as a one-way alias to its canonical semantic role", () => {
    const errors: string[] = [];

    for (const [legacy, canonical] of Object.entries(LEGACY_ALIASES)) {
      const declarations = globalByName.get(legacy) ?? [];
      if (declarations.length !== 1) {
        errors.push(`${legacy} must have one authoritative alias declaration; found ${declarations.length}`);
      }
      for (const decl of declarations) {
        const actual = singleAliasTarget(decl.value);
        if (actual !== canonical) {
          errors.push(`${legacy} must alias ${canonical}; found ${decl.value} at ${path.basename(decl.file)}:${decl.line}`);
        }
        if (decl.file !== tokenOwnerPath) {
          errors.push(`${legacy} alias must be owned by styles/itsoc.css, not ${path.basename(decl.file)}`);
        }
      }
    }

    const legacyNames = new Set(Object.keys(LEGACY_ALIASES));
    for (const decl of globalDeclarations.filter((candidate) => isCanonicalThemeName(candidate.name))) {
      for (const target of varTargets(decl.value)) {
        if (legacyNames.has(target)) {
          errors.push(`${decl.name} points backward to legacy ${target} at ${path.basename(decl.file)}:${decl.line}`);
        }
      }
    }

    expect(errors, "legacy aliases must flow legacy -> semantic, never semantic -> legacy/raw").toEqual([]);
  });

  it("preserves Tailwind's HSL channel API as aliases without a second palette", () => {
    const adapterByName = groupByName(adapterDeclarations.filter(isGlobal));
    const expectedNames = Object.keys(TAILWIND_HSL_ADAPTERS).sort();
    const actualNames = [...adapterByName.keys()].sort();
    const errors: string[] = [];

    for (const [adapter, channel] of Object.entries(TAILWIND_HSL_ADAPTERS)) {
      const declarations = adapterByName.get(adapter) ?? [];
      if (declarations.length !== 1) {
        errors.push(`${adapter} must have one index.css compatibility declaration; found ${declarations.length}`);
      }
      for (const decl of declarations) {
        if (singleAliasTarget(decl.value) !== channel) {
          errors.push(`${adapter} must alias ${channel}; found ${decl.value}`);
        }
      }
      expect(tailwindConfig).toContain(`hsl(var(${adapter}))`);
    }

    if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) {
      errors.push(
        `index.css must contain only HSL adapters: unexpected=${actualNames.filter((name) => !expectedNames.includes(name)).join(",") || "none"}; ` +
          `missing=${expectedNames.filter((name) => !adapterByName.has(name)).join(",") || "none"}`,
      );
    }

    for (const severity of ["critical", "high", "medium", "low"]) {
      expect(tailwindConfig).toContain(`${severity}: "var(--sev-${severity})"`);
    }
    expect(errors, "Tailwind adapter contract violations").toEqual([]);
  });

  it("has no custom-property dependency cycles", () => {
    expect(findCycles(dependencyGraph()), "custom-property alias cycles").toEqual([]);
  });

  it("resolves every production var() reference or an exact local/fallback contract", () => {
    const declaredGlobals = new Set(globalDeclarations.map((decl) => decl.name));
    const violations: string[] = [];
    const cssFiles = walk(srcRoot, /\.css$/);

    for (const file of cssFiles) {
      const root = postcss.parse(read(file), { from: file });
      root.walkDecls((decl) => {
        const localNames = new Set<string>();
        if (decl.parent?.type === "rule") {
          (decl.parent as Rule).walkDecls(/^--/, (local) => {
            localNames.add(local.prop);
          });
        }
        for (const target of varTargets(decl.value)) {
          if (!declaredGlobals.has(target) && !localNames.has(target)) {
            violations.push(`${path.relative(webRoot, file)}:${decl.source?.start?.line ?? 0} -> ${target}`);
          }
        }
      });
    }

    for (const file of walk(srcRoot, /\.tsx?$/)) {
      const source = stripSourceComments(read(file));
      for (const match of source.matchAll(/var\(\s*(--[a-zA-Z0-9_-]+)(\s*,)?/g)) {
        const token = match[1];
        if (declaredGlobals.has(token)) continue;

        const relative = path.relative(webRoot, file);
        const exactFallback = "var(--bg-subtle, rgba(0, 0, 0, 0.02))";
        const isAllowlistedFallback =
          relative === "src/pages/Reports.tsx" &&
          token === "--bg-subtle" &&
          source.slice(match.index, match.index + exactFallback.length) === exactFallback;
        if (!isAllowlistedFallback) {
          violations.push(`${relative}:${lineAt(source, match.index)} -> ${token}`);
        }
      }
    }

    expect(
      violations,
      "unresolved production var() references (only Reports.tsx's exact --bg-subtle fallback and same-rule locals are allowlisted)",
    ).toEqual([]);
  });

  it("keeps warning status semantically distinct from high severity even when values coincide", () => {
    const graph = dependencyGraph();
    expect(singleAliasTarget(globalByName.get("--warn")?.[0]?.value ?? "")).toBe("--status-warning");
    expect(singleAliasTarget(globalByName.get("--high")?.[0]?.value ?? "")).toBe("--severity-high");
    expect(hasPath(graph, "--status-warning", "--severity-high")).toBe(false);
    expect(hasPath(graph, "--severity-high", "--status-warning")).toBe(false);
  });
});
