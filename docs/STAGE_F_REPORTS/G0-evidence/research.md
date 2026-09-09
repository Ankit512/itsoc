# G0 design-system foundation research

**Card:** G0, research only

**Branch:** `Ankit512/g0-research`

**Required base / inspected HEAD:** `bdbd496c5b082b92eec09af8554600561e132b84`

**Detector tripwire:** `364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876`

**Report commit:** the commit containing this file (the exact hash is in the worker handoff; a commit cannot contain its own hash)

## Executive finding

G0 is warranted, but the scope premise is materially understated. The tree has **48 unique global custom-property names**, not approximately 10: 29 in `itsoc.css`, 20 in `index.css`, with `--shadow` declared in both. There is also one component-local property, `--tour-glow`. At least 44 of the 48 global names have production consumers once Tailwind mappings and utility-class consumers are included; only `--fill`, `--info`, `--ok`, and `--danger` have no production consumer. The measured correction to “~10 real design tokens” is therefore **48 global names (4.8× the premise), split across two partially overlapping systems**.

The deeper criticism in the scope is still correct: there is no custom-property type scale or spacing scale, the radius system has two distinct values behind three names, and elevation ownership is broken. The two theme systems are close but not actually lock-step. In particular, the legacy and Tailwind accent values render differently in both themes, the dark muted-text values differ by a channel, and the unlayered `itsoc.css` `--shadow` silently overrides the different `index.css` `--shadow` value.

The safe G0 is a compatibility migration, not a palette redesign: establish one authoritative semantic layer; keep every currently required name as an alias; preserve the few measured differences explicitly; add exact-value type, spacing, shape, and elevation tokens without coalescing nearby values; then prove zero changed pixels over every route in both themes.

## Provenance and method

The pre-edit checks were run against the actual worktree:

```text
git rev-parse HEAD
bdbd496c5b082b92eec09af8554600561e132b84

git merge-base --is-ancestor bdbd496c5b082b92eec09af8554600561e132b84 HEAD
exit 0

git cat-file -e HEAD:web/src/styles/itsoc.css
git cat-file -e HEAD:web/src/index.css
both exit 0

shasum -a 256 anomaly_detector.py
364577c5c8a3014b6c22b72ef7a4048933eb796a87fe1bac8f087eb577a4a876
```

`graphify-out/graph.json` is absent, so there was no repository graph index to query. The audit instead used repository source, tests, `git log`/`git blame`, a clean archive of the exact base, and the real running application. External facts below are limited to the official CSS specifications and official Playwright documentation and are cited inline.

For real-app evidence, the exact base was exported to `/tmp/itsoc-g0-realapp.yPZYH9`, dependencies were installed there with `npm ci --ignore-scripts`, and a report was generated from the repository fixture `tests/eval/cases/pos_bruteforce_compromise.log` using the real analyzer (`--rules-only`). The analyzer parsed 7/7 lines and emitted two detector findings; the UI's real grouping produced three visible finding groups. `console/serve.py` served that report and its real API, and the web app was exercised in system Chrome at 1500×1000, DPR 1, `en-GB`, UTC.

The source-app sweep captured 48 PNGs: every one of the 24 reachable route states below in light and dark. A production `npm run build` also completed from the clean base (1,689 transformed modules), the production bundle was served through `console/serve.py`, and Overview and Incidents were spot-checked in both themes. No API response, component state, screenshot, or visual fixture was mocked or staged.

The existing focused theme tests also pass on the base:

```text
src/test/c4-themes.test.tsx       10 tests passed
src/test/shadow-tokens.test.tsx    3 tests passed
src/test/theme.test.tsx            3 tests passed
total                             16 tests passed
```

Those green tests do not invalidate the findings below; several gaps are precisely outside what those tests assert.

## 1. Exact token inventory

The two blocks are visible at [`itsoc.css:21`](../../../web/src/styles/itsoc.css#L21) and [`index.css:25`](../../../web/src/index.css#L25). Counts below are lexical production-source references with comments and `web/src/test` excluded. For Tailwind plumbing, `D` is the number of direct `var(--token)` references (normally including its mapping in `tailwind.config.ts`) and `U` is the number of mapped utility-name occurrences across production web source. Counts are an audit aid, not an assertion that every branch renders in one screenshot.

### `itsoc.css`: 29 global names

| Token | Dark value | Light value | Direct production `var()` refs |
|---|---|---|---:|
| `--bg` | `#09090b` | `#fbfbfc` | 11 |
| `--pan` | `#0e0e12` | `#ffffff` | 51 |
| `--pan2` | `#17171c` | `#f1f1f4` | 17 |
| `--inset` | `#0b0b0f` | `#f7f7f9` | 21 |
| `--track` | `#1a1a20` | `#ececef` | 2 |
| `--fill` | `#3f3f4a` | `#c4c4cd` | 0 |
| `--bd` | `#1e1e24` | `#ececef` | 102 |
| `--bd2` | `#2a2a31` | `#e0e0e5` | 24 |
| `--ink` | `#ededf0` | `#18181b` | 110 |
| `--ink2` | `#c9c9d1` | `#3f3f46` | 17 |
| `--mut` | `#8f8f98` | `#71717a` | 120 |
| `--mut2` | `#5c5c66` | `#a1a1aa` | 45 |
| `--acc` | `#8b7cff` | `#6d5cf0` | 134 |
| `--acc-ink` | `#ffffff` | `#ffffff` | 9 |
| `--acc-weak` | `color-mix(in srgb,var(--acc) 16%,transparent)` | `color-mix(in srgb,var(--acc) 12%,transparent)` | 13 |
| `--crit` | `#f26d78` | `#f26d78` | 52 |
| `--high` | `#f0a54a` | `#f0a54a` | 28 |
| `--med` | `#d3b23a` | `#d3b23a` | 7 |
| `--low` | `#3ecf8e` | `#3ecf8e` | 22 |
| `--info` | `#8f8f98` | `#71717a` | 0 |
| `--ok` | `#3ecf8e` | `#3ecf8e` | 0 |
| `--warn` | `#f0a54a` | `#f0a54a` | 13 |
| `--danger` | `#f26d78` | `#f26d78` | 0 |
| `--radius` | `6px` | `6px` | 13 |
| `--radius-sm` | `6px` | `6px` | 24 |
| `--radius-xs` | `4px` | `4px` | 9 |
| `--shadow` | `0 8px 30px rgba(0,0,0,.35)` | `0 8px 30px rgba(20,24,40,.12)` | 9, including Tailwind mapping |
| `--mono` | `'Geist Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace` | inherited from `:root` | 34 |
| `--sans` | `'Geist',-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,system-ui,sans-serif` | inherited from `:root` | 7 |

The light block has 27 declarations because the two font stacks inherit from the `:root` half of the combined dark/root selector. That is functionally valid theme parity, though it makes a naive block-equality test misleading. A 30th, non-global name, `--tour-glow`, is declared and consumed inside the tour spotlight rule at [`itsoc.css:371`](../../../web/src/styles/itsoc.css#L371).

### `index.css`: 20 global names

| Token | Light value | Dark value | Production consumers |
|---|---|---|---:|
| `--background` | `240 20% 98.6%` | `240 10% 3.9%` | D 1; `bg-background` U 26 |
| `--foreground` | `240 6% 10%` | `240 9% 93.5%` | D 1; `text-foreground` U 57 |
| `--card` | `0 0% 100%` | `240 13% 6.3%` | D 1; `bg-card` U 36 |
| `--card-foreground` | `240 6% 10%` | `240 9% 93.5%` | D 1; `text-card-foreground` U 1 |
| `--muted` | `240 12% 95.1%` | `240 10% 10%` | D 1; `bg-muted` U 13 |
| `--muted-foreground` | `240 3.8% 46.1%` | `240 5% 57.8%` | D 2; `text-muted-foreground` U 124 |
| `--primary` | `249 84% 65.1%` | `249 100% 74.3%` | D 4; `bg-primary` U 9; `text-primary` U 20 |
| `--primary-foreground` | `0 0% 100%` | `0 0% 100%` | D 1; `text-primary-foreground` U 5 |
| `--accent` | `249 84% 96%` | `249 28% 28%` | D 1; `bg-accent` U 18 |
| `--accent-foreground` | `249 75% 45%` | `249 91% 83%` | D 1; `text-accent-foreground` U 6 |
| `--border` | `240 8% 93.1%` | `240 9% 12.9%` | D 4; `border-border` U 25 |
| `--input` | `240 8% 93.1%` | `240 9% 12.9%` | D 1; `border-input` U 1 |
| `--ring` | `249 84% 65.1%` | `249 100% 74.3%` | D 1; `ring-ring` U 2 |
| `--sev-critical` | `#f26d78` | `#f26d78` | D 4 |
| `--sev-high` | `#f0a54a` | `#f0a54a` | D 2 |
| `--sev-medium` | `#d3b23a` | `#d3b23a` | D 4 |
| `--sev-low` | `#3ecf8e` | `#3ecf8e` | D 3 |
| `--shadow` | `0 1px 2px rgba(26,32,51,.06), 0 4px 14px rgba(26,32,51,.06)` | `0 1px 2px rgba(0,0,0,.3), 0 4px 14px rgba(0,0,0,.3)` | D 9 through the shared name; collides; see below |
| `--shadow-pop` | `0 12px 32px -8px rgba(26,32,51,.28)` | `0 12px 32px -8px rgba(0,0,0,.55)` | D 4 |
| `--shadow-modal` | `0 24px 64px -12px rgba(26,32,51,.45)` | `0 24px 64px -12px rgba(0,0,0,.7)` | D 1 |

The utility mappings are defined at [`tailwind.config.ts:9`](../../../web/tailwind.config.ts#L9). The audit also found 29 `font-mono` utility occurrences, which use Tailwind's `ui-monospace` stack rather than the Geist Mono stack behind `--mono`; this is another real split hidden by the token-only count.

### Duplicate values are not all duplicate semantics

| Scope | Same current value | Interpretation |
|---|---|---|
| both `itsoc.css` themes | `--crit = --danger`, `--high = --warn`, `--low = --ok`, `--radius = --radius-sm` | Preserve distinct severity/status semantics; exact-value sharing may happen below the semantic layer. |
| dark `itsoc.css` | `--mut = --info` | Different roles that currently share a primitive. |
| light `itsoc.css` | `--pan = --acc-ink`, `--track = --bd`, `--mut = --info` | Coincidental equality; do not alias these semantic roles directly. |
| both `index.css` themes | `--foreground = --card-foreground`, `--primary = --ring`, `--border = --input` | Safe compatibility aliases to common semantic roles today. |
| light `index.css` | `--card = --primary-foreground` | Coincidental equality. |
| both files and themes | critical/high/medium/low quartet | One canonical severity layer should own these. |

The semantic separation between warning and high severity is already contractual. The C4 tests explicitly reject using the severity ramp for warning/advisory states even though `--warn` and `--high` have the same raw value; see [`c4-themes.test.tsx:197`](../../../web/src/test/c4-themes.test.tsx#L197) and the history note below.

## 2. Theme parity, graph validity, and cascade defects

### Parity

- `itsoc.css` has both-theme values for all 24 colour/surface/elevation names required by the C4 contract, plus all three radius names. Font families are static inherited values.
- `index.css` has the same 20-name set in light and dark.
- The store stamps `.dark` and `data-theme` together at [`ui.ts:19`](../../../web/src/store/ui.ts#L19), and `main.tsx` reapplies that state before React renders at [`main.tsx:13`](../../../web/src/main.tsx#L13). The three existing theme-toggle tests pass.
- There is a minor error-path asymmetry: if local-storage access throws in the pre-paint script, its catch says “stay light” but does not stamp `data-theme="light"`. Normal browser operation was synchronized; storage-denied mode was not exercised in this research run.

### The systems do not render identically

The comment in [`index.css:12`](../../../web/src/index.css#L12) says the HSL plumbing values are lock-step and render identically to `itsoc.css`. Live computed-style measurement in system Chrome disproved that claim:

| Pair | Light computed RGB | Dark computed RGB | Result |
|---|---|---|---|
| `--bg` / `hsl(var(--background))` | both `251,251,252` | both `9,9,11` | exact |
| `--pan` / `hsl(var(--card))` | both `255,255,255` | both `14,14,18` | exact |
| `--pan2` / `hsl(var(--muted))` | both `241,241,244` | both `23,23,28` | exact |
| `--ink` / `hsl(var(--foreground))` | both `24,24,27` | both `237,237,240` | exact |
| `--bd` / `hsl(var(--border))` | both `236,236,239` | both `30,30,36` | exact |
| four severity pairs | exact | exact | exact |
| `--acc` / `hsl(var(--primary))` | `109,92,240` / `114,91,241` | `139,124,255` / `144,124,255` | **different** |
| `--mut` / `hsl(var(--muted-foreground))` | both `113,113,122` | `143,143,152` / `142,142,153` | **different** |

Those differences must be preserved as named compatibility roles during a zero-pixel migration. Unifying them merely because their comments say they match would introduce a visible diff.

### `--shadow` has two owners, but only one effective value

`index.css` declares `--shadow` inside `@layer base`, while `itsoc.css` declares it unlayered. `main.tsx` also imports `itsoc.css` after `index.css` at [`main.tsx:7`](../../../web/src/main.tsx#L7). For normal declarations, unlayered rules have priority over named and anonymous layers according to the official [CSS Cascading and Inheritance Level 5 layer ordering](https://drafts.csswg.org/css-cascade-5/#layer-order). Therefore the `index.css` card-shadow declaration is dead in the running app.

Live computed style confirmed the root value is the `itsoc.css` value in both themes:

- light: `0 8px 30px rgba(20, 24, 40, 0.12)`;
- dark: `0 8px 30px rgba(0, 0, 0, 0.35)`.

Consequently, Tailwind's `shadow-card` mapping at [`tailwind.config.ts:29`](../../../web/tailwind.config.ts#L29) consumes the shell shadow, not the two-layer value its comment attributes to `index.css`. `--shadow-pop` and `--shadow-modal` do not collide and remain effective from `index.css`.

### Resolution and cycles

No custom-property dependency cycle exists. The only global dependency is `--acc-weak → --acc`; the local graph adds `--tour-glow → --acc`.

There is one referenced but undeclared name: `--bg-subtle` at [`Reports.tsx:606`](../../../web/src/pages/Reports.tsx#L606). Its explicit `rgba(0, 0, 0, 0.02)` fallback prevents an invalid used value today, but it is an unthemed compatibility escape hatch. The official [CSS Custom Properties specification](https://drafts.csswg.org/css-variables-2/) defines custom properties as inherited, defines cycles as guaranteed-invalid, and defines `var()` fallback substitution when the referenced property's value cannot be used. A G0 contract should catch both unresolved names and cycles rather than relying on browser fallback behavior.

## 3. Type, spacing, radius, elevation, and hard-code audit

### Measured coverage

| Area | Current custom-property coverage | Literal/source evidence |
|---|---|---|
| Font family | `--sans`, `--mono` | Tailwind separately defines different sans/mono stacks. |
| Type scale | none | `itsoc.css` has 213 `font-size` declarations using 21 distinct literal sizes, from `8.5px` through `32px`. The most frequent are `10px` (33), `10.5px` (31), `11px` (29), `12px` (28), and `11.5px` (23). |
| Spacing scale | none | `itsoc.css` has 18 distinct `gap` expressions and 90 distinct padding expressions. |
| Radius | three names, two values | `--radius` and `--radius-sm` are both `6px`; `--radius-xs` is `4px`. Across the stylesheet there are 18 distinct radius expressions, including literals from `2px` to `20px`, asymmetric corners, and `50%`. Tailwind separately defines `sm=6px`, `md=8px`, `lg=12px`. |
| Elevation | nominally three global names, but split ownership | `--shadow` collides; popover/modal live only in `index.css`; rail, FAB, tour glow, and focus ring encode their own geometry. |

“No type scale” and “no spacing scale” are therefore accurate. “No elevation system” is directionally accurate but should be stated as “a partial, conflicting elevation system”: three names exist, only two have a single owner, and several elevations remain outside it.

### Risky hard-coded values

These are migration candidates, not automatic bugs; each must retain its exact computed colour/geometry in G0.

| Location | Current hard-code | Risk |
|---|---|---|
| [`itsoc.css:255`](../../../web/src/styles/itsoc.css#L255) | overlay mixes `#000` | Global overlay role has no token. |
| [`itsoc.css:335`](../../../web/src/styles/itsoc.css#L335) | overlay mixes `rgba(0,0,0,.58)` | Second overlay formula, outside theme ownership. |
| [`itsoc.css:924`](../../../web/src/styles/itsoc.css#L924) | rail `0 20px 60px color-mix(...)` | The colour is token-derived, but elevation geometry is hard-coded. |
| [`itsoc.css:926`](../../../web/src/styles/itsoc.css#L926) | FAB `0 10px 28px color-mix(...)` | Same guard blind spot. |
| [`itsoc.css:940`](../../../web/src/styles/itsoc.css#L940) | focus ring geometry | Should be a focus token, not elevation. |
| [`SeverityDonut.tsx:50`](../../../web/src/components/charts/SeverityDonut.tsx#L50) | two `#fff` labels | Should use an on-severity/on-strong token. |
| [`History.tsx:147`](../../../web/src/pages/History.tsx#L147) | confirmed purge text `#fff` | Should use an on-danger token. |
| [`Reports.tsx:98`](../../../web/src/pages/Reports.tsx#L98) | two `var(--bg, #fff)` uses | Fallback is light-only if the contract breaks. |
| [`Reports.tsx:606`](../../../web/src/pages/Reports.tsx#L606) | undeclared `--bg-subtle` with black-alpha fallback | Looks different by surface/theme and evades the global registry. |

There are also two `shadow-sm` uses and nine `shadow-xs` uses. The production CSS contains `.shadow-sm` but no `.shadow-xs`: Tailwind 3.4 has no configured `xs` shadow in this tree, and live computed style for a `shadow-xs` element was `none`. G0 should either map those nine uses to an exact token deliberately or reject the unknown utility; tokenizing an imagined shadow would change pixels.

The existing shadow guard at [`shadow-tokens.test.tsx:47`](../../../web/src/test/shadow-tokens.test.tsx#L47) only rejects `rgba()`/hex colours in a `box-shadow`. It therefore misses the rail and FAB shadows because their colours are `color-mix(var(--ink), ...)`. Its definition-count assertion at line 75 also requires the current duplicate `--shadow` declarations without proving which one wins. That test must be updated with the ownership migration, not weakened.

## 4. Legacy contracts that constrain the migration

The following are not safe to delete in G0 without migrating consumers and tests in the same change:

- The C4 both-theme test explicitly requires these 24 names in both theme blocks at [`c4-themes.test.tsx:153`](../../../web/src/test/c4-themes.test.tsx#L153): `--bg`, `--pan`, `--pan2`, `--inset`, `--track`, `--fill`, `--bd`, `--bd2`, `--ink`, `--ink2`, `--mut`, `--mut2`, `--acc`, `--acc-ink`, `--acc-weak`, `--crit`, `--high`, `--med`, `--low`, `--info`, `--ok`, `--warn`, `--danger`, and `--shadow`.
- `lib/severity.ts` returns the four `--sev-*` names directly at [`severity.ts:9`](../../../web/src/lib/severity.ts#L9).
- The runbook regression test asserts the exact source spelling `color:var(--ink2)` at [`runbook-card.test.tsx:413`](../../../web/src/test/runbook-card.test.tsx#L413).
- `shadow-tokens.test.tsx` currently asserts two textual definitions of each index elevation token and two more `itsoc.css` `--shadow` definitions. The test should move to semantic ownership assertions when the CSS moves.
- Many tests assert `is-*` classes or severity-token confinement. Aliasing preserves these; renaming selectors is outside G0.

These tests are useful constraints, but source-spelling assertions should be updated to accept/prove canonical aliases. Keeping old names as explicit aliases is the least risky route and avoids coupling a foundation card to a 400+ call-site rewrite.

## 5. Recommended canonical taxonomy and compatibility map

### Ownership

Put the authoritative global declarations in the unlayered design-system file. Keep `index.css` for Tailwind layers and base application only; it must not own a competing theme block. Use three levels:

1. **Theme primitives/channels**: the exact existing per-theme values, including HSL channel tokens where `hsl(var(...))` compatibility requires them.
2. **Canonical semantic tokens**: role names used by new code.
3. **Legacy aliases**: every old name, pointing to the semantic role or an explicitly named compatibility role.

Do not alias semantic roles to one another merely because their present values match. If severity-high and status-warning share a primitive, both semantic nodes remain separate.

### Canonical semantic set

| Family | Canonical names |
|---|---|
| Surfaces/data | `--surface-canvas`, `--surface-panel`, `--surface-raised`, `--surface-recessed`, `--surface-track`, `--data-fill-neutral` |
| Borders | `--border-subtle`, `--border-strong`, `--border-input` |
| Text | `--text-primary`, `--text-secondary`, `--text-muted`, `--text-faint`, `--text-on-action`, `--text-on-danger`, `--text-on-severity` |
| Action/selection | `--action-primary`, `--action-primary-subtle`, `--control-selected`, `--text-on-selected`, `--focus-ring-color` |
| Severity | `--severity-critical`, `--severity-high`, `--severity-medium`, `--severity-low`, `--severity-info` |
| Non-severity status | `--status-success`, `--status-warning`, `--status-danger` |
| Typography | `--font-family-sans`, `--font-family-mono`; semantic size/line-height/weight pairs such as `--type-caption-*`, `--type-label-*`, `--type-body-*`, `--type-title-*`, with exact current values |
| Spacing | `--space-*` exact-value scale plus purpose-specific layout sizes where a value is not a genuine reusable step |
| Shape | `--shape-radius-xs` (`4px`), `--shape-radius-sm` (`6px`), `--shape-radius-md` (`8px`), `--shape-radius-lg` (`12px`), `--shape-radius-pill`; retain exact-purpose tokens for `10px`, `14px`, and asymmetric shapes until a later visual change |
| Elevation | `--elevation-card`, `--elevation-popover`, `--elevation-modal`, `--elevation-rail`, `--elevation-fab`, plus separate `--focus-ring` and `--overlay-*` tokens |

For type and spacing, inventory first and name by actual role. G0 must not round `10.5px` to `10px`, turn `7px` into `8px`, or otherwise “clean up” close values. A token may initially preserve an awkward value; consolidation belongs in a later card with a documented pixel diff.

### Pixel-preserving legacy aliases

| Existing name | Alias target |
|---|---|
| `--bg` | `--surface-canvas` |
| `--pan` | `--surface-panel` |
| `--pan2` | `--surface-raised` |
| `--inset` | `--surface-recessed` |
| `--track` | `--surface-track` |
| `--fill` | `--data-fill-neutral` |
| `--bd` | `--border-subtle` |
| `--bd2` | `--border-strong` |
| `--ink` | `--text-primary` |
| `--ink2` | `--text-secondary` |
| `--mut` | `--text-muted` |
| `--mut2` | `--text-faint` |
| `--acc` | `--action-primary` |
| `--acc-ink` | `--text-on-action` |
| `--acc-weak` | `--action-primary-subtle` |
| `--crit`, `--sev-critical` | `--severity-critical` |
| `--high`, `--sev-high` | `--severity-high` |
| `--med`, `--sev-medium` | `--severity-medium` |
| `--low`, `--sev-low` | `--severity-low` |
| `--info` | `--severity-info` |
| `--ok` | `--status-success` |
| `--warn` | `--status-warning` |
| `--danger` | `--status-danger` |
| `--radius`, `--radius-sm` | `--shape-radius-sm` |
| `--radius-xs` | `--shape-radius-xs` |
| `--shadow` | `--elevation-card` using the currently effective `itsoc.css` value |
| `--shadow-pop` | `--elevation-popover` |
| `--shadow-modal` | `--elevation-modal` |
| `--mono` | `--font-family-mono` |
| `--sans` | `--font-family-sans` |

Tailwind's HSL names require a compatibility detail. Existing mappings call `hsl(var(--background))`, so `--background` cannot alias a full-colour token such as `--surface-canvas`; it must continue to contain channels. Define canonical `--surface-canvas-hsl`, `--text-primary-hsl`, and similar channel primitives, then alias both forms:

```css
--surface-canvas-hsl: 240 20% 98.6%;
--surface-canvas: hsl(var(--surface-canvas-hsl));
--background: var(--surface-canvas-hsl);
--bg: var(--surface-canvas);
```

Use the same pattern for the exact pairs: background/canvas, foreground/text-primary, card/panel, muted/raised, border/subtle, input/border-input, and severity. Preserve the measured exceptions under explicit compatibility names:

- `--primary` and `--ring` → `--compat-action-primary-hsl` until utility consumers migrate, while `--acc` → `--action-primary` retains its exact hex;
- `--muted-foreground` → `--compat-text-muted-hsl` until the one-channel dark difference is deliberately resolved;
- `--accent`/`--accent-foreground` map to selected-control roles, not to `--acc-weak`;
- `--primary-foreground` maps through an HSL channel primitive for white, while `--acc-ink` maps to the full-colour semantic.

This looks more verbose than collapsing values, but it is the only honest zero-pixel migration. Once all Tailwind consumers use full semantic tokens, the compatibility HSL nodes can be removed in a separately proven change.

## 6. Reachable-route inventory and real-app observations

Routes come directly from [`App.tsx:27`](../../../web/src/App.tsx#L27). All 23 declared URLs plus the wildcard state returned the application and rendered their expected real component during the sweep.

| Route captured | Component/state | Notes |
|---|---|---|
| `/` | Overview | Real report metrics and grouped findings. |
| `/alerts` | Alerts / Findings | Canonical findings screen. |
| `/findings` | Alerts / Findings | Legacy alias. |
| `/incidents` | Incidents | Three real incident clusters in the fixture-backed run. |
| `/cases` | Cases | Reachable canonical route. |
| `/approvals` | Approvals | Reachable canonical route; polls every 5 s. |
| `/intel` | Intel | Canonical intel screen. |
| `/threat-intel` | ThreatIntel | Legacy/wrapper route. |
| `/enrichment` | Enrichment | Legacy/wrapper route. |
| `/network` | Network | Canonical network screen. |
| `/discovery` | Network, discovery tab | Alias with `defaultTab="discovery"`. |
| `/vulnerabilities` | Network, vulnerabilities tab | Alias with `defaultTab="vulnerabilities"`. |
| `/assets` | Assets | Polls assets/users every 5 s. |
| `/sources` | Sources | Canonical sources screen. |
| `/collectors` | Sources | Legacy alias; collector status polls every 3 s, OEM every 5 s. |
| `/integrations` | Integrations | Reachable; connection success is a client timer, so it was not triggered for evidence. |
| `/history` | History | Metrics and events poll every 5 s. |
| `/reports` | Reports | Reachable real report screen; active exports can poll every 1 s. |
| `/settings` | Settings | Reachable canonical route. |
| `/oem` | OemEngine | Direct route is reachable even though navigation exposure is experimental; polls every 5 s. |
| `/login` | Login | With the actual local auth context, honestly rendered the already-signed-in state. |
| `/signup` | Login | Same component and actual state as `/login`. |
| `/logout` | Logout in `AppShell` | Reachable framed lifecycle screen. |
| `/does-not-exist` | wildcard Placeholder | Honest “Not found” state. |

The app has live pollers on Alerts, Approvals, Assets, History, Incidents, Network, Collectors, OEM, Reports while an export is running, and parts of Copilot. To test whether normal background refresh made the evidence nondeterministic, `/`, `/assets`, `/network`, `/history`, `/collectors`, and `/oem` were captured twice 5.5 seconds apart in each theme. All 12 pairs were byte-decoded and compared at the pixel level: **0 of 1,500,000 pixels changed in every pair**. This proves stability for the observed real report and server state, not for all possible external connectors or future timestamps.

The Integrations screen's “Connect” path uses a local `setTimeout` and reports a fixed “14ms” response rather than a measured API call at [`Integrations.tsx:218`](../../../web/src/pages/Integrations.tsx#L218). It was not used or masked in this evidence. Whether that demo interaction satisfies the product's honest-surface rule is outside G0 and remains an owner-visible unknown.

## 7. Reproducible before/after and changed-pixel method

The implementation card should produce 96 route images (24 states × 2 themes × base/candidate) plus diff images and a machine-readable manifest. The current research screenshots establish that the matrix is reachable; they are not a substitute for candidate A/B evidence.

1. Create two **detached** trees: exact required base and candidate HEAD. Verify ancestry, both CSS artefacts, and the detector hash in each before capture.
2. Generate one deterministic rules-only report from the repository log fixture, once. Copy the report and fresh isolated `.soc` state to both servers. Do not share a mutable store and do not initiate network discovery, connectors, export jobs, or other actions with time/external effects.
3. Run `npm ci` and `npm run build` in the same pinned Node/npm environment for both trees. Serve each production bundle through its own `console/serve.py` process. Record Node, npm, Chrome/Playwright, OS, locale, timezone, viewport, DPR, and commit hashes in the manifest.
4. For each route above, create a fresh browser context at 1500×1000, DPR 1, `en-GB`, UTC. Seed only the real `itsoc-theme` local-storage contract for light/dark and assert that `.dark` and `data-theme` agree. Separately exercise the real toggle once so a broken toggle cannot be hidden by pre-seeding.
5. Wait for the app shell, API success, and `document.fonts.ready`. Disable CSS animations/transitions and hide the caret consistently; do not mask values. Playwright's official [visual-comparisons documentation](https://playwright.dev/docs/test-snapshots) says `toHaveScreenshot()` waits for two consecutive screenshots to match and uses Pixelmatch, and warns that screenshots vary by environment, so the base and candidate must use the same capture environment. Its official [test configuration reference](https://playwright.dev/docs/api/class-testconfig) documents screenshot defaults and `maxDiffPixels`, `maxDiffPixelRatio`, and threshold controls.
6. Capture base and candidate PNGs with identical names. Decode both as RGBA. A pixel is changed if **any** channel differs: `changed = count(any(base_rgba != candidate_rgba, axis=channel))`; report `changed`, `width × height`, and `changed / total`. Emit an amplified diff PNG and side-by-side HTML. G0's required threshold is exact: `threshold: 0`, `maxDiffPixels: 0`.
7. Repeat a candidate screenshot after at least the longest normal page poll interval for every polling route. If it changes, diagnose the real source. Do not hide it with a mask. If a genuinely time-varying state cannot be stabilized without faking data, record that state as unreachable for pixel proof and explain why.
8. Add real, reachable interaction states where tokens materially render outside the route baseline: an incident detail selected from the fixture, a real case detail if available, command palette, guided tour, Copilot rail, Runs popover, Upload modal, and any approval modal reachable through the real backend. Do not inject component state or intercept API responses to manufacture them.

The repository currently has no Playwright dependency or checked-in browser configuration. That setup cost is an implementation decision; a one-off unpinned browser command is insufficient final evidence.

## 8. Focused, red-capable token contract test

Add `web/src/test/design-token-contract.test.ts` backed by a small pure analyzer built on the already-declared `postcss` dependency. The analyzer should accept CSS/source strings so the test can mutate in memory and prove each assertion bites.

Baseline assertions:

1. Parse declarations from the CSS AST, not regex over comments/selectors. Assert one authoritative global theme owner and no cross-file duplicate global name.
2. Assert the exact canonical themed set exists once in light and dark; assert static families/scales once at root. Compare sets bidirectionally and assert nonempty rule/declaration counts to prevent vacuous passes.
3. Assert the explicit legacy alias map above exactly. A legacy name may resolve through channels, but it may not silently change target.
4. Build a dependency graph from every `var()` in token values and reject cycles.
5. Scan production `.css`, `.ts`, and `.tsx`; every `var()` reference must resolve to a global declaration, a same-rule local declaration such as `--tour-glow`, or an explicitly allowlisted fallback. Remove or declare `--bg-subtle`; do not broadly allow any fallback.
6. Assert semantic boundaries: status-warning and severity-high remain distinct semantic nodes even if they share a primitive; likewise success/low and danger/critical.
7. Reject raw colour declarations outside the primitive/theme allowlist, and reject any non-`none` box-shadow geometry outside elevation/focus token declarations. This catches `color-mix()` hardcodes that the current test misses.
8. Reject unknown Tailwind token utilities such as the current no-op `shadow-xs`, or add an exact mapping intentionally.

Required mutation table:

| In-memory mutation | Assertion that must fail |
|---|---|
| Delete `--surface-panel` from light | both-theme completeness |
| Change `--bg` alias from canvas to raised | legacy alias contract |
| Add `--loop-a:var(--loop-b)` and `--loop-b:var(--loop-a)` | cycle detection |
| Add production fixture `color:var(--not-a-token)` | unresolved consumer |
| Add a canonical root token to `index.css` | single ownership / duplicate declaration |
| Add `box-shadow:0 8px 24px color-mix(...)` to a component rule | elevation confinement |
| Replace `--status-warning` use with `--severity-high` | semantic boundary |

For each mutation, assert the analyzer returns the expected diagnostic, then run the unmodified inputs and assert success. This implements the stage rule that a guard must be observed failing, rather than merely adding another green count assertion.

## 9. History that explains the current constraints

- `e8c1f5f` introduced the `is-*` foundation and global design-system file.
- `1a5904b` changed both token blocks for Design v3 and introduced the current self-hosted Geist setup.
- `353607f` added/normalized the small radius aliases during command-palette work.
- `7960d5d` introduced the elevation tokens and `shadow-tokens.test.tsx`; it is the source of the current duplicate-`--shadow` contract.
- `53202f7` reinforced the distinction between warning/advisory semantics and severity tokens even when values coincide.
- `82e5e3e` added the exact `color:var(--ink2)` runbook regression assertion after a visible ordered-list regression.

This history argues for aliases and test migration, not wholesale deletion of old spellings.

## 10. Recommended implementation order

1. Add the pure contract analyzer and mutation tests first; demonstrate every mutation fails and restore it.
2. Establish the canonical primitives/semantic roles in one unlayered theme owner. Preserve divergent primary/muted compatibility channels exactly.
3. Replace the duplicate index theme declarations with legacy channel aliases. Make the currently effective `itsoc.css` shadow the canonical card elevation; add exact rail/FAB/overlay/focus roles.
4. Add exact-value type, spacing, shape, and typography-family tokens and migrate call sites mechanically. Do not normalize near values.
5. Update existing C4/runbook/shadow tests to assert semantic ownership and aliases while preserving their behavioural/palette constraints.
6. Run the focused tests, `gate.sh --web`, detector hash, unresolved/cycle audit, and the complete real-app production A/B matrix. Any changed pixel must be zero or individually documented as a deliberate exception; G0's stated intent makes zero the default.

## Unknowns and decisions for the implementation owner

- Does “replace” require every one of the 213 font-size declarations and 162 gap declarations to move in G0, or only establishment plus migration of repeated exact values? A full mechanical migration is possible but substantially enlarges the proof surface. The no-pixel rule forbids rationalizing values either way.
- Should the current primary/muted HSL differences remain permanent semantic distinctions, or be unified later with an explicit visual-diff decision? They cannot be unified invisibly.
- Should Playwright and its browser version be committed as a dev dependency for durable evidence, or should CI provide a pinned external runner? The repository currently provides neither.
- Which interactive states beyond the 24 route baselines are mandatory acceptance evidence? The report recommends all real overlays/rails touched by the migrated tokens, but some approval/case states may require a real mutation sequence and a fresh isolated store.
- Is the Integrations fixed “14ms” timer accepted demo behavior? It was not used for visual evidence and should not be silently normalized under a styling card.
- The storage-denied pre-paint theme path was not exercised; if it is part of supported operation, it needs a separate test.

## Source index

Repository primary sources: [`CLAUDE.md`](../../../CLAUDE.md), [`GUARDRAILS.md`](../../../GUARDRAILS.md), [`ITSOC_STAGE_F_SCOPE.md:89`](../../ITSOC_STAGE_F_SCOPE.md#L89), [`App.tsx`](../../../web/src/App.tsx), [`main.tsx`](../../../web/src/main.tsx), [`ui.ts`](../../../web/src/store/ui.ts), [`itsoc.css`](../../../web/src/styles/itsoc.css), [`index.css`](../../../web/src/index.css), [`tailwind.config.ts`](../../../web/tailwind.config.ts), [`c4-themes.test.tsx`](../../../web/src/test/c4-themes.test.tsx), [`shadow-tokens.test.tsx`](../../../web/src/test/shadow-tokens.test.tsx), [`runbook-card.test.tsx`](../../../web/src/test/runbook-card.test.tsx), [`severity.ts`](../../../web/src/lib/severity.ts), and the repository history commits listed above.

External primary sources: [CSS Custom Properties for Cascading Variables Level 2](https://drafts.csswg.org/css-variables-2/), [CSS Cascading and Inheritance Level 5 — layer ordering](https://drafts.csswg.org/css-cascade-5/#layer-order), [Playwright visual comparisons](https://playwright.dev/docs/test-snapshots), and [Playwright `testConfig.expect` screenshot options](https://playwright.dev/docs/api/class-testconfig).
