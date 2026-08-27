# Design v3 — GAP ANALYSIS (shipped `main @ 2366a5f` vs v3 `dc` mockup)

Read-only diff by Pam, 2026-08-27. Sources: `itsoc_console_v3.dc.html` (target; read as static
HTML/CSS — mustache/`support.js` ignored), `ITSOC_ALL_PAGES_DESIGN.md`, `ITSOC_CLAUDE_DESIGN_PROMPT.md`
vs `web/src/**` + `console/**` at HEAD 2366a5f. Size tags: **TRIVIAL** token/label · **SMALL** layout ·
**MEDIUM** new component · **LARGE** new page+backend.

## Headline (for scoping)
- **Enrichment + OEM Engine are ALREADY SHIPPED — front AND back.** The task's candidate "two new
  pages" premise is stale: pages, routes, nav, and backend all exist (details in §B). No LARGE
  new-page work. Only a layout-fidelity pass remains.
- **Only ONE arguably-LARGE item: the Incidents/RCA screen** — needs restructuring to the v3
  3-column composition, and a genuinely-new *7-run brute-force sparkline* that needs a real
  cross-run series (data + honesty question). Everything else is TRIVIAL/SMALL fidelity.
- **~13 token values drift + no Geist font loaded** — cheap but touches every screen at once, so do
  it first as one foundation change.

---

## A. GLOBAL / FOUNDATION

### A1. Font — Geist not loaded  **[TRIVIAL–SMALL]**
- v3: `<link>` Google Fonts `Geist:400;500;600;700` + `Geist Mono:400;500;600`; body
  `font-family:'Geist',system-ui`; mono `'Geist Mono',ui-monospace`.
- Shipped: NO Geist anywhere (`web/index.html` has no font link; `web/src` has none).
  `itsoc.css:24-25` `--sans` = `-apple-system,…,Inter,system-ui` (system fallback), `--mono` =
  `ui-monospace,…`. App renders in the OS sans, not Geist.
- Fix: add the font link (or self-host) + set `--sans:'Geist',…` / `--mono:'Geist Mono',…`.
- ⚠️ **Decision for god:** loading from `fonts.googleapis.com` is a network egress on a
  "nothing leaves this machine" local tool. Recommend **self-hosting** the Geist woff2 in
  `web/public/` and `@font-face`, not the CDN link, to keep the honesty posture. Self-host makes
  this SMALL, not TRIVIAL.

### A2. Design-token values drift  **[TRIVIAL ×~13, one file]**
`itsoc.css:17-31` vs v3 `:root`/`[data-theme=light]` (dc lines 15-16). Dark deltas:
| token | v3 | shipped |
|---|---|---|
| bg | `#09090b` | `#0b0d12` |
| panel/`--pan` | `#0e0e12` | `#14161d` |
| panel2/`--pan2` | `#17171c` (raised/hover, *lighter*) | `#0f1218` (*darker* — role inverted) |
| border/`--bd` | `#1e1e24` | `#1e222c` |
| ink | `#ededf0` | `#e7eaf1` |
| mut | `#8f8f98` | `#828b9c` |
| mut2 | `#5c5c66` | `#5c6474` |
| accent/`--acc` | `#8b7cff` | `#7c6cff` |
| crit | `#f26d78` | `#f0616d` |
| high | `#f0a54a` | `#f2a33c` |
| med | `#d3b23a` | `#d6b02e` |
| low | `#3ecf8e` | `#33c895` |
- v3 adds semantic tokens **`--inset` `--track` `--fill`** (insets, chart tracks, bar fills) not in
  shipped. Light theme differs similarly (v3 `--panel2:#f1f1f4` vs shipped `--pan2:#fbfbfd`, etc).
- ⚠️ `--pan2` role is *inverted*: v3 `panel2` is a raised/hover tint lighter than `panel`; shipped
  `--pan2` is darker than `--pan` and used for the sidebar. A blind value-swap will visually invert
  the sidebar — must be reviewed per-use, so tag this **SMALL** overall, not pure TRIVIAL.
- Also mirror the drift in `web/src/index.css` shadcn triplets + `--sev-*` (kept in lock-step for
  un-migrated Tailwind interiors — but everything is now is-*, so this may be prunable).

### A3. Sidebar width 220 → 212px  **[TRIVIAL]**
`itsoc.css:44-45,279` uses `220px`; v3 sidebar is `212px`. One value (3 occurrences).

### A4. Banned unicode glyphs (line-icons-only rule)  **[TRIVIAL]**
v3 non-negotiable: line icons only, "never unicode glyphs (no ◈ ▦ ≋)". Shipped uses:
- `AppShell.tsx:354` — `◆ AI Analyst` (rail launcher) — **replace with a Lucide icon**.
- `Collectors.tsx:93` — `≋` (explicitly a banned glyph) — replace.
- `Overview.tsx:19` (`▲/▼` delta), `Alerts.tsx:308` (`▲/▼` sort), `CopilotRail.tsx:587` (`▲` trend)
  — filled triangles; swap for arrow chars (v3 allows `→`) or tiny Lucide chevrons.

### A5. Sidebar "RECENT INCIDENTS" contextual list  **[SMALL / MEDIUM]**
v3 sidebar (dc:75-78): on the Incidents route, a `RECENT INCIDENTS` group appears under nav —
dot + entity + tiny severity word (server-01 CRIT, db-02 HIGH…). Shipped `AppShell.tsx` has no such
contextual list. New route-aware sidebar sub-component fed by real incidents. **MEDIUM** if wired to
live data, **SMALL** if a simple top-3 slice.

### A6. Sidebar footer meta line  **[TRIVIAL]**
v3 foot (dc:100-102): green dot + "Ankit K." + "ANALYST" + mono `rules v7 · qwen3:8b · local`.
Shipped `is-side-foot` has user + Logout + model var — verify it renders the mono `rules · model ·
local` line and the ANALYST role uppercase. Likely a label tweak only.

---

## B. ENRICHMENT & OEM ENGINE — **already shipped (NOT a gap)**
Confirms/closes candidate delta #2. **Frontend + backend both exist:**
- Pages: `web/src/pages/Enrichment.tsx`, `web/src/pages/OemEngine.tsx` (real files, not stubs).
- Routes: `App.tsx:51-52` (`/enrichment`, `/oem`). Nav: `AppShell.tsx:40-41` (Experimental group).
- Backend: `console/ti_oem.py` — `enrich_ip`, `ti_key_status` (OTX/AbuseIPDB), `create_connector`,
  `connector_view`, `templates` (Cisco Firepower/PANOS/etc), masked-secret storage.
- Serve routes (`serve.py:1391-1508`): GET `/api/ti/keys`, `/api/oem/connectors`,
  `/api/oem/templates`; POST `/api/ti/enrich`, `/api/oem/connectors`, `/api/oem/poll`.
- Egress fence present + off-by-default (`serve.py:71-77,1659` `OEM_FENCE_MSG`, `oem_egress_enabled`).
- **Remaining work = fidelity only:** confirm the shipped pages match v3 layout — Enrichment:
  honest banner + Provider-keys card (OTX + AbuseIPDB rows, masked input+Save) + Enrich-an-IP card
  (warn when no key) + Recent-IOC-lookups empty state. OEM: honest banner + Add/update-connector
  form (Template/Name/Vendor/Poll/BaseURL/EventsPath/API-token "stored masked") + Connectors empty
  list. Tag **SMALL** each (layout check, no new endpoints).

---

## C. PER-SCREEN LAYOUT DELTAS

### C1. Incidents / RCA — **the big one [MEDIUM, one sub-item LARGE-ish]**
Shipped `Incidents.tsx` has the *ingredients* (rca-facts + `rca.facts.timeline`, rca-runbook,
rca-hypothesis, is-lifecycle, is-facts, correlated findings, dashed root-cause panel) but NOT the v3
composition. v3 (dc:242-…) wants a **3-column** incident detail:
- **Breadcrumb** `Incidents / INC-4a7f` + header row (CRITICAL pill · bold title · state `New ▾`) +
  meta line "entity → server-01 · detected · span · N correlated · `severity is rule-owned` pill).
  Shipped header is `entity — N correlated finding(s)` + lifecycle steps; no breadcrumb/INC-id, no
  right-aligned state button in this shape.
- **Card: Attack timeline** — horizontal hairline axis with a *tick cluster* (~14 red ticks =
  failed logins), green "login OK" dot, amber "C2 blocked" dot, times beneath, legend. Shipped
  renders `rca.facts.timeline` as a list, **not** the axis+tick-cluster viz. → **MEDIUM** new SVG.
- **Card: Root cause** — "advisory · hypothesis · not a verdict" pill + hypothesis + three rows:
  Runbook / **Chain (T1110 → T1078 → T1571 technique pills)** / Rules. Shipped has runbook +
  hypothesis but no single-card **Chain pill row**; techniques are elsewhere. → SMALL reflow.
- **Card: Evidence — verbatim log lines** (inset, accent left-border, red/green/amber emphasis,
  caption "verbatim from the source log — nothing generated"). Shipped Findings/Alerts has the
  is-evidence block but the **Incident detail does not carry a verbatim-evidence card**. → SMALL
  (reuse is-evidence).
- **Right rail:** Properties list (Severity/State/Entity/Findings/Techniques/First/Last) + a
  **brute-force sparkline card** "last 7 runs · ↑ trending up · forecast: elevated" + analyst card.
  Shipped incident route shows the global copilot rail, **not** an incident Properties+sparkline
  rail. → Properties = SMALL; **sparkline "last 7 runs" = the riskiest item** — needs a real
  cross-run per-entity series (data plumbing) or an honest empty state; must NOT fabricate a trend.
  ⚠️ **Decision for god:** is a real 7-run brute-force series available/derivable, or do we show an
  honest "n/a — needs ≥2 runs"? This determines MEDIUM vs LARGE.

### C2. Overview — drop the donut  **[SMALL]**
v3 Overview (dc:132-181) = 5 KPI cards + **2-column** row (Findings-over-time stacked bars · Top
ATT&CK tactics `derived` pill) + Latest-alerts table. **No donut** (0 donut refs in dc). Shipped
`Overview.tsx:120-134` is `is-grid-3` with **SeverityDonut restored** + AlertsOverTime + TacticBars.
→ Remove donut, go 2-col. (Note: this *reverses* the P1 "donut restored" decision — v3 is the newer
target; flag to human since P1 donut was an approved call.) Provenance strip, KPI deltas, latest
alerts already match. TacticBars & over-time chart present.

### C3. Findings — close  **[SMALL fidelity]**
Shipped Alerts.tsx already matches v3 Findings (dc:184-…): filter row, master-detail, Sev/Time/Rule/
Host/ATT&CK columns, RULE VERDICT·AUTHORITATIVE vs EXPLANATION·ADVISORY blocks, verbatim Evidence,
predicate + event sequence. Spot-check spacing/label parity only. Fix the `▲/▼` sort glyph (A4).

### C4. Sources / Settings / Assets / Threat Intel / Discovery / Vulnerabilities / History /
Reports / Cases / Logout / Login — **all exist in is-*; fidelity spot-check each [SMALL]**
Every screen already ships as an is-* page (`Collectors, Settings, Assets, ThreatIntel, Discovery,
Vulnerabilities, History, Reports, Cases, Login, Logout` all present, all using is-panel/is-table/
is-note). These were built in Design-v2 P2 (Jim). I did **not** line-diff each against v3 markup
(timeboxed) — treat as **one SMALL fidelity pass per screen**: confirm the v3 banner copy, card
structure, and column sets in `ITSOC_ALL_PAGES_DESIGN.md §PAGE LAYOUTS` match. No new backends
implied (all endpoints exist). Honest empty/`n/a` states must be preserved verbatim.

### C5. Command palette & Run switcher  **[TRIVIAL–SMALL]**
Shipped `CommandPalette.tsx` (is-palette*) + `RunSwitcher.tsx` (is-runs*) already match the v3
overlay/dropdown shape. v3 palette groups = Screens / **Actions** (Switch theme, Enable Experimental,
Upload logs, Refresh) / **Ask itsoc** (free-text → analyst). Verify the Actions + Ask-itsoc groups
exist; run-switcher already has Today/Previous + unparsed-amber + current-✓. Spot-check only.

---

## D. PROPOSED PHASING (only real deltas; ~most work already shipped)

**Phase v3.0 — Foundation (1 branch, cheap, touches all screens)** — *~S*
A1 font (self-host Geist), A2 tokens (careful `--pan2` role review), A3 width, A4 glyph sweep,
A6 footer label. Build+vitest gate. This alone gets ~80% of the visual "v3 feel".

**Phase v3.1 — Incidents/RCA recomposition (1 branch, the real build)** — *~M/L*
C1: breadcrumb+header, attack-timeline SVG (tick cluster), root-cause Chain-pill row, evidence card
in detail, right-rail Properties. **Blocked-decision:** the 7-run sparkline (real series vs honest
n/a) — needs god's call before starting. Largest single effort.

**Phase v3.2 — Overview + fidelity sweep (1 branch)** — *~S*
C2 drop donut → 2-col; A5 sidebar RECENT INCIDENTS list; C3/C5 spot-fixes.

**Phase v3.3 — Experimental & auth-screen fidelity pass (1 branch, mechanical)** — *~S each*
B (Enrichment/OEM layout match) + C4 (9 experimental screens + Login/Logout) — banner copy, cards,
columns vs `ITSOC_ALL_PAGES_DESIGN.md`. Parallelizable / could be Jim's since he built P2.

**Rough effort:** v3.0 small, v3.2/v3.3 small-mechanical, v3.1 is the one that carries real risk
(timeline SVG + sparkline-data decision). No LARGE new-page+backend work anywhere.

---

## Honesty caveats
- I did NOT run the server or take screenshots (read-only, no browser) — this is a code/markup diff,
  not a rendered pixel diff. A live pixel pass (the parked `redesign-visual-polish`) still matters
  once a browser is connected.
- C4 experimental screens were confirmed to *exist in is-*, not line-diffed against v3 markup —
  flagged honestly as a spot-check, not a verified match.
- Detector untouched; frozen sha assumed unchanged (no code edited).
