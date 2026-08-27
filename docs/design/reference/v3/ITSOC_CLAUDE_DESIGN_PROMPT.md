# Claude Design prompt — itsoc. SOC console

Paste the block below into Claude Design. It produces the full console in one consistent
system: Linear/Vercel look, Grafana data density, dark + light, with the RCA/incident screen
composed exactly as specified.

---

Design a **local security-operations console called `itsoc.`** — a desktop web app. Produce a
cohesive multi-screen UI in **both dark and light themes**. The north-star feel is **Linear ×
Vercel**: calm, confident, near-monochrome, spacious, precise — with **Grafana-grade data
density** (real charts, dense tables, sparklines) sitting quietly inside that restraint.

## Look & feel (hold this bar exactly)
- **Surfaces (dark):** app background near-black `#09090b`; panels `#0e0e12`; hairline borders
  `#1e1e24` (1px, never heavier). **Light:** bg `#fbfbfc`, panels `#ffffff`, borders `#ececef`.
- **Accent:** a single restrained violet — `#8b7cff` dark / `#6d5cf0` light. Use it ONLY on the
  active nav item, links, focus rings, and one primary action. Everything else is monochrome.
  This is monochrome-first, not a colorful dashboard.
- **Severity colors** (used sparingly, as small dots/text, not big fills): critical `#f26d78`,
  high `#f0a54a`, medium `#d3b23a`, low `#3ecf8e`.
- **Type:** Inter (or Geist), tight tracking (~-0.01em on headings), small and precise. Use a
  monospace (Geist Mono / SF Mono) for IDs, timestamps, rule names, and log evidence. All
  numbers use **tabular figures**.
- **Icons:** clean **line icons only** (Lucide/Geist style, ~1.7px stroke). Never emoji, never
  unicode glyphs (no ◈ ▦ ≋). Never use special glyphs as UI elements.
- **Punctuation:** clean typographic middots ( · ), en/em dashes, and arrows (→) — proper UTF-8.
- **Flat.** No gradients, no drop shadows except on floating overlays (command palette, toasts).
  Generous whitespace. Primary buttons are ink-on-background (dark button on dark = light fill),
  Vercel-style — not a big colored block.

## Global frame (every authenticated screen)
- **Left sidebar (~212px):** `itsoc.` wordmark top (lowercase, one word, the trailing dot in the
  accent color — always this exact treatment). Below it a subtle "Search… ⌘K" command pill. Then
  primary nav with line icons: **Overview, Findings, Incidents, Sources, Settings** (active item =
  panel-filled with accent icon). Then a small **"Experimental"** group label with an OFF/ON pill
  that reveals Assets, Threat Intel, Discovery, Vulnerabilities, History. Footer: a green status
  dot + user name + "Analyst" role, and a small mono line "rules v7 · qwen3:8b · local".
- **Top bar:** page title (tight) with a muted mono subtitle beneath (e.g. run + lines parsed).
  Right side: a primary "Upload logs", a run-switcher pill (filename + chevron), and a theme
  toggle icon.
- **Command palette (⌘K):** centered overlay, search input, a list of screens/actions with line
  icons, keyboard-hint footer.
- **AI copilot rail (right, ~300px):** present on Overview and Incidents. See "AI analyst" below.

## THE RCA / INCIDENT SCREEN — compose exactly like this
Three columns: sidebar · center incident detail · right rail.
- **Center, top:** a breadcrumb "Incidents / INC-4a7f". Then a header row: a small **CRITICAL**
  severity pill, a bold title "Brute-force → successful compromise", and a right-aligned state
  button "New ▾". A muted meta line: "203.0.113.44 → **server-01** · detected 02:16:41 · span
  2m 29s · 3 correlated findings" with a subtle "severity is rule-owned" pill.
- **Card: Attack timeline.** A clean horizontal timeline on a hairline axis: a cluster of ~14
  short red tick marks (failed logins), one green dot labeled "login OK", and one amber dot far
  right labeled "C2 blocked", with times (02:16:41 · 02:16:52 · 02:19:10) beneath. A tiny legend.
- **Card: Root cause.** An "advisory · hypothesis · not a verdict" pill top-right. A 2–3 sentence
  grounded hypothesis (accent-colored inline code for entities like `admin`). Below a hairline:
  three labeled rows — **Runbook** ("matched `auth_bruteforce.md` — rotate the credential… · score
  4.1 · coverage 100%"), **Chain** (T1110 → T1078 → T1571 as small accent-tinted technique pills),
  **Rules** (mono rule names).
- **Card: Evidence — verbatim log lines.** A monospace block on a slightly inset surface with a
  thin accent left-border. Show ~5 real log lines: two `Failed password` (red emphasis), a muted
  "… 11 more failed attempts …", one `Accepted password` (green emphasis), one `OUTBOUND BLOCK`
  (amber). Caption: "verbatim from the source log — nothing generated".
- **Right rail:** a **Properties** list (Severity: CRITICAL pill, State, Entity, Findings,
  Techniques as small pills, First seen, Last seen — mono values). Below, a small **sparkline
  card** "Brute-force on server-01 · last 7 runs" (rising area line, accent) with "↑ trending up ·
  forecast: elevated". Below that, the **itsoc analyst** card (advisory pill): a user question
  bubble "What's the root cause here?" and an answer bubble that interprets THIS incident, citing
  "from 3 findings + `auth_bruteforce.md`", plus two suggestion chips and an "Ask about this
  incident…" input, footed with "Rules set severity. I interpret & explain — I don't decide."

## Other screens (same system)
- **Overview:** a mono run-provenance strip; a row of 5 KPI cards (Total/Critical/High/Medium/Low,
  deltas only when a prior run exists, else "no prior run"); a wide **findings-over-time** stacked
  bar chart (by severity — a real time-series, never a solid block); a **Top ATT&CK tactics** panel
  (thin horizontal bars, "derived" pill); a **Latest alerts** table with a severity dot + mono rule.
- **Findings:** filter row, then master–detail: a left table (Sev · Time · Rule · Host · ATT&CK)
  and a right detail panel with two side-by-side blocks — **RULE VERDICT · AUTHORITATIVE** (colored
  verdict + reason) and **PLAIN-LANGUAGE EXPLANATION · ADVISORY** — then a verbatim **Evidence**
  mono block, then the **rule predicate** (mono) and **event sequence**.

## AI analyst — showcase, not just chat
The copilot can **render real views inline** on request: "show me the critical incidents" → a
compact incident table in the rail; "summarize the dashboard" → a small KPI strip + one grounded
line; "what's on server-01?" → an entity summary. Each card is advisory-labeled, cites its real
sources ("cited: N findings"), and links to the full page. The AI chooses *what to surface*; it
never states a verdict.

## Non-negotiable honesty (keep these labels verbatim)
"RULE VERDICT · AUTHORITATIVE" vs "EXPLANATION · ADVISORY"; "derived tags — not verdicts";
"verbatim from the source log — nothing generated"; "observed entities only"; "severity is
rule-owned"; honest "n/a" and empty states (never invented rows); the Experimental group is OFF
by default.

**Deliver:** the RCA/incident screen first (dark + light), then Overview and Findings, all in one
consistent system with the exact tokens, icons, and spacing above.
