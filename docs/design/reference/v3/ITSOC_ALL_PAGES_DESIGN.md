# itsoc. — every screen, laid out (Claude Design prompt)

Companion to `ITSOC_CLAUDE_DESIGN_PROMPT.md`. Same design language; this lays out **every page,
the sidebar, and the command menu** at the same layout fidelity as the RCA screen.

## Look recap (hold exactly)
Linear × Vercel with Grafana data density. Dark near-black `#09090b` surfaces / `#0e0e12` panels /
`#1e1e24` 1px hairline borders (light: `#fbfbfc` / `#fff` / `#ececef`). One restrained violet accent
`#8b7cff` (light `#6d5cf0`) — active nav, links, focus, one primary button only; everything else
monochrome. Severity dots crit `#f26d78` high `#f0a54a` med `#d3b23a` low `#3ecf8e`. Inter/Geist,
tight tracking, tabular numerals; monospace for IDs/timestamps/rules/evidence. **Line icons only**
(Lucide/Geist, ~1.7px) — never glyphs/emoji. Flat; shadows only on overlays. Clean UTF-8 punctuation.
Wordmark always `itsoc.` lowercase with the dot in accent. Both themes for every screen.

---

## SIDEBAR (212px, every authed screen)
Top: a small rounded accent-tinted square logo mark + `itsoc.` wordmark. Below: a "Search… ⌘K"
command pill (muted, hairline). Primary nav (line icon + label, active = panel-filled with accent
icon): **Overview · Findings · Incidents · Sources · Settings**. On Incidents, a contextual
"RECENT INCIDENTS" list appears under nav (dot + entity + tiny severity word). Then a small
"EXPERIMENTAL" group label with an OFF/ON pill; ON reveals: Assets · Threat Intel · Discovery ·
Vulnerabilities · History. Footer pinned bottom: a green status dot + user name, "Analyst" role
(muted uppercase), a Logout row (line icon), and a mono meta line "rules v7 · qwen3:8b · local".

## TOP BAR (every authed screen)
Left: page title (tight tracking) with a muted **mono subtitle** beneath (context, e.g. run +
lines parsed). Right cluster: a primary **Upload logs** button (ink-on-bg), a **run-switcher** pill
(filename + chevron), **Runs** and **Refresh** ghost buttons, and a **theme toggle** icon button.

## COMMAND / CUSTOMIZATION MENU (⌘K overlay)
Centered floating panel with a soft shadow. Top: a search input with a leading search icon and an
`ESC` hint. Body: grouped results — **Screens** (Overview, Findings, Incidents, Sources, Settings,
Assets, Threat Intel…), **Actions** (Switch theme, Enable Experimental features, Upload logs,
Refresh dashboard), and **Ask itsoc** (free text → routes to the AI analyst). Each row = line icon
+ label; active row accent-tinted with an ↵ affordance. Footer: "↑↓ navigate · ↵ select · esc
close" left, "itsoc. command palette" right.

## RUN SWITCHER (dropdown from the top-bar pill)
Floating panel: a "Search runs…" input; grouped **Today / Previous runs**; each row = filename
(mono) + timestamp + findings count on the right; the current run is accent-tinted with a ✓;
unparsed runs are flagged in the high/amber color. Scrolls at length.

---

## PAGE LAYOUTS

### Login (no sidebar)
Split screen. **Left brand panel:** logo mark + `itsoc.` wordmark, a large tagline "Local, honest,
rules-first security operations.", three accent-checked value lines, and a dashed honest note "Local
demo — a single profile on this machine." **Right form:** a centered card (max ~360px) with a
segmented "Log in / Sign up" tab control, Username and Passphrase fields, one primary "Sign in to
session →" button, and a small note "Passphrase is scrypt-hashed locally; auth routes through one
swap-seam module ready for future token/passkey." Sign up adds a Name field. Theme toggle top-right.

### Overview (has copilot)
Full-width **mono provenance strip** (file · hosts · lines parsed/unparsed · ruleset · model ·
detector sha). Row of **5 KPI cards** (Total, Critical, High, Medium, Low): small muted label, big
tabular number in severity color, tiny delta ("↓ 52%" / "no prior run" when there's none). Then a
2-column row: a **wide "Findings over time"** card (stacked bar time-series by severity + legend)
and a **"Top ATT&CK tactics"** card (thin horizontal bars + "derived" pill). Then a full-width
**"Latest alerts"** table (Time · Severity dot · Rule mono · Host · Finding), rows drill to
Findings. A sticky **AI-analyst bar** rests at the bottom (or the copilot rail on the right).

### Findings
Filter row: a "Filter findings…" input, a severity select, and a muted "N of M findings · lines
parsed · unparsed" count. Below, **master–detail** (two columns): left a table (Severity tag · Time
mono · Rule mono · Host · ATT&CK pill), rows selectable; right a detail panel — header (severity
tag + rule) → bold finding title → two side-by-side blocks: **RULE VERDICT · AUTHORITATIVE** (colored
verdict word + reason) and **PLAIN-LANGUAGE EXPLANATION · ADVISORY** → a verbatim **Evidence** mono
block (thin accent left-border, matched span highlighted, caption "verbatim — nothing generated") →
two more blocks: **Rule predicate that fired** (mono, arrow-highlighted) and **Event sequence**.

### Incidents / RCA
As specified in the main prompt — three columns (sidebar with contextual recent-incidents list ·
center incident detail with breadcrumb, header, attack-timeline card, root-cause card, evidence
card · right rail with Properties, a brute-force sparkline card, and the itsoc-analyst card).

### Sources (live collectors)
Full-width honest banner ("real listener state — never a fake running"). 2-column row: **Syslog
collector** card (a Listen-port input; two radios Loopback `127.0.0.1` / All-interfaces `0.0.0.0`
with an amber "exposes to the network" warning; Start/Stop buttons + a live state line) and a
**Listener status** facts card (State, real Bind/port — never "undefined", Protocols UDP+TCP,
Messages received, Last message). Below, a **Recent received events** panel (honest empty state).

### Settings (customization)
Honest banner ("only settings that genuinely do something are shown"). Stacked cards (max ~560px):
**Compute location** — radios Local ("nothing leaves this machine") / Remote ("calls an
OpenAI-compatible endpoint, redacted first"); selecting Remote reveals Base URL, Model, API-key
fields; a "Save compute settings" button. **Outbound redaction** — a note that redaction is a
consequence of compute location, "not applicable" while local. **Analyst model** — "Model: qwen3:8b ·
Endpoint: local" with "the model only explains — never sets a severity". **Appearance** — theme
Dark/Light toggle ("saved for next visit").

### Assets (experimental)
Honest "observed entities only" banner. An **Assets** table (Asset mono · Kind HOST/IP · Events ·
Findings · Risk pill · Last seen mono). Below, a **Users at risk** table (User · Events · Findings ·
Risk), with at-risk vs "clean" pills.

### Threat Intel (experimental)
Honest "surfaced, not generated — derived tags, not verdicts" banner. 2-column row: **Indicators of
Compromise** table (Name · Pattern mono · Types · Valid from) from an offline STIX bundle; and a
**Rule → MITRE map** (each rule mono with its technique pills).

### Discovery (experimental)
Honest **active-scan** banner ("private/loopback targets only · user-initiated · this is an active
network operation, not read-only"). A **Scan** card (target host/CIDR input, "Discover live nodes"
and "Service + vulnerability scan" buttons, a warning line). A **Scan status** facts card (State,
Target, Mode, Hosts found, Assets/Vulns stored, Started/Finished). A **Discovered assets** table
(Seen · IP · Hostname · MAC/vendor · OS · Open ports).

### Vulnerabilities (experimental)
Honest banner ("severity is the CVSS band NSE reported; empty = unknown, shown honestly"). A
**Vulnerabilities** table (Asset IP · Name · CVE · Severity · CVSS · Status) or an honest empty
state pointing to Discovery.

### Enrichment (experimental)
Honest banner ("real provider responses, never fabricated"). A **Provider keys** card (AlienVault
OTX + AbuseIPDB rows, each "no key configured / configured", masked input + Save). An **Enrich an
IP** card (input + Enrich button; a warning when no key is set). A **Recent IOC lookups** panel
(honest empty).

### OEM Engine (experimental)
Honest banner ("read-only OEM/API connectors · credentials stored masked · last-run is the real
outcome"). An **Add / update a connector** form (Template select e.g. Cisco Firepower, Connector
name, Vendor, Poll interval, Base URL, Events path, API token — "stored masked, never returned",
Save). A **Connectors** list (honest empty until one is added).

### History (experimental)
Honest banner ("persistent event store · counts are real totals · severity is source-reported").
A **KPI strip** (Events, Critical, High, Assets, Open Vulns, IOC Hits — "source-reported"). 2-column
row: an **Ingest Windows Event Log (.evtx)** card (Choose .evtx) and a **Retention & cleanup** card
(retention-days input, Run cleanup, and a red "Danger — purge all history" box requiring typed
PURGE). Below, an **Events** table (Time · Source type · Host · Event ID · Severity · Message).

### Reports (experimental)
Honest "real files only" banner + a "Generate report" button. A **Download the current run** card
(HTML + JSON primary buttons; CSV/XML/MD secondary). A **Saved reports** table (Report name mono ·
Size · Created), honest empty state.

### Cases (experimental)
Honest note ("analyst-entered, stored locally, not derived — no sample cases invented"). A "+ New
case" button top-right. A cases list, or a dashed empty state "No cases yet."

### Logout
A single honest card: "itsoc. is a local, single-user tool — there is no account, no login, no
server session, so there is nothing to actually sign out of." Explains it can clear local UI state
(theme, dismissed notifications, current search). Buttons: "Clear local UI state" and "Cancel".
(In demo-auth mode, the copy becomes "sign out of this local demo session".)

---

**Deliver order:** the RCA/incident screen and Overview first (both themes), then Findings, Sources,
Settings, and the sidebar + command menu, then the Experimental screens — all one consistent system.
