# itsoc. — canonical design tokens (single source of truth)

Derived from the two authoritative mockups in this folder (`design_itsoc_overview.html`,
`design_itsoc_incident_rca.html`) and SPEC §2. **Phase 0 turns this into the real CSS-variable
file every component imports.** The two mockups differ trivially (overview uses `--panel/--panel2`,
incident uses `--pan/--pan2`); **canonical names follow SPEC §2 + the incident mockup: `--pan/--pan2`.**
All frontend phases MUST consume these variables — never hardcode a hex.

## Dark (default)
```
--bg:#0d0e12; --pan:#14161d; --pan2:#101218; --bd:#1d212b;
--ink:#e9ebf1; --mut:#828b9c; --acc:#7c6cff;
--crit:#f0616d; --high:#f2a33c; --med:#d6b02e; --low:#33c895;
```
## Light ([data-theme=light])
```
--bg:#f6f7f9; --pan:#ffffff; --pan2:#fbfbfd; --bd:#e7e9ef;
--ink:#12141a; --mut:#6a7385; --acc:#6d5cf0;
--crit:#df4650; --high:#d98600; --med:#b08a00; --low:#12a37e;
```
## Shape / feel
- 3-column app: `nav (~200-210px) · content (1fr) · detail/copilot rail (~288-300px)`.
- Radius: cards 12px, controls 8-9px, pills/tags 5px, chips 20px. 1px borders. Flat, no gradients.
- Type: system stack; tabular-nums for numbers; mono (ui-monospace) for rules/IDs/evidence.
- Accent used sparingly (active nav, primary buttons, links, chart series highlight).
- Honesty surfaces are DESIGN ELEMENTS — preserve verbatim: "severity is rule-owned",
  "derived · not a verdict", "advisory · hypothesis · not a verdict", verbatim evidence block,
  "Rules set severity. I interpret & explain — I don't decide." (copilot footer).
