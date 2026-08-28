# INC-4a7f — the canonical demo scenario (C2 acceptance + C5 demo)

`INC-4a7f` is the fixed, human-memorable id the design kit, the Stage-C **C2**
acceptance criteria and the **C5** demo script all use for one scenario:

> **Brute-force `203.0.113.44` → `server-01`** — a burst of failed logins for
> `admin` from `203.0.113.44` against `server-01`, followed by a successful
> login (credential compromise).

C2 acceptance and the C5 demo therefore refer to **the same object**.

## It is a REAL incident, not a fixture record

Incident ids are **derived from a content hash** (`console/soc.py`,
`derive_incidents`: `inc-<sha1(runId|entity|kind|first|fids_hash)[:12]>`), so they
are not human-chosen and drift with the run date (the run id embeds
`generated_at[:10]`). We do **not** fabricate a record carrying `INC-4a7f` — that
would violate the honesty guardrail, and the incident must be genuine rule output.

Instead:

- **The seed** is the checked-in fixture **`sample-2.log`** (repo root — the same
  sample the console picker offers and C5 drives). Its lines 5–12 are the
  brute-force burst + success from `203.0.113.44` on `server-01`.
- Running the real analysis over it fires the real rule
  (`auth_bruteforce_success`, **critical**, `T1110 Brute Force`), which correlates
  into a real incident with **entity `203.0.113.44`** and **host `server-01`**.
- That incident is made **addressable as `INC-4a7f`** through a minimal alias seam.

## The alias seam (`console/soc.py`)

```
INCIDENT_ALIASES = {"INC-4a7f": {"entity": "203.0.113.44", "entityKind": "ip"}}
```

`get_incident("INC-4a7f")` (and `set_incident_state` / `derive_rca`, which the
demo drives) resolve the alias to whichever **stored, rule-produced** incident
matches the scenario signature, and annotate it with `alias: "INC-4a7f"`. When a
scenario recurs across runs the pick is deterministic (prefer `T1110`, then
earliest detection, then id order).

Guarantees:

- **Real, never faked.** The alias only ever points at an incident the rules
  actually produced. If the scenario has not been analyzed, `INC-4a7f` resolves to
  `None` — an honest empty, never a minted record.
- **Deterministic.** Re-deriving from a fresh store yields the same id; `INC-4a7f`
  is stable by construction regardless of the volatile derived id.
- **Isolated.** No derived id changes. Ordinary incident lookups are byte-for-byte
  unaffected — `INCIDENT_ALIASES` is the only set of ids the seam touches.

Chosen route: **(a) explicit alias**, not (b) forcing the hash to emit `INC-4a7f`.
Route (b) is infeasible (SHA-1 pre-image) and would special-case the derivation,
risking every other incident's id. The alias is additive and leaves the frozen
detector and the derivation untouched.

Asserted by `check_inc4a7f_scenario()` in `console/test_console.py`.
