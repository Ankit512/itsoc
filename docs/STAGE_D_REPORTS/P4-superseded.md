# P4 superseded — Docker replaced OPNsense as the reference connector

**When:** 2026-08-30. **Ruling:** owner, this session. **Run:** `run_2a9045b4270b`.

## What P4 was

The post-C execution prompt listed P4 as `console/actions/opnsense.py` behind `preview()` / `execute()` / `revoke()`, after D0–D1, with a live item BLOCKED if no OPNsense box.

## What the owner ruled

The Stage C D-2 amendment was a **shift to Docker instead of OPNsense**, not a deferral of OPNsense into Stage D.

**Ratified 2026-08-30:** the connector interface plus `ssh_firewall.py` satisfied the reference-adapter obligation. OPNsense remains the on-demand follow-on it was always designated as.

The reference write-connector already shipped in C3: `console/actions/ssh_firewall.py` against `demo/target/` (nftables-over-SSH, key auth, block/unblock IP, tagged revoke). Runbooks bind `"ssh_firewall"` / `"firewall"`. `console/actions/opnsense.py` was never created.

## Consequence

P4 is **not remaining Stage D work.** It is not dispatched. An OPNsense REST adapter only returns if the owner reopens it as a named extra (design partner / demo optics). Until then it is leftover wording from the pre-D-2 plan.

No code change. Detector freeze unchanged.
