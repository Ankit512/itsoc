# ITSOC Stage C — Kickoff Questions (Owner Input Sheet)

_Companion to `ITSOC_ORCHESTRATOR_PROMPT.md`. The orchestrator issues this once, verbatim, as its first message to the owner — before the environment gate result, before C0. Autonomous mode does not begin until the blocking answers are recorded. Answers get committed to `docs/STAGE_C_ANSWERS.md` alongside the build doc (secrets excluded — paths to secrets only, never values)._

---

Owner — before I start the autonomous run, I need the following decided. Three are blocking; three have defaults I will apply unless you override. Answer inline.

## Blocking — the run cannot complete without these

**Q1 · Push authority.** May I push to `origin`?
- (a) Continuously — phase branches and merged `main` as each phase auto-gates.
- (b) Once — only after C5 completes clean.
- (c) Never — everything stays local until you review.
- _Default if unanswered: (c). Note: (c) means nothing reaches GitHub during the run._

> Answer:

**Q2 · OPNsense VM (needed by Phase C3).** Will a live OPNsense VM be reachable from this machine by the time C3 starts?
- If **yes**: provide the host/URL now, and the local config-file path where the API key/secret will live (path only — never paste credentials here; they must never appear in chat, CLI args, or logs).
- If **no**: I will build C3 against the abstract connector with a mock, mark the live end-to-end acceptance item **BLOCKED — VM required**, and the C5 demo will run on the mock — the headline demo will not show a real firewall block until the VM exists.
- _This is a provisioning decision only you can make: stand up the VM now, or accept a mocked v1 demo._

> Answer (yes + host + config path / no):

**Q3 · Step-up identity for approvals.** Approvals re-use the Phase-6 scrypt seam.
- (a) Use the existing local profile's passphrase as the demo approver identity.
- (b) Provision a fresh demo identity — you set the name and passphrase locally yourself; tell me only the profile name.
- _Either way, the passphrase is never written in chat, answers file, task cards, or logs._

> Answer:

## Defaults — applied unless you say otherwise

**Q4 · Worker CLIs.** I will assume Codex and Gemini CLIs are installed and authenticated on this machine. If either turns out to be missing at first dispatch, I route that tier's work up to Claude Code agents (slower, same quality bar) and note it in the log — no stop.

> Override (if any):

**Q5 · Org-context seed.** Default `org_context.json`: `server-01 → crown-jewel`, all other observed assets → `standard`. Name any additional crown-jewel or low-criticality assets, or accept the default.

> Override (if any):

**Q6 · Repo rename.** `log-anomaly-detector → itsoc` stays **out of scope** for this run unless you opt in. If opted in, it happens last (end of C5) and only with push authority (a) or (b) from Q1.

> Override (if any):

---

_Once Q1–Q3 are answered: I record answers, run the environment gate, and begin C0. Any question that becomes newly relevant mid-run and is not covered here or in the build doc → I stop and ask; I do not guess._
