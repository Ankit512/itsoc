import { screen, within } from "@testing-library/react";
import App from "@/App";
import { renderApp, mockFetch, consoleState, finding } from "./helpers";
import type { Incident, Rca } from "@/lib/api";

/** Phase 1 (spec §8): the RCA panel in the incident detail must render each
 *  honest state faithfully — facts always; a runbook citation only when the
 *  engine matched one (honest no-match note otherwise); an LLM hypothesis only
 *  when present and guard-passed (withheld-with-note otherwise). And it is
 *  advisory only: no severity appears anywhere inside the panel. */

const ADVISORY_LABEL = "advisory · hypothesis · not a verdict";

function incident(over: Partial<Incident> = {}): Incident {
  return {
    id: "inc-abc123", runId: "test-run", entity: "203.0.113.44", entityKind: "ip",
    title: "203.0.113.44 — 2 correlated finding(s)", severity: "CRITICAL", state: "new",
    findingIds: ["detector-0", "detector-1"], findingCount: 2,
    techniques: [], attackerStatus: "",
    createdAt: "2026-08-13T02:16:44+00:00", firstSeen: "2026-08-13T02:16:44+00:00",
    lastSeen: "2026-08-13T02:18:00+00:00", acknowledgedAt: null, resolvedAt: null,
    timeUncertain: false, ...over,
  };
}

/** Base RCA mirroring soc.derive_rca output; overrides build each state. */
function rca(over: Partial<Rca> = {}): Rca {
  return {
    incidentId: "inc-abc123",
    facts: {
      incidentId: "inc-abc123", entity: "203.0.113.44", entityKind: "ip",
      findingIds: ["detector-0", "detector-1"], membersLoaded: 2,
      rules: ["auth_bruteforce", "auth_bruteforce_success"],
      firstSeen: "2026-08-13T02:16:44+00:00", lastSeen: "2026-08-13T02:18:00+00:00",
      timeline: [
        { t: "02:16:44", label: "First failed login", line: 5, findingId: "detector-0", rule: "auth_bruteforce" },
        { t: "02:18:00", label: "Successful login for 'admin'", line: 41, findingId: "detector-1", rule: "auth_bruteforce_success" },
      ],
      note: null,
    },
    runbook: { matched: false, note: "no runbook match" },
    hypothesis: { text: null, label: ADVISORY_LABEL,
                  note: "model unavailable — deterministic facts only" },
    ...over,
  };
}

async function renderRca(r: Rca) {
  mockFetch({
    "/api/incidents/inc-abc123/rca": r,
    "/api/incidents": { incidents: [incident()] },
    "/console_state.json": consoleState([finding(0), finding(1)]),
  });
  renderApp(<App />, { route: "/findings?facet=incidents&sel=inc-abc123" });
  return await screen.findByTestId("rca-panel");
}

describe("RCA panel — the three honest layers (Phase 1)", () => {
  it("facts-only (model off): facts always render; runbook and hypothesis state their absence", async () => {
    const panel = await renderRca(rca());

    // Layer 1 — deterministic facts, always present.
    const facts = await within(panel).findByTestId("rca-facts");
    expect(facts).toHaveTextContent("auth_bruteforce");
    expect(facts).toHaveTextContent("auth_bruteforce_success");
    expect(facts).toHaveTextContent("2026-08-13T02:16:44+00:00 → 2026-08-13T02:18:00+00:00");
    expect(facts).toHaveTextContent("First failed login");
    expect(facts).toHaveTextContent("Successful login for 'admin'");
    // Layer 2 — no fabricated citation, the engine's own note verbatim.
    expect(within(panel).getByTestId("rca-runbook")).toHaveTextContent("no runbook match");
    // Layer 3 — model off: honest note, no invented prose.
    const hyp = within(panel).getByTestId("rca-hypothesis");
    expect(hyp).toHaveTextContent("model unavailable — deterministic facts only");
    expect(hyp).toHaveTextContent(ADVISORY_LABEL);
  });

  it("runbook-matched: the real citation renders with its file, bar values and verbatim passage", async () => {
    const panel = await renderRca(rca({
      runbook: {
        matched: true, file: "suspicious-outbound.md",
        title: "Suspicious outbound connection (possible C2) response",
        passage: "Identify the process behind the connection on the source host.",
        score: 11.04, coverage: 1,
      },
    }));
    const rb = await within(panel).findByTestId("rca-runbook");
    expect(rb).toHaveTextContent("Suspicious outbound connection (possible C2) response");
    expect(rb).toHaveTextContent("suspicious-outbound.md · score 11.04 · rule coverage 100%");
    expect(rb).toHaveTextContent("Identify the process behind the connection on the source host.");
  });

  it("runbook-no-match: the engine's below-the-bar note renders, never a forced citation", async () => {
    const panel = await renderRca(rca({
      runbook: {
        matched: false,
        note: "no runbook match — best candidate suspicious-outbound.md scored 0.97 (coverage 0%), below the citation bar",
      },
    }));
    const rb = await within(panel).findByTestId("rca-runbook");
    expect(rb).toHaveTextContent("below the citation bar");
    // No citation artifacts: no title line, no quoted passage.
    expect(rb.querySelector("blockquote")).toBeNull();
    expect(rb).not.toHaveTextContent(/score \d/);
  });

  it("hypothesis-shown: guard-passed prose renders WITH the advisory label", async () => {
    const panel = await renderRca(rca({
      hypothesis: {
        text: "The failed-login burst from 203.0.113.44 followed by a success indicates a guessed credential; the account should be treated as compromised.",
        label: ADVISORY_LABEL, note: null,
      },
    }));
    const hyp = await within(panel).findByTestId("rca-hypothesis");
    expect(hyp).toHaveTextContent(/guessed credential/);
    expect(hyp).toHaveTextContent(ADVISORY_LABEL);
    expect(hyp).not.toHaveTextContent(/withheld|model unavailable/);
  });

  it("hypothesis-withheld: the guard's note and reasons render, never substitute prose", async () => {
    const panel = await renderRca(rca({
      hypothesis: {
        text: null, label: ADVISORY_LABEL,
        note: "withheld — failed the explanation consistency guard",
        reasons: ["names IP 198.51.100.7, which is not in this finding's entities or evidence"],
      },
    }));
    const hyp = await within(panel).findByTestId("rca-hypothesis");
    expect(hyp).toHaveTextContent("withheld — failed the explanation consistency guard");
    expect(hyp).toHaveTextContent("names IP 198.51.100.7");
    expect(hyp).toHaveTextContent(ADVISORY_LABEL);
  });

  it("advisory only: no severity appears anywhere inside the RCA panel", async () => {
    const panel = await renderRca(rca({
      runbook: { matched: true, file: "ssh-brute-force.md",
        title: "SSH brute-force / credential attack response",
        passage: "Block the source IP at the firewall.", score: 21.85, coverage: 1 },
      hypothesis: { text: "A credential-guessing burst preceded the success.",
        label: ADVISORY_LABEL, note: null },
    }));
    // The incident's CRITICAL badge lives in the header ABOVE the panel; the
    // panel itself must never show or imply a severity/verdict (§2 principle 1).
    expect(panel).toHaveTextContent("severity above is rule-owned and unaffected");
    expect(panel.textContent).not.toMatch(/CRITICAL|HIGH|MEDIUM|LOW|severity: /);
  });
});
