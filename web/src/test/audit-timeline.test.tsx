// @ts-expect-error node:crypto type declarations not included in browser tsconfig
import crypto from "node:crypto";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { AuditTimeline } from "@/components/AuditTimeline";
import type { AuditEntry, AuditVerification, AuditStatus } from "@/lib/api";

const GENESIS = "0".repeat(64);
const FIELDS = [
  "ts",
  "actor",
  "incident_id",
  "runbook_id",
  "step",
  "eligibility_proof",
  "evidence_refs",
  "request_redacted",
  "response_verbatim",
  "status",
  "prev_hash",
  "entry_hash",
] as const;
const HASHED_FIELDS = FIELDS.filter((f) => f !== "entry_hash");
const STATUSES = ["approved", "rejected", "executed", "failed"] as const;

/** Canonical JSON matching console/audit.py exactly: sorted keys, no whitespace, UTF-8 */
function canonicalJson(payload: unknown): string {
  if (payload === null || typeof payload !== "object") {
    return JSON.stringify(payload);
  }
  if (Array.isArray(payload)) {
    return "[" + payload.map(canonicalJson).join(",") + "]";
  }
  const obj = payload as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`);
  return "{" + pairs.join(",") + "}";
}

/** Compute sha256 entry hash matching console/audit.py compute_hash */
function computeHash(entry: Record<string, unknown>): string {
  const payload: Record<string, unknown> = {};
  for (const f of HASHED_FIELDS) {
    payload[f] = entry[f] ?? null;
  }
  return crypto.createHash("sha256").update(canonicalJson(payload), "utf8").digest("hex");
}

/**
 * Real verification function matching console/audit.py verify_chain() byte-for-byte.
 * This is the real integrity checker used to prove tampering honestly.
 */
function verifyAuditChain(entries: AuditEntry[]): AuditVerification {
  const result: AuditVerification = {
    ok: true,
    count: entries.length,
    break: null,
    head: null,
  };

  let prev = GENESIS;
  let head: string | null = null;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i] as unknown as Record<string, unknown>;
    if (!entry || typeof entry !== "object") {
      result.ok = false;
      result.break = { index: i, reason: "line is not a JSON object" };
      return result;
    }

    const missing = FIELDS.filter((f) => !(f in entry));
    if (missing.length > 0) {
      result.ok = false;
      result.break = { index: i, reason: "entry is missing required field(s): " + missing.join(", ") };
      return result;
    }

    const status = entry.status as string;
    if (!STATUSES.includes(status as (typeof STATUSES)[number])) {
      result.ok = false;
      result.break = {
        index: i,
        reason: "status is not one of " + STATUSES.join("|"),
        expected: STATUSES.join("|"),
        found: status,
      };
      return result;
    }

    if (entry.prev_hash !== prev) {
      result.ok = false;
      result.break = {
        index: i,
        reason: "prev_hash does not match the previous entry_hash (the chain is cut here)",
        expected: prev,
        found: String(entry.prev_hash),
      };
      return result;
    }

    const recomputed = computeHash(entry);
    if (recomputed !== entry.entry_hash) {
      result.ok = false;
      result.break = {
        index: i,
        reason: "entry_hash does not match the entry's contents (this entry was modified after it was written)",
        expected: String(entry.entry_hash),
        found: recomputed,
      };
      return result;
    }

    prev = entry.entry_hash as string;
    head = prev;
  }

  result.head = head;
  return result;
}

/** Helper to generate a validly linked, cryptographically hashed audit chain */
function createValidAuditChain(): AuditEntry[] {
  const chain: AuditEntry[] = [];

  const raw0 = {
    ts: "2026-08-29T12:00:00Z",
    actor: "analyst",
    incident_id: "inc-4a7f",
    runbook_id: "rb-block-ip",
    step: "approve",
    eligibility_proof: { eligible: true, technique: "T1110" },
    evidence_refs: ["rec-101", "rec-102"],
    request_redacted: "nft add element inet itsoc blacklist { [IP-1] comment \"itsoc:appr-4a7f\" }",
    response_verbatim: null,
    status: "approved" as AuditStatus,
    prev_hash: GENESIS,
  };
  const hash0 = computeHash(raw0);
  const entry0: AuditEntry = { ...raw0, entry_hash: hash0 };
  chain.push(entry0);

  const raw1 = {
    ts: "2026-08-29T12:00:05Z",
    actor: "analyst",
    incident_id: "inc-4a7f",
    runbook_id: "rb-block-ip",
    step: "execute",
    eligibility_proof: null,
    evidence_refs: ["rec-101"],
    request_redacted: "nft add element inet itsoc blacklist { [IP-1] comment \"itsoc:appr-4a7f\" }",
    response_verbatim: "element added to inet itsoc blacklist",
    status: "executed" as AuditStatus,
    prev_hash: hash0,
  };
  const hash1 = computeHash(raw1);
  const entry1: AuditEntry = { ...raw1, entry_hash: hash1 };
  chain.push(entry1);

  const raw2 = {
    ts: "2026-08-29T12:15:00Z",
    actor: "analyst",
    incident_id: "inc-4a7f",
    runbook_id: "rb-isolate-host",
    step: "reject",
    eligibility_proof: null,
    evidence_refs: [],
    request_redacted: null,
    response_verbatim: null,
    status: "rejected" as AuditStatus,
    prev_hash: hash1,
  };
  const hash2 = computeHash(raw2);
  const entry2: AuditEntry = { ...raw2, entry_hash: hash2 };
  chain.push(entry2);

  return chain;
}

describe("AuditTimeline (is-audit-timeline)", () => {
  it("renders a verified clean chain with footer, entries, and isolated status palettes", () => {
    const chain = createValidAuditChain();
    const verification = verifyAuditChain(chain);

    // Assert the verification function honestly passed
    expect(verification.ok).toBe(true);
    expect(verification.count).toBe(3);
    expect(verification.break).toBeNull();
    expect(verification.head).toBe(chain[2].entry_hash);

    render(<AuditTimeline entries={chain} verification={verification} />);

    // 1. Footer is present and indicates verified chain
    const footer = screen.getByTestId("audit-chain-verified");
    expect(footer).toBeInTheDocument();
    expect(footer).toHaveTextContent(/chain verified/);
    expect(footer).toHaveTextContent(/3 entries/);
    expect(footer).toHaveTextContent(chain[2].entry_hash.slice(0, 8));

    // 2. Broken banner and empty state are NOT in the document
    expect(screen.queryByTestId("audit-chain-broken-banner")).not.toBeInTheDocument();
    expect(screen.queryByTestId("audit-chain-empty")).not.toBeInTheDocument();

    // 3. Entries are rendered with mono timestamps, actors, runbooks, and hashes
    expect(screen.getByTestId("audit-entry-0")).toBeInTheDocument();
    expect(screen.getByTestId("audit-entry-1")).toBeInTheDocument();
    expect(screen.getByTestId("audit-entry-2")).toBeInTheDocument();

    expect(screen.getAllByText("@analyst").length).toBe(3);
    expect(screen.getAllByText("rb-block-ip").length).toBe(2);
    expect(screen.getByText("rb-isolate-host")).toBeInTheDocument();
    expect(screen.getAllByText(/prev:/).length).toBe(3);
    expect(screen.getAllByText(/hash:/).length).toBe(3);

    // 4. Command previews are rendered
    expect(screen.getAllByText(/Command Preview/).length).toBe(2);
    expect(screen.getByText(/Execution Response/)).toBeInTheDocument();

    // 5. Palette isolation: non-failed chips must not use the crit palette
    const approvedChip = screen.getByTestId("chip-approved");
    const executedChip = screen.getByTestId("chip-executed");
    const rejectedChip = screen.getByTestId("chip-rejected");

    expect(approvedChip).toHaveClass("is-chip--approved");
    expect(approvedChip).not.toHaveClass("is-chip--failed");

    expect(executedChip).toHaveClass("is-chip--executed");
    expect(executedChip).not.toHaveClass("is-chip--failed");

    expect(rejectedChip).toHaveClass("is-chip--rejected");
    expect(rejectedChip).not.toHaveClass("is-chip--failed");
  });

  it("applies critical severity palette (--crit) to failed status ONLY", () => {
    const chain = createValidAuditChain();
    // Add a failed entry
    const rawFailed = {
      ts: "2026-08-29T12:20:00Z",
      actor: "analyst",
      incident_id: "inc-4a7f",
      runbook_id: "rb-block-ip",
      step: "execute",
      eligibility_proof: null,
      evidence_refs: [],
      request_redacted: "nft add element inet itsoc blacklist { [IP-1] }",
      response_verbatim: "ssh: connect to host 127.0.0.1 port 2222: Connection refused",
      status: "failed" as AuditStatus,
      prev_hash: chain[2].entry_hash,
    };
    const hashFailed = computeHash(rawFailed);
    const entryFailed: AuditEntry = { ...rawFailed, entry_hash: hashFailed };
    chain.push(entryFailed);

    const verification = verifyAuditChain(chain);
    expect(verification.ok).toBe(true);

    render(<AuditTimeline entries={chain} verification={verification} />);

    const failedChip = screen.getByTestId("chip-failed");
    expect(failedChip).toHaveClass("is-chip--failed");
    expect(failedChip).toHaveTextContent("failed");
  });

  it("PROVES HONESTY ON REAL TAMPER: modifying an entry's content breaks hash and displays CHAIN BROKEN banner", () => {
    // 1. Start with a real valid 3-entry chain
    const chain = createValidAuditChain();
    const originalEntry1Hash = chain[1].entry_hash;

    // 2. TAMPER WITH ENTRY 1: modify the redacted request command payload
    const tamperedChain: AuditEntry[] = [
      chain[0],
      {
        ...chain[1],
        request_redacted: "nft add element inet itsoc blacklist { 198.51.100.99 }", // TAMPERED!
      },
      chain[2],
    ];

    // 3. Run real verification against the tampered chain
    const verification = verifyAuditChain(tamperedChain);

    // Assert real verification detected the exact break
    expect(verification.ok).toBe(false);
    expect(verification.break).not.toBeNull();
    expect(verification.break?.index).toBe(1);
    expect(verification.break?.reason).toContain(
      "entry_hash does not match the entry's contents (this entry was modified after it was written)",
    );
    expect(verification.break?.expected).toBe(originalEntry1Hash);
    expect(verification.break?.found).toBe(computeHash(tamperedChain[1] as unknown as Record<string, unknown>));

    // 4. Render the component with the real broken verification result
    render(<AuditTimeline entries={tamperedChain} verification={verification} />);

    // 5. Assert the loud CHAIN BROKEN banner is rendered with exact diagnostic numbers
    const banner = screen.getByTestId("audit-chain-broken-banner");
    expect(banner).toBeInTheDocument();
    expect(banner).toHaveTextContent("CHAIN BROKEN at entry #1");
    expect(banner).toHaveTextContent(
      "entry_hash does not match the entry's contents (this entry was modified after it was written)",
    );
    expect(banner).toHaveTextContent(originalEntry1Hash);
    expect(banner).toHaveTextContent(verification.break?.found ?? "");

    // 6. Assert "chain verified" footer is NOT rendered
    expect(screen.queryByTestId("audit-chain-verified")).not.toBeInTheDocument();

    // 7. Broken entry in the timeline is marked with broken class
    const entry1Element = screen.getByTestId("audit-entry-1");
    expect(entry1Element).toHaveClass("is-audit-entry--broken");
  });

  it("PROVES HONESTY ON REAL TAMPER: cutting the chain (altering prev_hash) breaks verification and reports cut", () => {
    const chain = createValidAuditChain();
    const badPrevHash = "deadbeef".repeat(8);

    // TAMPER WITH ENTRY 2: sever prev_hash link
    const severedChain: AuditEntry[] = [
      chain[0],
      chain[1],
      {
        ...chain[2],
        prev_hash: badPrevHash, // TAMPERED!
      },
    ];

    const verification = verifyAuditChain(severedChain);

    expect(verification.ok).toBe(false);
    expect(verification.break?.index).toBe(2);
    expect(verification.break?.reason).toContain(
      "prev_hash does not match the previous entry_hash (the chain is cut here)",
    );
    expect(verification.break?.expected).toBe(chain[1].entry_hash);
    expect(verification.break?.found).toBe(badPrevHash);

    render(<AuditTimeline entries={severedChain} verification={verification} />);

    const banner = screen.getByTestId("audit-chain-broken-banner");
    expect(banner).toBeInTheDocument();
    expect(banner).toHaveTextContent("CHAIN BROKEN at entry #2");
    expect(banner).toHaveTextContent("the chain is cut here");
    expect(banner).toHaveTextContent(chain[1].entry_hash);
    expect(banner).toHaveTextContent(badPrevHash);

    expect(screen.queryByTestId("audit-chain-verified")).not.toBeInTheDocument();
  });

  it("renders an empty ledger honestly as empty (NEVER as verified)", () => {
    const emptyVerification: AuditVerification = {
      ok: true,
      count: 0,
      break: null,
      head: null,
    };

    render(<AuditTimeline entries={[]} verification={emptyVerification} />);

    const empty = screen.getByTestId("audit-chain-empty");
    expect(empty).toBeInTheDocument();
    expect(empty).toHaveTextContent("No audit entries recorded yet");

    // Must NEVER show verified footer on empty ledger
    expect(screen.queryByTestId("audit-chain-verified")).not.toBeInTheDocument();
    expect(screen.queryByTestId("audit-chain-broken-banner")).not.toBeInTheDocument();
  });

  it("filters entries by incidentId when specified", () => {
    const chain = createValidAuditChain();
    // Add entry for a different incident
    const rawOther = {
      ts: "2026-08-29T12:30:00Z",
      actor: "analyst",
      incident_id: "inc-9999",
      runbook_id: "rb-isolate-host",
      step: "reject",
      eligibility_proof: null,
      evidence_refs: [],
      request_redacted: null,
      response_verbatim: null,
      status: "rejected" as AuditStatus,
      prev_hash: chain[2].entry_hash,
    };
    const entryOther: AuditEntry = { ...rawOther, entry_hash: computeHash(rawOther) };
    const fullChain = [...chain, entryOther];
    const verification = verifyAuditChain(fullChain);

    render(<AuditTimeline entries={fullChain} verification={verification} incidentId="inc-9999" />);

    // Only inc-9999 should be rendered
    expect(screen.getByText("inc-9999")).toBeInTheDocument();
    expect(screen.queryByText("inc-4a7f")).not.toBeInTheDocument();
  });
});
