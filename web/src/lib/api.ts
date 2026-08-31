import { getToken } from "@/lib/auth";

/** Typed client for the EXISTING Python console API (serve.py, 127.0.0.1:8765).
 *  Every shape below mirrors what the backend actually emits today — nothing
 *  here invents fields the server does not send. The Phase B SOC subsystems
 *  (console/soc.py, contract in docs/soc_subsystems.md) are consumed only
 *  where a page exists for them: the Overview's ops footer reads /api/metrics,
 *  which aggregates incidents, assets, users and run history server-side. */

// One authenticated transport for every backend call in this module. It adds
// only Authorization, so multipart FormData keeps its browser-generated
// Content-Type boundary and callers retain their existing headers/signals.
const fetch = (input: RequestInfo | URL, init: RequestInit = {}) => {
  const headers = new Headers(init.headers);
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  return globalThis.fetch(input, { ...init, headers });
};

export interface Delta { pct: number; dir: "up" | "down" }

/** AI copilot Showcase directive (design-v2 §4). The backend picks WHAT real
 *  data to surface; the rail renders it as is-* cards. Every value is real
 *  backend data (rule-owned severities, detector/rule titles) — never a
 *  verdict. `citedFindings` is a real count; empty items → honest "nothing
 *  matches". */
export interface ViewItem {
  id?: string;
  severity?: string;
  entity?: string;
  rule?: string;
  host?: string;
  title?: string;
  findingCount?: number;
  deeplink?: string;
}
export interface ViewKpi { label: string; value: number | null; note?: string }
export interface AskView {
  type: "incidents" | "findings" | "dashboard" | "entity";
  title: string;
  filter?: string;
  items?: ViewItem[];
  kpis?: ViewKpi[];
  deeplink?: string;
  citedFindings?: number;
}

export interface CopilotCitation {
  n?: number | string | null;
  raw?: string;
  findingId?: string | null;
}
export interface CopilotInvestigation {
  answer?: string;
  citations?: CopilotCitation[];
  followups?: string[];
  facts?: Record<string, unknown>;
  source?: string;
}
export interface CopilotRunbookRow {
  id: string;
  name?: string | null;
  severityFloor?: string | null;
  triggerRules?: string[];
  eligible: boolean;
  missing?: string[];
  incidentId?: string | null;
}
export interface CopilotRunbookScan {
  runbooks: CopilotRunbookRow[];
  incidentCount?: number;
  note?: string | null;
}
export interface CopilotForecastPhase {
  name: string;
  observed: boolean;
  watch: boolean;
  tactics?: string[];
}
export interface CopilotForecast {
  thisRun?: {
    runId?: string | null;
    findings?: number;
    matchingLines?: number;
    topTitle?: string | null;
    topSev?: string | null;
  };
  techniques?: { id: string; name: string; tactic: string }[];
  phases?: CopilotForecastPhase[];
  history?: { runId: string; findingCount: number }[];
  note?: string;
  source?: string;
}
export interface CopilotPlaybook {
  advisory?: boolean;
  executable?: boolean;
  source?: string;
  title?: string;
  filename?: string;
  markdown?: string;
  note?: string;
}

export interface OverviewData {
  generatedAt: string;
  timeWindowLabel: string;
  kpis: {
    total: number; critical: number; high: number; medium: number; low: number;
    deltas: Record<"total" | "critical" | "high" | "medium" | "low", Delta | null>;
    /** Matching source lines covered by the grouped findings. Equals `total`
     *  when every finding is a single line. Display-only — not a new verdict. */
    matchingLines?: {
      total: number; critical: number; high: number; medium: number; low: number;
    };
  };
  severityDonut: { bucket: string; count: number; pct: number }[];
  alertsOverTime: { bins: { t: string; critical: number; high: number; medium: number; low: number }[] };
  mitreTactics: { tactic: string; count: number }[];
  latestAlerts: {
    id: string; time: string; severity: string; attackerStatus: string;
    tactics: string[]; name: string; source: string;
    /** dc Latest-alerts columns. Empty string = not derivable for this finding. */
    rule?: string; host?: string;
    occurrences?: number;
  }[];
  ingestion: { acceptedLabel: string; files: { name: string; ok: boolean }[] };
  model: string;
}

/** /api/overview returns {error} instead of data when no run exists yet. */
export type OverviewResponse = OverviewData | { error: string };

export interface EvidenceLine { n: number | string; a: string; hit: string; b: string; crit?: boolean }

export interface Finding {
  id: string;
  sev: string;
  ruleSev: string;
  llmSev: string | null;
  delta: string | null;
  prov: string;
  type: string;
  host: string;
  hostDerived: boolean;
  /** Log channel (CBS/CSI/…) when the line has no hostname. Display only. */
  scope?: string;
  time: string;
  stamp: string;
  title: string;
  ruleWhy: string;
  explanation: string;
  predicate: string;
  ruleRef: string;
  occurrences: number;
  mitre?: { id: string; name: string; tactic: string }[];
  chips: { text: string }[];
  lines: EvidenceLine[];
  linesNote: string | null;
  timeline: { t: string; label: string; line?: number; dot?: string }[];
  /** Advisory AI recommendation. NEVER a verdict — `sev` stays rule-owned. */
  aiTriage?: {
    advisory: boolean;
    ruleSeverity: string;
    aiSeverity: string;
    confidence: string;
    agrees: boolean;
    cause: string;
    falsePositiveHint?: string;
    nextSteps?: string[];
    note: string;
  };
}

export interface ConsoleState {
  idle?: boolean;
  live?: boolean;
  runId?: string;
  runWindow?: string;
  runHosts?: string;
  runParsed?: string;
  generatedAt?: string;
  linesParsed?: number;
  linesUnparsed?: number;
  unrecognized?: boolean;
  emptyInput?: boolean;
  compareRun?: boolean;
  findings: Finding[];
  manifest?: { detector_sha256?: string | null; ruleset?: string | null } & Record<string, unknown>;
  sourceLabel?: string;
  /** Absolute path of the analyzed log on the server — the value GET
   *  /api/stream accepts for tailing the CURRENT run's log (the backend
   *  whitelist is bundled samples + an exact match on this path). */
  logPath?: string;
  /** Set when the model endpoint was down: the run is rules-only (verdicts
   *  complete, advisory explanations skipped) and this says so. */
  llmNote?: string | null;
}

/** /api/progress — the running analysis job, polled after POST /api/analyze. */
export interface AnalyzeJob {
  status: "idle" | "running" | "done" | "error";
  phase?: string;
  done?: number;
  total?: number;
  findings?: number;
  label?: string;
  error?: string | null;
  note?: string | null;
  etaSeconds?: number | null;
  partialReady?: boolean;
}

/** /api/metrics — soc.metrics(): every value is derived or null, never guessed.
 *  mttd/mttr are null until incidents carry real acknowledge/resolve stamps;
 *  the *Basis fields say how many incidents each mean is computed from. */
export interface Metrics {
  openIncidents: number;
  mttaSeconds: number | null; mttaBasis: number;
  mttrSeconds: number | null; mttrBasis: number;
  assetsAtRisk: number | null;
  usersAtRisk: number | null;
  dataSources: number;
}

/** /api/runs — saved runs as navigation entries, newest first, plus which
 *  one is currently open. */
export interface RunEntry {
  file: string; runId: string; label: string; generatedAt: string;
  findings: number; unrecognized: boolean; compareRun: boolean; marked?: number;
}

/** /api/runs-summary — the whole history in one shape. A history file that
 *  cannot be read appears flagged `unreadable` (never silently dropped); a
 *  run predating stored severity counts is `dataComplete: false` and
 *  contributes zeros, never guesses. */
export interface RunsSummaryEntry {
  file: string; runId: string;
  generatedAt?: string; sourceLabel?: string;
  linesParsed?: number; findingCount?: number;
  severityCounts?: Record<string, number>;
  findingSeverityCounts?: Record<string, number>;
  topTechniques?: { id: string; name: string; tactic: string; count: number }[];
  unrecognized?: boolean; dataComplete?: boolean; unreadable?: boolean;
}

export interface RunsSummary {
  runs: RunsSummaryEntry[];
  totals: {
    runCount: number; linesParsed: number; findingCount: number;
    severityCounts: Record<string, number>;
    mitreFrequency: { id: string; name: string; tactic: string; count: number }[];
  };
}

// --- Phase C (Incidents / Threat Intel / Assets / Reports) ---
// Shapes mirror console/soc.py exactly (contract: docs/soc_subsystems.md).
// Every value is derived from real findings/events/files or is null — the UI
// renders null as n/a and an absent inventory as an honest empty state.

export interface Technique { id: string; name: string; tactic: string }

/** Analyst lifecycle: the ONLY mutable part of an incident. Rules still own
 *  severity — `severity` here is the max member verdict, a display rollup.
 *  NEW → TRIAGED → INVESTIGATING → ESCALATED → RESOLVED → CLOSED.
 *  `acknowledged` is accepted as an alias of `triaged` by the API. */
export type IncidentState =
  | "new" | "triaged" | "investigating" | "escalated" | "resolved" | "closed";
export const INCIDENT_STATES: IncidentState[] =
  ["new", "triaged", "investigating", "escalated", "resolved", "closed"];

export interface Incident {
  id: string;
  runId: string;
  entity: string;
  entityKind: "ip" | "host" | "rule";
  title: string;
  severity: string;              // max member severity — display aggregation
  state: IncidentState;
  findingIds: string[];
  findingCount: number;
  techniques: Technique[];
  attackerStatus: string;        // "" when unmapped
  createdAt: string | null;      // earliest finding time = detection
  firstSeen: string | null;
  lastSeen: string | null;
  acknowledgedAt: string | null; // stamped by the analyst, else null
  resolvedAt: string | null;
  timeUncertain: boolean;
  isRollup?: boolean;
  // --- C1-T1: Cases absorbed into Incidents (all additive/optional) ---
  /** "rule" (detector-derived, the default) or "manual" (analyst-created from
   *  an incident-less case). A manual incident must NEVER be rendered as a
   *  rule-detected one. */
  origin?: "rule" | "manual";
  /** Honest badge for a manual incident — analyst-created, carries no rule
   *  verdict. Present only when origin === "manual". */
  manualBadge?: string;
  /** Severity an analyst assigned to the underlying case, if any. Shown ONLY
   *  when present and MUST be labelled "analyst-assigned" — never as a rule
   *  verdict. `severity` is null for manual incidents. */
  analystSeverity?: string | null;
  /** Case records absorbed onto this incident (many-to-many is fine: a case
   *  can appear on several incidents). Empty/absent when no case links here. */
  cases?: EmbeddedCase[];
}

/** A pre-merge Case projected onto an Incident (C1-T1). Loss-free: every case
 *  field travels. `caseStatus` is the analyst's real case lifecycle, kept
 *  separate from the incident's operational `state`. `linkedFindings` is the
 *  analyst's chosen findings — deliberately separate from `Incident.findingIds`
 *  (which is derived and recomputed). */
export interface EmbeddedCase {
  caseId: string;
  title: string;
  notes: string;
  assignee: string;
  caseStatus: CaseStatus;
  caseCreatedAt: string | null;
  caseUpdatedAt: string | null;
  linkedFindings: string[];
  linkedIncidents: string[];
}

/** Normalize an incident from the API. Manual incidents (analyst-created cases)
 *  carry `severity: null` on the wire — no rule verdict. The UI treats severity
 *  as a string everywhere (e.g. `sevVar`/`sevWord` in the shell call
 *  `.toUpperCase()`), so we coerce the null to "" here at the single seam rather
 *  than making every consumer null-safe. "" reads as "no rule severity"; the
 *  manual badge is what actually communicates the state. */
export function normIncident(i: Incident): Incident {
  return { ...i, severity: (i.severity as string | null) ?? "" };
}

export interface RcaFactEvent { t: string; label: string; line?: number; findingId?: string; rule?: string }
export interface RcaFacts {
  incidentId?: string;
  entity?: string;
  entityKind?: string;
  findingIds?: string[];
  membersLoaded?: number;
  rules: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  timeline: RcaFactEvent[];
  note?: string | null;
}

export interface RcaRunbook {
  matched: boolean;
  file?: string;
  title?: string;
  passage?: string;
  score?: number;
  coverage?: number;
  note?: string;
}

export interface RcaHypothesis {
  text: string | null;
  label: string;
  note?: string | null;
  reasons?: string[];
}

/** One reconstructed record in the deterministic investigation timeline. Every
 *  entry carries its source record number `n`, which resolves back to a verbatim
 *  line in the events store — that resolvable {n} is what makes it a fact. */
export interface InvestigationEvent {
  n: number;
  ts: string;
  level: string;
  host: string;
  msg: string;
  raw: string;
  isFinding: boolean;
  findingId?: string | null;
}
export interface InvestigationAsset {
  name: string;
  kind: string;
  role: string;
  records: number[];
  firstRecord: number;
  eventCount: number;
}
export interface InvestigationCorrelation {
  entity?: string | null;
  entityKind?: string | null;
  assets: InvestigationAsset[];
}
export interface InvestigationIoc {
  type: string;
  value: string;
  records: number[];
  firstRecord: number;
  count: number;
}
export interface InvestigationBlastRadius {
  sourceEntity?: string | null;
  assets: string[];
  accounts: string[];
  assetCount: number;
  accountCount: number;
  records: number[];
}
/** The DETERMINISTIC investigation case (console/investigate.py). Rule-derived,
 *  every fact cited by a resolvable record {n}, and never a model output. */
export interface Investigation {
  entity?: string | null;
  entityKind?: string | null;
  timeline: InvestigationEvent[];
  correlation: InvestigationCorrelation;
  iocs: InvestigationIoc[];
  blastRadius: InvestigationBlastRadius;
  recordsConsidered: number[];
  note?: string | null;
}
/** The pending advisory seam carried on the /rca payload — the deterministic
 *  case never waits on it. Advisory prose arrives from the separate /advisory
 *  route and is never a verdict. */
export interface RcaAdvisorySeam {
  status: string;        // "pending" here; the /advisory route fills or times out
  label: string;
  text: string | null;
  note?: string | null;
}

export interface Rca {
  incidentId: string;
  facts: RcaFacts;
  runbook: RcaRunbook;
  hypothesis: RcaHypothesis;
  // Additive (C2): the deterministic investigation file + the pending advisory
  // seam. Optional so pre-C2 payloads (and the existing RCA tests) still type.
  investigation?: Investigation;
  advisory?: RcaAdvisorySeam;
  deterministic?: boolean;
  assembledInMs?: number;
}

/** One grounded advisory agent's output. `status` is the honesty surface:
 *  "complete" (guard-passed prose), "rejected" (all prose withheld), or
 *  "timed_out" (the model was unreachable — shown, never silently dropped). */
export type AdvisoryStatus = "complete" | "rejected" | "timed_out";
export interface AdvisorySentence { text: string; records: number[] }
export interface AdvisoryBlock {
  kind: string;
  label: string;                 // "ADVISORY · narrative" etc.
  status: AdvisoryStatus;
  text: string | null;
  sentences: AdvisorySentence[];
  rejected: { text: string; records: number[]; reasons: string[] }[];
  grounding: { factual_sentences: number; cited_and_resolvable: number; ratio: number };
  note?: string | null;
}
/** The parallel-advisory report (/api/incidents/:id/advisory). Dispatched
 *  SEPARATELY from the deterministic case; the screen must never block on it. */
export interface AdvisoryReport {
  incidentId: string;
  label: string;                 // "ADVISORY"
  status: "complete" | "timed_out";
  blocks: AdvisoryBlock[];
  grounding: { factual_sentences: number; cited_and_resolvable: number; ratio: number };
  note?: string | null;
}

/** Gated-response approval (C3/C4 · D3 step-up). Mirrors the record soc.py
 *  stores in approvals.json. Rules own eligibility (`eligibilityProof` is
 *  runbooks.eligible() verbatim, `evidenceRefs` are rule-owned record numbers);
 *  the connector owns `requestRedacted`/`responseVerbatim` (the command is the
 *  REDACTED preview — raw params never reach this shape); the analyst supplies
 *  only `actor`, filled from the verified step-up username. */
export type ApprovalState = "pending" | "approved" | "rejected" | "executed" | "failed";

export interface EligibilityProof { eligible: boolean; missing: string[]; [k: string]: unknown }
export interface ApprovalRequestRedacted {
  command?: string; description?: string; connector?: string; action?: string;
  params?: Record<string, unknown>; error?: string;
}
export interface ApprovalResponseVerbatim {
  output?: string; connector?: string; action?: string; error?: string;
}
export interface Approval {
  id: string;
  incidentId: string;                       // rule-owned
  runbookId: string;                        // rule-owned
  connector: string;                        // connector-owned
  step: number;
  state: ApprovalState;
  eligibilityProof: EligibilityProof;       // rule-owned (verbatim from eligible())
  evidenceRefs: string[];                    // rule-owned record numbers
  requestRedacted: ApprovalRequestRedacted;  // connector-owned (redacted preview)
  responseVerbatim: ApprovalResponseVerbatim | null;
  actor: string | null;                      // analyst-supplied (verified at step-up)
  failureReason: string | null;
  createdAt: string;
  updatedAt: string;
}

// ---- C4-F1: runbook recommendation (Incidents Response panel) ------------
/** One rule-eligible runbook for an incident. Rule-owned throughout:
 *  `eligibilityProof` is runbooks.eligible() verbatim ({eligible, missing}),
 *  `triggerRules` are the runbook definition's trigger.rule_ids verbatim. No
 *  connector/command/handle — a reference, never something executable. */
export interface EligibleRunbook {
  runbookId: string;
  name: string | null;
  severityFloor: string | null;
  triggerRules: string[];
  eligibilityProof: EligibilityProof;
}
/** The advisory (model) half — a ranking + justifications filtered to the
 *  eligible ids, with an honest status. It can never widen eligibility and
 *  carries no executable handle; the Response panel treats it as advice only. */
export interface RunbookRecommendationAdvisory {
  label: string;
  status: "complete" | "absent" | "timed_out";
  ranking: string[];
  justifications: { runbookId: string; text: string }[];
  note: string | null;
}
export interface RunbookRecommendation {
  type: "runbook_recommendation";
  advisory: true;
  incidentId: string | null;
  eligible: EligibleRunbook[];              // deterministic, rule-owned
  recommendation: RunbookRecommendationAdvisory;   // advisory (model), honest states
}
// --------------------------------------------------------------------------

/** Cross-run brute-force attempt series for an incident's entity (RCA rail
 *  sparkline). A DERIVED display aggregation over run history — never a verdict.
 *  available=false is the honest n/a (fewer than 2 real runs for the entity). */
export interface AttemptPoint { label: string; date: string; attempts: number }
export interface AttemptSeries {
  available: boolean;
  entity: string;
  points: AttemptPoint[];
  note?: string;
  thisRun?: number;
  avg?: number;
  changePct?: number | null;
  direction?: "up" | "down" | "flat";
  forecast?: string;
  runs?: number;
  caption?: string;
}

export interface Asset {
  id: string; name: string; kind: "host" | "ip";
  events: number; findings: number; atRisk: boolean;
  riskScore?: number; maxSeverity?: string | null;
  lastSeen: string | null;
}

export interface UserEntity {
  id: string; name: string; events: number; findings: number; atRisk: boolean;
  riskScore?: number; maxSeverity?: string | null;
}

export interface ThreatIndicator {
  id: string; name: string; pattern: string;
  types: string[]; validFrom: string;
}

export interface ThreatIntel {
  indicators: ThreatIndicator[];
  indicatorSource: string;
  ruleTechniques: Record<string, Technique[]>;
  attackCacheWarm: boolean;
}

export interface Report { name: string; bytes: number; createdAt: string }

/** Downloadable export formats served by GET /api/export. Each is a real
 *  serialization of the CURRENT run's findings (console/export.py) — no
 *  fabricated rows. `label`/`ext` drive the Download panel controls. */
export type ExportFormat = "csv" | "html" | "xml" | "json" | "md";
export const EXPORT_FORMATS: { format: ExportFormat; label: string; ext: string }[] = [
  { format: "csv", label: "CSV", ext: "csv" },
  { format: "json", label: "JSON", ext: "json" },
  { format: "xml", label: "XML", ext: "xml" },
  { format: "html", label: "HTML", ext: "html" },
  { format: "md", label: "Markdown", ext: "md" },
];

/** Both /api/assets and /api/users return {error} (HTTP 200) when the server
 *  is idle — an empty inventory is indistinguishable from "nothing at risk". */
type OrError<T> = T | { error: string };

// --- Cases (Phase C) ---
export type CaseStatus =
  | "new" | "triaged" | "investigating" | "escalated" | "resolved" | "closed";
export const CASE_STATUSES: CaseStatus[] =
  ["new", "triaged", "investigating", "escalated", "resolved", "closed"];

export type CaseActivityKind =
  | "comment" | "note" | "attachment" | "observable"
  | "runbook" | "state" | "assignee" | "system";
export interface CaseActivity { at: string; actor: string; kind: CaseActivityKind; text: string }
export type ObservableType = "url" | "ip" | "hash" | "domain" | "email";
export interface CaseObservable { id: string; type: ObservableType; value: string; verdict?: string }
export type AttachmentKind = "note" | "json" | "html" | "image" | "other";
export interface CaseAttachment { id: string; name: string; size?: number; kind: AttachmentKind }
export interface CaseSummary { what?: string; impact?: string; when?: string }

export interface Case {
  id: string;
  title: string;
  notes: string;
  assignee: string;
  category?: string;
  summary?: CaseSummary;
  status: CaseStatus;
  history?: { status: CaseStatus; at: string }[];
  activity: CaseActivity[];
  observables: CaseObservable[];
  attachments: CaseAttachment[];
  links: { findings: string[]; incidents: string[] };
  createdAt: string;
  updatedAt: string;
}

export interface CaseCreate {
  title: string;
  notes?: string;
  assignee?: string;
  category?: string;
  summary?: CaseSummary;
  links?: { findings?: string[]; incidents?: string[] };
}

export type CasePatch = Partial<Pick<Case, "title" | "notes" | "assignee" | "status" | "category" | "summary">> & { actor?: string };
export interface CaseCommentInput { text: string; actor?: string }
export interface CaseObservableInput { type: ObservableType; value: string; verdict?: string; actor?: string }
export interface CaseAttachmentInput { name: string; size?: number; kind?: AttachmentKind; actor?: string }
export interface CaseRunResult { case: Case; markdown: string; advisory: true; executed: false }

// --- Settings (Phase C) ---
/** Masked compute config from /api/compute — the key is never exposed, only
 *  whether one is set (`hasKey`). Remote fields are absent when mode is local. */
export interface ComputeConfig {
  mode: "local" | "remote";
  baseUrl?: string;
  model?: string;
  hasKey?: boolean;
}

export interface ComputeInput {
  mode: "local" | "remote";
  baseUrl?: string;
  model?: string;
  apiKey?: string;
}

// --- Live syslog collector (socf-syslog) ---
// The real state of the background UDP/TCP listener. `exposed` is true only
// when bound to 0.0.0.0 (reachable from the network) — the UI warns on it.
export interface SyslogStatus {
  running: boolean;
  bind: string;
  port: number;
  protocols: string[];
  exposed: boolean;
  receivedCount: number;
  storedCount: number;
  // Back-pressure accounting (C5-T2). A bounded queue sits between the listeners
  // and the SQLite writer; when it saturates, drops are COUNTED here rather than
  // lost silently in the kernel. `laggingCount` is the live backlog depth.
  ingestedCount: number;
  droppedCount: number;
  laggingCount: number;
  queueCapacity: number;
  queueUsed: number;
  startedAt: string | null;
  lastEventAt: string | null;
  error: string;
}
export interface SyslogStart {
  port: number;
  bind: string;
}

// One row from the persistent store's `events` table (the fields the collector
// panel shows to confirm received syslog actually landed). `severity` is the
// SOURCE-REPORTED level, never a verdict.
export interface StoreEvent {
  id: number;
  ts: string;
  source: string;
  source_type: string;
  host: string;
  src_ip: string;
  severity: string;
  message: string;
  raw: string;
  // Present on the full events read (History page); optional so the syslog
  // panel's narrower use keeps type-checking.
  category?: string;
  event_id?: string;
  user?: string;
  dst_ip?: string;
  action?: string;
}
export interface StoreEventsPage {
  items: StoreEvent[];
  total: number;
  limit: number;
  offset: number;
}

// --- nmap discovery + vuln scan (socf-discovery) ---
// The REAL state of the scanner. This is a dual-use tool: only private/
// loopback/link-local targets are ever accepted (the backend refuses a public
// or publicly-resolving target with an honest 400), every scan is user-
// initiated, and when nmap is not installed the backend returns an honest
// error — never a simulated result. Results land in the persistent store and
// are read back through /api/store/{assets,vulns}.
export interface DiscoveryStatus {
  running: boolean;
  target: string;
  vuln: boolean;
  startedAt: string | null;
  finishedAt: string | null;
  error: string;
  hostsFound: number;
  assetsStored: number;
  vulnsStored: number;
  nmapInstalled: boolean;
}
export interface DiscoveryScanInput {
  target: string;
  vuln?: boolean;
}

// One row from the store's `assets` table — a host nmap actually observed.
export interface StoreAsset {
  id: number;
  ts: string;
  ip: string;
  hostname: string;
  mac: string;
  vendor: string;
  os: string;
  ports: string;
  source: string;
  status: string;
}
export interface StoreAssetsPage {
  items: StoreAsset[];
  total: number;
  limit: number;
  offset: number;
}

// One row from the store's `vulnerabilities` table. `severity` is derived from
// the NSE-reported CVSS band (empty when NSE gave no score) — never guessed.
export interface StoreVuln {
  id: number;
  ts: string;
  asset_ip: string;
  name: string;
  cve: string;
  severity: string;
  cvss: number;
  details: string;
  source: string;
  status: string;
}
export interface StoreVulnsPage {
  items: StoreVuln[];
  total: number;
  limit: number;
  offset: number;
}

// --- TI enrichment + OEM polling (socf-ti-oem) ---
// All keys/tokens are user-supplied and stored secret-masked — the browser only
// ever learns whether one is present (hasKey/hasToken), never the value.
// Verdicts/severity come from the provider's / vendor's real response.
export interface TiKeyStatus { otx: boolean; abuseipdb: boolean }

// One row from the store's `iocs` table — a real provider lookup result.
export interface StoreIoc {
  id: number;
  ts: string;
  ioc: string;
  ioc_type: string;
  provider: string;
  score: number;
  verdict: string;
  details: string;
  source_event_id: number | null;
}
export interface StoreIocsPage {
  items: StoreIoc[]; total: number; limit: number; offset: number;
}

/** POST /api/ti/enrich result. A provider with no key set is listed in
 *  `notConfigured` (not called); a failed call is in `errors` with the real
 *  reason; only real hits are in `results`. `error` is set for an invalid IP. */
export interface TiEnrichResult {
  ip: string;
  error?: string;
  results: StoreIoc[];
  errors: { provider: string; error: string }[];
  notConfigured: string[];
}

/** Browser-safe OEM connector view — presence flags only, never the config
 *  blob or the token. `lastRun`/`lastError` are the REAL poll outcome. */
export interface OemConnector {
  name: string;
  kind: string;
  enabled: boolean;
  interval: number | null;
  lastRun: string | null;
  lastError: string;
  hasConfig: boolean;
  hasToken: boolean;
}
export interface OemConnectorInput {
  name: string;
  config: { vendor?: string; baseUrl?: string; eventsPath?: string };
  enabled?: boolean;
  interval?: number;
  token?: string;
}
export interface OemPollResult {
  name: string; ok: boolean; stored: number; error: string;
}

// --- EVTX ingest + history/retention (socf-evtx-history) ---
// Command-Center KPI counts from store.metrics(). `critical`/`high` count
// SOURCE-REPORTED severities, not anomaly verdicts — label them as such.
export interface StoreMetrics {
  events: number; critical: number; high: number;
  assets: number; openVulns: number; iocHits: number;
}

/** Public settings view: non-secret values, plus which secret keys are set. */
export interface PublicSettings {
  settings: Record<string, string>;
  secrets: Record<string, boolean>;
}

export interface EvtxStatus { available: boolean; message: string }
export interface EvtxIngestResult {
  stored: number; parsed: number; skipped: number; file?: string;
}

/** Filters for the history events read (all optional). */
export interface HistoryQuery {
  q?: string; severity?: string; source_type?: string; host?: string;
  limit?: number; offset?: number;
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  overview: () => getJson<OverviewResponse>("/api/overview"),
  consoleState: () => getJson<ConsoleState>(`/console_state.json?t=${Date.now()}`),
  runs: () => getJson<{ runs: RunEntry[]; current?: string | null }>("/api/runs"),
  runsSummary: () => getJson<RunsSummary>("/api/runs-summary"),
  metrics: () => getJson<Metrics>("/api/metrics"),
  progress: () => getJson<AnalyzeJob>("/api/progress"),

  /** Load a saved run back into the dashboard (POST /api/open). */
  openRun: async (file: string): Promise<{ ok: boolean; error?: string }> => {
    const res = await fetch("/api/open", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file }),
    });
    if (res.ok) return { ok: true };
    const body = await res.json().catch(() => ({}));
    return { ok: false, error: body.error ?? `HTTP ${res.status}` };
  },

  ask: async (question: string): Promise<{ answer?: string; view?: AskView | null; error?: string }> => {
    const res = await fetch("/api/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question }),
    });
    return res.json();
  },

  /** Showcase directive (design-v2 §4): ask the backend which REAL view to
   *  surface for this question. Deterministic + model-free, so it is fast and
   *  works even when the LLM is offline. Returns null when the question is not
   *  a showcase request, or on any non-OK response (the rail then shows prose
   *  only — never an invented card). */
  askView: async (question: string): Promise<AskView | null> => {
    try {
      const res = await fetch("/api/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question, view: true }),
      });
      if (!res.ok) return null;
      const body = (await res.json().catch(() => ({}))) as { view?: AskView | null };
      return body.view ?? null;
    } catch {
      return null;
    }
  },

  copilotAngles: async (): Promise<Record<string, unknown>> => {
    try {
      const res = await fetch("/api/copilot/angles");
      if (!res.ok) return {};
      const body = await res.json().catch(() => ({}));
      return (body && typeof body === "object") ? body as Record<string, unknown> : {};
    } catch {
      return {};
    }
  },

  copilotForecast: async (): Promise<CopilotForecast> => {
    try {
      const res = await fetch("/api/copilot/forecast");
      if (!res.ok) return { phases: [], history: [], note: "forecast unavailable" };
      return (await res.json().catch(() => ({}))) as CopilotForecast;
    } catch {
      return { phases: [], history: [], note: "forecast unavailable" };
    }
  },

  copilotPlaybook: async (): Promise<CopilotPlaybook> => {
    try {
      const res = await fetch("/api/copilot/playbook");
      if (!res.ok) return { markdown: "", note: "playbook unavailable", advisory: true, executable: false };
      return (await res.json().catch(() => ({}))) as CopilotPlaybook;
    } catch {
      return { markdown: "", note: "playbook unavailable", advisory: true, executable: false };
    }
  },

  copilotRunbooks: async (): Promise<CopilotRunbookScan> => {
    try {
      const res = await fetch("/api/copilot/runbooks");
      if (!res.ok) return { runbooks: [], incidentCount: 0, note: "runbook scan unavailable" };
      const body = (await res.json().catch(() => ({}))) as CopilotRunbookScan;
      return {
        runbooks: Array.isArray(body.runbooks) ? body.runbooks : [],
        incidentCount: typeof body.incidentCount === "number" ? body.incidentCount : 0,
        note: typeof body.note === "string" ? body.note : null,
      };
    } catch {
      return { runbooks: [], incidentCount: 0, note: "runbook scan unavailable" };
    }
  },

  copilotSuggest: async (caseId?: string): Promise<string[]> => {
    try {
      const suffix = caseId ? `?caseId=${encodeURIComponent(caseId)}` : "";
      const res = await fetch(`/api/copilot/suggest${suffix}`);
      if (!res.ok) return [];
      const body = (await res.json().catch(() => ({}))) as { questions?: string[] };
      return Array.isArray(body.questions) ? body.questions.filter((q) => typeof q === "string") : [];
    } catch {
      return [];
    }
  },

  investigate: async (question: string): Promise<CopilotInvestigation | null> => {
    try {
      const res = await fetch("/api/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question, investigate: true }),
      });
      if (!res.ok) return null;
      const body = (await res.json().catch(() => ({}))) as { investigation?: CopilotInvestigation | null };
      return body.investigation ?? null;
    } catch {
      return null;
    }
  },

  /** Stream the analyst reply token-by-token over SSE. `onDelta` fires per
   *  chunk; resolves when the model sends `done`. Pass an AbortSignal to
   *  cancel — the backend stops when the connection drops. Errors (unreachable
   *  model, HTTP failure, or an `error` event) reject honestly. */
  askStream: async (
    question: string,
    onDelta: (text: string) => void,
    signal?: AbortSignal,
    onInvestigation?: (inv: CopilotInvestigation) => void,
  ): Promise<void> => {
    const res = await fetch("/api/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question, stream: true }),
      signal,
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error ?? `HTTP ${res.status}`);
    }
    if (!res.body) throw new Error("this browser cannot read a streamed reply");

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      // SSE frames are separated by a blank line.
      let sep: number;
      while ((sep = buffer.indexOf("\n\n")) !== -1) {
        const frame = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        const line = frame.split("\n").find((l) => l.startsWith("data:"));
        if (!line) continue;
        const evt = JSON.parse(line.slice(5).trim()) as
          { delta?: string; done?: boolean; error?: string; investigation?: CopilotInvestigation };
        if (evt.error) throw new Error(evt.error);
        if (evt.investigation && onInvestigation) onInvestigation(evt.investigation);
        if (evt.done) return;
        if (evt.delta) onDelta(evt.delta);
      }
    }
  },

  analyzeUpload: async (file: File): Promise<{ ok: boolean; error?: string }> => {
    const form = new FormData();
    form.append("file", file);
    const res = await fetch("/api/analyze", { method: "POST", body: form });
    if (res.ok || res.status === 202) return { ok: true };
    const body = await res.json().catch(() => ({}));
    return { ok: false, error: body.error ?? `HTTP ${res.status}` };
  },

  /** Ingest a log from a public URL: the backend fetches it (http/https only,
   *  SSRF/size/text-gated) and runs the SAME analyze pipeline. A bad or unsafe
   *  URL comes back as an honest 400 with the real reason. */
  analyzeUrl: async (url: string): Promise<{ ok: boolean; error?: string }> => {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (res.ok || res.status === 202) return { ok: true };
    const body = await res.json().catch(() => ({}));
    return { ok: false, error: body.error ?? `HTTP ${res.status}` };
  },

  // --- Phase C endpoints ---
  incidents: async (state?: IncidentState) => {
    const r = await getJson<{ incidents: Incident[] }>(
      `/api/incidents${state ? `?state=${state}` : ""}`);
    return { incidents: (r.incidents ?? []).map(normIncident) };
  },
  incident: async (id: string) => {
    const r = await getJson<OrError<Incident>>(`/api/incidents/${id}`);
    return "error" in r ? r : normIncident(r);
  },
  incidentRca: (id: string) => getJson<OrError<Rca>>(`/api/incidents/${id}/rca`),
  /** The parallel grounded advisory agents (narrative / ATT&CK / pivots). This
   *  is dispatched SEPARATELY from the deterministic case and may take up to the
   *  server deadline or time out — callers must render it in its own query so the
   *  investigation file never waits on it. */
  incidentAdvisory: (id: string) =>
    getJson<OrError<AdvisoryReport>>(`/api/incidents/${id}/advisory`),
  incidentBruteforce: (id: string) =>
    getJson<AttemptSeries>(`/api/incidents/${id}/bruteforce`),

  // ---- C4-F1: rule-eligible runbooks for the Incidents Response panel ------
  /** The rule-owned eligible-runbooks list for an incident (plus a separate
   *  advisory ranking that can never widen eligibility). Sources the Response
   *  panel; the panel cannot disagree with the engine because this is the same
   *  eligible()/missing data the 409 create path uses. 404 for an unknown id. */
  incidentRunbookRecommendation: (id: string) =>
    getJson<OrError<RunbookRecommendation>>(
      `/api/incidents/${encodeURIComponent(id)}/runbook-recommendation`),
  // --------------------------------------------------------------------------

  /** Analyst lifecycle transition (POST /api/incidents/<id>/state). Returns the
   *  updated incident; 400 (bad state) / 404 (unknown id) reject honestly. */
  setIncidentState: async (id: string, state: IncidentState): Promise<Incident> => {
    const res = await fetch(`/api/incidents/${id}/state`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ state }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
    return normIncident(body as Incident);
  },

  // --- Gated-response approvals (C3/C4 · D3 step-up) ---------------------
  // The single authoritative approval surface. Rules own eligibility; the
  // step-up passphrase is D3 material — it is sent ONLY in the POST body,
  // NEVER in a URL/query, and is never echoed back (a failed step-up returns
  // a generic error with no credential). A 409 carries the engine's own
  // `missing` array verbatim, so the client cannot disagree with the rules.
  approvals: (state?: ApprovalState) =>
    getJson<{ approvals: Approval[] }>(`/api/approvals${state ? `?state=${state}` : ""}`),

  approval: (id: string) =>
    getJson<OrError<Approval>>(`/api/approvals/${encodeURIComponent(id)}`),

  createApproval: async (
    input: { incidentId: string; runbookId: string; stepIndex?: number },
  ): Promise<{ ok: boolean; approval?: Approval; missing?: string[]; error?: string }> => {
    const res = await fetch("/api/approvals", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok
      ? { ok: true, approval: body as Approval }
      : { ok: false, missing: (body as { missing?: string[] }).missing,
          error: (body as { error?: string }).error ?? `HTTP ${res.status}` };
  },

  /** Approve a pending step and fire its connector. `passphrase` is D3 step-up
   *  material: it travels in the request body only, is never placed in the URL,
   *  and is never returned. A wrong passphrase is a generic 401; a stale
   *  re-evaluation is a 409 carrying the engine's `missing` array. */
  approveApproval: async (
    id: string, passphrase: string,
  ): Promise<{ ok: boolean; approval?: Approval; missing?: string[]; error?: string }> => {
    const res = await fetch(`/api/approvals/${encodeURIComponent(id)}/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ passphrase }),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok
      ? { ok: true, approval: body as Approval }
      : { ok: false, missing: (body as { missing?: string[] }).missing,
          error: (body as { error?: string }).error ?? `HTTP ${res.status}` };
  },

  /** Reject a pending approval — also a step-up act (passphrase in the body,
   *  never the URL, never echoed). No connector is ever touched on this path. */
  rejectApproval: async (
    id: string, passphrase: string,
  ): Promise<{ ok: boolean; approval?: Approval; error?: string }> => {
    const res = await fetch(`/api/approvals/${encodeURIComponent(id)}/reject`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ passphrase }),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok
      ? { ok: true, approval: body as Approval }
      : { ok: false, error: (body as { error?: string }).error ?? `HTTP ${res.status}` };
  },

  assets: () => getJson<OrError<{ assets: Asset[] }>>("/api/assets"),
  users: () => getJson<OrError<{ users: UserEntity[] }>>("/api/users"),
  threatIntel: () => getJson<ThreatIntel>("/api/threat-intel"),

  reports: () => getJson<{ reports: Report[] }>("/api/reports"),

  /** Generate a report for the CURRENT run (POST /api/reports). 409 when no run
   *  is loaded — the exporter has nothing real to render. */
  generateReport: async (): Promise<Report> => {
    const res = await fetch("/api/reports", { method: "POST" });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
    return body as Report;
  },

  /** URL of a downloadable export of the CURRENT run in `format` (GET
   *  /api/export). The backend sets Content-Disposition: attachment and a
   *  <runId>.<ext> filename; used as an <a href download>. 409 when idle. */
  exportUrl: (format: ExportFormat) => `/api/export?format=${format}`,

  // --- Cases (Phase C) ---
  // Analyst-entered records in cases.json: GET list, POST create (title
  // required), PATCH one by id. The store is the only writer; nothing is
  // derived — an empty store honestly means no cases.
  listCases: () => getJson<{ cases: Case[] }>("/api/cases"),

  createCase: async (input: CaseCreate): Promise<{ ok: boolean; case?: Case; error?: string }> => {
    const res = await fetch("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, case: body as Case }
                  : { ok: false, error: body.error ?? `HTTP ${res.status}` };
  },

  patchCase: async (id: string, patch: CasePatch): Promise<{ ok: boolean; case?: Case; error?: string }> => {
    const res = await fetch(`/api/cases/${encodeURIComponent(id)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, case: body as Case }
                  : { ok: false, error: body.error ?? `HTTP ${res.status}` };
  },

  addCaseComment: async (id: string, input: CaseCommentInput): Promise<{ ok: boolean; case?: Case; error?: string }> => {
    const res = await fetch(`/api/cases/${encodeURIComponent(id)}/comment`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, case: body as Case } : { ok: false, error: body.error ?? `HTTP ${res.status}` };
  },

  addCaseObservable: async (id: string, input: CaseObservableInput): Promise<{ ok: boolean; case?: Case; error?: string }> => {
    const res = await fetch(`/api/cases/${encodeURIComponent(id)}/observables`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, case: body as Case } : { ok: false, error: body.error ?? `HTTP ${res.status}` };
  },

  addCaseAttachment: async (id: string, input: CaseAttachmentInput): Promise<{ ok: boolean; case?: Case; error?: string }> => {
    const res = await fetch(`/api/cases/${encodeURIComponent(id)}/attachments`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, case: body as Case } : { ok: false, error: body.error ?? `HTTP ${res.status}` };
  },

  addCaseRunbook: async (id: string, runbookId: string): Promise<{ ok: boolean; result?: CaseRunResult; error?: string; reason?: string }> => {
    const res = await fetch(`/api/cases/${encodeURIComponent(id)}/run`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ runbookId }),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, result: body as CaseRunResult }
                  : { ok: false, error: body.error ?? `HTTP ${res.status}`, reason: body.reason };
  },

  // --- Settings (Phase C) ---
  // The masked compute config (never the API key itself). Only real,
  // effective knobs — mode local/remote, and for remote the base URL/model.
  getCompute: () => getJson<ComputeConfig>("/api/compute"),

  setCompute: async (input: ComputeInput): Promise<{ ok: boolean; config?: ComputeConfig; error?: string }> => {
    const res = await fetch("/api/compute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, config: body as ComputeConfig }
                  : { ok: false, error: body.error ?? `HTTP ${res.status}` };
  },

  // --- Syslog collector (socf-syslog) ---
  // Poll the REAL listener state; start/stop the background UDP+TCP listener.
  // A failed start (bad/privileged port, in use) comes back as an honest error.
  syslogStatus: () => getJson<SyslogStatus>("/api/syslog/status"),

  /** Recent events from the persistent store, filtered to the syslog collector,
   *  newest first — used to confirm received messages actually landed. */
  syslogEvents: (limit = 15) =>
    getJson<StoreEventsPage>(`/api/store/events?source_type=syslog&limit=${limit}`),

  syslogStart: async (input: SyslogStart): Promise<{ ok: boolean; status?: SyslogStatus; error?: string }> => {
    const res = await fetch("/api/syslog/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, status: body as SyslogStatus }
                  : { ok: false, error: (body as { error?: string }).error ?? `HTTP ${res.status}` };
  },

  syslogStop: async (): Promise<{ ok: boolean; status?: SyslogStatus; error?: string }> => {
    const res = await fetch("/api/syslog/stop", { method: "POST" });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, status: body as SyslogStatus }
                  : { ok: false, error: (body as { error?: string }).error ?? `HTTP ${res.status}` };
  },

  ingestWebhook: async (input: {
    source: "edr" | "firewall" | "cloud" | "webhook";
    events?: unknown[] | Record<string, unknown>;
    event?: Record<string, unknown>;
  }): Promise<{
    ok: boolean;
    accepted?: number; stored?: number; duplicates?: number; unparsed?: number;
    sigmaHits?: { id: string; title: string; level: string; count: number }[];
    note?: string; error?: string;
  }> => {
    const res = await fetch("/api/ingest/webhook", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok
      ? { ok: true, ...(body as object) }
      : { ok: false, error: (body as { error?: string }).error ?? `HTTP ${res.status}` };
  },

  ingestStatus: () => getJson<{ sources: Record<string, number>; total: number }>("/api/ingest/status"),
  sigmaRules: () => getJson<{ rules: { id: string; title: string; level: string }[] }>("/api/sigma/rules"),
  copilotTriage: () => getJson<{
    advisory: boolean; count: number; disagreements: number;
    items: { id: string; ruleSeverity: string; aiSeverity: string; agrees: boolean }[];
    note: string;
  }>("/api/copilot/triage"),

  // --- nmap discovery + vuln scan (socf-discovery) ---
  // Poll the REAL scanner state; launch a scan (always user-initiated). A
  // refused target (public / not private) or a missing nmap comes back as an
  // honest error, never a fake OK. Discovered assets/vulns are read back from
  // the persistent store.
  discoveryStatus: () => getJson<DiscoveryStatus>("/api/discovery/status"),

  discoveryScan: async (
    input: DiscoveryScanInput,
  ): Promise<{ ok: boolean; status?: DiscoveryStatus; error?: string }> => {
    const res = await fetch("/api/discovery/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, status: body as DiscoveryStatus }
                  : { ok: false, error: (body as { error?: string }).error ?? `HTTP ${res.status}` };
  },

  /** Discovered hosts from the persistent store (assets table), newest first. */
  discoveryAssets: (limit = 100) =>
    getJson<StoreAssetsPage>(`/api/store/assets?source=nmap&limit=${limit}`),

  /** Vulnerabilities from the persistent store, newest first. Severity is the
   *  NSE-reported CVSS band (empty = unknown), never keyword-guessed. */
  vulns: (limit = 200) =>
    getJson<StoreVulnsPage>(`/api/store/vulns?limit=${limit}`),

  // --- TI enrichment + OEM polling (socf-ti-oem) ---
  // Keys/tokens are user-supplied and stored masked; the browser only sees
  // presence. Verdicts come from real provider/vendor responses — never faked.
  tiKeys: () => getJson<TiKeyStatus>("/api/ti/keys"),

  /** Enrich one IP via every configured provider. An unconfigured provider is
   *  reported (not called); a failed call carries the real error; only real
   *  hits are stored + returned. Read the full IOC history from /api/store/iocs. */
  tiEnrich: async (ip: string): Promise<TiEnrichResult> => {
    const res = await fetch("/api/ti/enrich", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok && !(body as TiEnrichResult).ip) {
      throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
    }
    return body as TiEnrichResult;
  },

  /** Store an IOC lookup value (masked secret) via the store settings endpoint.
   *  Used to save the OTX / AbuseIPDB API keys — the value is write-only. */
  setTiKey: async (which: "otx" | "abuseipdb", value: string): Promise<TiKeyStatus> => {
    const key = which === "otx" ? "otx_api_key" : "abuseipdb_api_key";
    await fetch("/api/store/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key, value }),
    });
    return getJson<TiKeyStatus>("/api/ti/keys");
  },

  /** IOC lookups from the persistent store, newest first. A verdict of
   *  malicious/suspicious is a hit; the score is the provider's real number. */
  iocs: (limit = 200) =>
    getJson<StoreIocsPage>(`/api/store/iocs?limit=${limit}`),

  oemConnectors: () => getJson<{ connectors: OemConnector[] }>("/api/oem/connectors"),

  oemCreateConnector: async (
    input: OemConnectorInput,
  ): Promise<{ ok: boolean; connector?: OemConnector; error?: string }> => {
    const res = await fetch("/api/oem/connectors", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, connector: body as OemConnector }
                  : { ok: false, error: (body as { error?: string }).error ?? `HTTP ${res.status}` };
  },

  /** Poll one connector now. A placeholder base URL or a failed call is an
   *  honest error that stores nothing — never a fabricated event. */
  oemPoll: async (name: string): Promise<OemPollResult> => {
    const res = await fetch("/api/oem/poll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
    return body as OemPollResult;
  },

  // --- EVTX ingest + history/retention (socf-evtx-history) ---
  /** Whether the optional python-evtx parser is installed. When false, an .evtx
   *  ingest returns an honest install message rather than a fake parse. */
  evtxStatus: () => getJson<EvtxStatus>("/api/evtx/status"),

  /** Ingest a Windows .evtx file into the store. A missing python-evtx library
   *  comes back as an honest error — never a simulated parse. */
  evtxIngest: async (file: File): Promise<{ ok: boolean; result?: EvtxIngestResult; error?: string }> => {
    const form = new FormData();
    form.append("file", file);
    const res = await fetch("/api/evtx/ingest", { method: "POST", body: form });
    const body = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, result: body as EvtxIngestResult }
                  : { ok: false, error: (body as { error?: string }).error ?? `HTTP ${res.status}` };
  },

  /** Persistent history events (filter/paginate). Empty table -> honest empty. */
  historyEvents: (query: HistoryQuery = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== "" && v !== null) qs.set(k, String(v));
    }
    if (!qs.has("limit")) qs.set("limit", "100");
    return getJson<StoreEventsPage>(`/api/store/events?${qs.toString()}`);
  },

  /** Command-Center KPI counts (store.metrics). */
  storeMetrics: () => getJson<StoreMetrics>("/api/store/metrics"),

  /** The store's public settings (retention_days lives here). */
  storeSettings: () => getJson<PublicSettings>("/api/store/settings"),

  setRetentionDays: async (days: number): Promise<PublicSettings> => {
    const res = await fetch("/api/store/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: "retention_days", value: String(days) }),
    });
    return res.json() as Promise<PublicSettings>;
  },

  /** Retention purge of history older than N days (default: stored retention). */
  storeCleanup: async (days?: number): Promise<{ deleted: Record<string, number>; retentionDays: number }> => {
    const res = await fetch("/api/store/cleanup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(days === undefined ? {} : { days }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
    return body as { deleted: Record<string, number>; retentionDays: number };
  },

  /** DESTRUCTIVE full wipe of all data tables. Requires {confirm:true}; the UI
   *  gates this behind a typed confirmation. */
  storePurge: async (): Promise<{ purged: Record<string, number> }> => {
    const res = await fetch("/api/store/purge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
    return body as { purged: Record<string, number> };
  },

  // --- Audit Ledger & Chain Verification (C4-T2 / D4) ---
  auditChain: () => getJson<AuditChainResponse>("/api/audit"),
  auditVerify: () => getJson<AuditVerification>("/api/audit/verify"),

  // --- Efficacy Surface (D2) ---
  efficacy: () => getJson<EfficacyResponse>("/api/efficacy"),
  runEfficacy: async (): Promise<EfficacyResponse> => {
    const res = await fetch("/api/efficacy", { method: "POST" });
    const body = await res.json().catch(() => ({}));
    if (!res.ok && res.status !== 202) {
      throw new Error((body as { error?: string }).error ?? `HTTP ${res.status}`);
    }
    return body as EfficacyResponse;
  },
};

// --- Audit Ledger & Chain Verification (C4-T2 / D4) ---
export type AuditStatus = "approved" | "rejected" | "executed" | "failed";

export interface AuditEntry {
  ts: string;
  actor: string;
  incident_id: string;
  runbook_id: string;
  step: string;
  status: AuditStatus;
  eligibility_proof?: unknown;
  evidence_refs?: string[];
  request_redacted?: string | null;
  response_verbatim?: string | null;
  prev_hash: string;
  entry_hash: string;
}

export interface AuditBreak {
  index: number;
  reason: string;
  expected?: string | null;
  found?: string | null;
}

export interface AuditVerification {
  ok: boolean;
  count: number;
  break: AuditBreak | null;
  head: string | null;
  path?: string;
}

export interface AuditChainResponse {
  entries: AuditEntry[];
  verification: AuditVerification;
}

// --- Efficacy Surface (D2) ---
export interface EfficacyMiss {
  line: number;
  raw: string;
  why: string;
}

export interface EfficacyFalsePositive {
  rule_id: string;
  severity?: string | null;
  summary?: string | null;
  evidence?: string | null;
}

export interface EfficacyRuleScore {
  lines_covered: number[];
  true_positive_findings: number;
  false_positive_findings: number;
  malicious_lines: number;
  malicious_lines_detected: number;
  precision: number;
  recall: number;
  f1: number;
}

export interface EfficacyTotals {
  true_positive_findings: number;
  false_positive_findings: number;
  malicious_lines: number;
  malicious_lines_detected: number;
  precision: number;
  recall: number;
  f1: number;
  missed_lines?: number;
  findings?: number;
}

export interface EfficacyScenario {
  scenario: string;
  format: string;
  line_count?: number;
  totals: EfficacyTotals;
  per_rule?: Record<string, EfficacyRuleScore>;
  misses: EfficacyMiss[];
  false_positives?: EfficacyFalsePositive[];
  scope: string;
  run_date?: string;
  log?: string;
}

export interface EfficacyRun {
  run_date: string;
  scope: string;
  pipeline: string;
  scenarios: EfficacyScenario[];
  total_misses: number;
  total_false_positives: number;
}

export interface EfficacyResponse {
  status: "idle" | "running" | "done" | "error";
  run: EfficacyRun | null;
  error: string | null;
}
