/**
 * The guided tour is intentionally a map of real screens, not a simulated
 * product. Every step navigates to an existing route and points at the same
 * navigation item the user can use after the tour ends.
 */
export interface TourStep {
  id: string;
  route: string;
  /** CSS selector for the persistent navigation item to spotlight. */
  selector: string;
  title: string;
  summary: string;
  detail: string;
  action: string;
}

export const TOUR_STEPS: TourStep[] = [
  {
    id: "overview", route: "/", selector: '[data-tour="nav-overview"]',
    title: "Get the operational picture", summary: "Overview", action: "Start by checking the run summary and the severity distribution.",
    detail: "This is the quickest way to orient yourself after a run finishes. Counts and severity come from the rules engine; the assistant can explain the evidence, but it does not change the verdict.",
  },
  {
    id: "findings", route: "/alerts", selector: '[data-tour="nav-findings"]',
    title: "Review the evidence", summary: "Findings", action: "Open the highest-priority finding and inspect its cited source lines.",
    detail: "Findings are individual rule matches. Each one keeps the rule, severity, matched event, and supporting log evidence together so you can verify why it appeared.",
  },
  {
    id: "incidents", route: "/incidents", selector: '[data-tour="nav-incidents"]',
    title: "Connect related findings", summary: "Incidents", action: "Use an incident to understand the sequence before deciding on a response.",
    detail: "Incidents group related findings into an investigation view. Root-cause notes add context around the rule-backed evidence; they are explanations, not a new severity decision.",
  },
  {
    id: "cases", route: "/cases", selector: '[data-tour="nav-cases"]',
    title: "Keep an investigation record", summary: "Cases", action: "Create or open a case when you need a durable analyst record.",
    detail: "Cases are where investigation notes, observables, activity, and attachments live. They let a team collaborate around an incident without altering the original finding.",
  },
  {
    id: "approvals", route: "/approvals", selector: '[data-tour="nav-approvals"]',
    title: "Approve actions deliberately", summary: "Approvals", action: "Review the requested action, scope, and evidence before granting approval.",
    detail: "Response actions are gated here. The assistant never executes a change on its own: approval is the authoritative checkpoint for actions such as blocking an indicator.",
  },
  {
    id: "intel", route: "/intel", selector: '[data-tour="nav-intel"]',
    title: "Add external context", summary: "Intel", action: "Use enrichment to add context, then return to the source evidence for the decision.",
    detail: "Threat intelligence and enrichment can show why an IP, domain, or hash deserves attention. Treat it as context alongside your logs, not as a replacement for a rule verdict.",
  },
  {
    id: "network", route: "/network", selector: '[data-tour="nav-network"]',
    title: "Inspect the network surface", summary: "Network", action: "Review discovery results and vulnerabilities before planning remediation.",
    detail: "The Network view brings active discovery and vulnerability results together. It is useful for validating whether an observed asset or exposure matches what the logs suggest.",
  },
  {
    id: "assets", route: "/assets", selector: '[data-tour="nav-assets"]',
    title: "Know the affected entities", summary: "Assets", action: "Filter to the host or user named in a finding to establish impact.",
    detail: "Assets and users are observed entities from your data. This view helps you answer who and what was involved without inventing asset records that were never seen.",
  },
  {
    id: "sources", route: "/sources", selector: '[data-tour="nav-sources"]',
    title: "Validate what was ingested", summary: "Sources", action: "Check parser coverage and collector health when a run looks incomplete.",
    detail: "Sources shows uploads and collectors feeding the current run. The parsed and unparsed counts are the honest record of what the system could read from the input.",
  },
  {
    id: "integrations", route: "/integrations", selector: '[data-tour="nav-integrations"]',
    title: "Manage connected systems", summary: "Integrations", action: "Confirm a connector’s status and permissions before relying on its data.",
    detail: "Integrations lists the local connectors available to the workspace. Credentials stay masked and each connection makes its scope visible so data flow is understandable.",
  },
  {
    id: "history", route: "/history", selector: '[data-tour="nav-history"]',
    title: "Look across runs", summary: "History", action: "Compare a prior run when you need to separate a new signal from a recurring pattern.",
    detail: "History provides the persistent view of previously ingested events and runs. Use it to add time-based context without losing the details from the active investigation.",
  },
  {
    id: "reports", route: "/reports", selector: '[data-tour="nav-reports"]',
    title: "Share supported evidence", summary: "Reports", action: "Export only after the investigation record is ready for a stakeholder.",
    detail: "Reports collects real, generated artifacts for handoff. It is the final communication step—after you have reviewed findings, recorded your analysis, and obtained any required approval.",
  },
  {
    id: "settings", route: "/settings", selector: '[data-tour="nav-settings"]',
    title: "Finish with a repeatable loop", summary: "Settings", action: "Upload or connect a source, investigate rule-backed findings, document the work, then approve any response.",
    detail: "Settings contains the controls that change local behavior. You now have the full workflow: ingest, verify evidence, investigate, add context, document, and act with approval.",
  },
];

/** Vocabulary used by the copilot when explaining the current screen. */
export function stepForRoute(pathname: string): TourStep | undefined {
  const route = pathname === "/findings" ? "/alerts" : pathname;
  return TOUR_STEPS.find((step) => step.route === route)
    ?? TOUR_STEPS.find((step) => step.route === "/");
}
