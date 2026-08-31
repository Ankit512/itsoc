/** Guided-tour steps for first-time users. Each step navigates to a route and
 *  spotlights a REAL element by `data-tour` selector. The tour is presentational
 *  only — it never derives a verdict; it just walks the screens that already
 *  exist. Selectors stay light so the tour degrades gracefully to a centered
 *  card if a target is absent (e.g. experimental nav hidden). */

export interface TourStep {
  /** route the step navigates to */
  route: string;
  /** CSS selector of the element to spotlight (a nav link with data-tour) */
  selector: string;
  /** data-tour token to stamp on the nav link so the spotlight can find it */
  tour: string;
  title: string;
  body: string;
}

export const TOUR_STEPS: TourStep[] = [
  {
    route: "/",
    selector: '[data-tour="nav-overview"]',
    tour: "nav-overview",
    title: "Start at Overview",
    body: "This dashboard summarizes the current run: how many events, how severe, and what the rules grouped into findings. Severity here always comes from rules — never an AI guess.",
  },
  {
    route: "/alerts",
    selector: '[data-tour="nav-findings"]',
    tour: "nav-findings",
    title: "Findings (events)",
    body: "These are the rule-caught events. Each row carries the real source line it matched, the rule that fired, and its evidence. You can open any finding to see its citing lines.",
  },
  {
    route: "/incidents",
    selector: '[data-tour="nav-incidents"]',
    tour: "nav-incidents",
    title: "Incidents (RCA)",
    body: "Incidents are derived from findings and carry a root-cause analysis. The AI explains what the rules already decided — it never raises or lowers a severity.",
  },
  {
    route: "/cases",
    selector: '[data-tour="nav-cases"]',
    tour: "nav-cases",
    title: "Cases",
    body: "Cases are analyst-kept case files: activity, observables, and stored attachments. Open a case to collaborate around a finding or incident without changing its verdict.",
  },
  {
    route: "/approvals",
    selector: '[data-tour="nav-approvals"]',
    tour: "nav-approvals",
    title: "Approvals (gated actions)",
    body: "Any response action (like a perimeter block) needs an explicit approval here. Nothing is executed from the AI assistant — approvals are the single authoritative surface.",
  },
  {
    route: "/intel",
    selector: '[data-tour="nav-intel"]',
    tour: "nav-intel",
    title: "Threat intel",
    body: "External context from feeds and enrichment. These are derived tags and real provider responses — enrichment is context, not a verdict.",
  },
  {
    route: "/assets",
    selector: '[data-tour="nav-assets"]',
    tour: "nav-assets",
    title: "Assets & users",
    body: "Observed entities only — hosts and users that actually appear in your logs. Nothing is inferred or invented here.",
  },
  {
    route: "/sources",
    selector: '[data-tour="nav-sources"]',
    tour: "nav-sources",
    title: "Sources (collectors)",
    body: "Where logs come from: collectors/listeners and uploads. A run here means a real file got parsed — the honest 'N lines parsed · M unparsed' line is the source of truth.",
  },
  {
    route: "/settings",
    selector: '[data-tour="nav-settings"]',
    tour: "nav-settings",
    title: "That's the loop",
    body: "Upload or connect a source → rules find findings → you triage, open cases, and approve actions. The AI assistant interprets and explains each step; the rules always own severity.",
  },
];

/** Basic navigation vocabulary so the assistant's "explain this page" can point
 *  at the matching tour step without importing React. */
export function stepForRoute(pathname: string): TourStep | undefined {
  const route = pathname.startsWith("/incidents") ? "/incidents"
    : pathname.split("/").slice(0, 2).join("/") === ""
      ? "/"
      : pathname === "/findings" ? "/alerts"
      : pathname;
  return TOUR_STEPS.find((s) => s.route === route) ?? TOUR_STEPS.find((s) => s.route === "/");
}
