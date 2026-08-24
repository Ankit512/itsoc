import { Routes, Route } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { Overview } from "@/pages/Overview";
import { Findings } from "@/pages/Findings";
import { Settings } from "@/pages/Settings";
import { Collectors } from "@/pages/Collectors";
import { OemEngine } from "@/pages/OemEngine";
import { History } from "@/pages/History";
import { Placeholder } from "@/pages/Placeholder";
import { CutNotice, ExperimentalOff, LegacyRedirect } from "@/pages/Fenced";
import { useUi } from "@/store/ui";

/** Phase 0 routing (ITSOC_V2_SPEC.md §3/§8).
 *  Default product: Overview · Findings · Sources · Settings.
 *  Old subsystem routes redirect into their Review facet inside Findings.
 *  Fenced Command-Center pages (OEM Engine, History) render only when the
 *  off-by-default experimental flag is on. Cut pages (Discovery,
 *  Vulnerabilities, Enrichment, Logout) render an honest removal notice —
 *  their scan/egress actions are disabled by default. */
export default function App() {
  const experimental = useUi((s) => s.experimental);
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Overview />} />
        <Route path="findings" element={<Findings />} />

        {/* Alerts is now Findings; the subsystem pages became Review facets. */}
        <Route path="alerts" element={<LegacyRedirect to="/findings" />} />
        <Route path="incidents" element={<LegacyRedirect to="/findings" facet="incidents" />} />
        <Route path="assets" element={<LegacyRedirect to="/findings" facet="entities" />} />
        <Route path="threat-intel" element={<LegacyRedirect to="/findings" facet="threat-intel" />} />
        <Route path="reports" element={<LegacyRedirect to="/findings" facet="reports" />} />
        <Route path="cases" element={<LegacyRedirect to="/findings" facet="cases" />} />

        <Route path="collectors" element={<Collectors />} />
        <Route path="settings" element={<Settings />} />

        {/* Fenced: kept in the repo, shown only when experimental is on. */}
        <Route path="oem"
               element={experimental ? <OemEngine /> : <ExperimentalOff title="OEM Engine" />} />
        <Route path="history"
               element={experimental ? <History /> : <ExperimentalOff title="History" />} />

        {/* Cut: these broke the read-only / zero-egress principles (§2). */}
        <Route path="discovery" element={
          <CutNotice title="Discovery"
            reason="Active nmap network scanning violates principle 4 (read-only): itsoc observes logs, it never probes your network." />
        } />
        <Route path="vulnerabilities" element={
          <CutNotice title="Vulnerabilities"
            reason="Active nmap NSE vulnerability scanning violates principle 4 (read-only): itsoc observes logs, it never probes your network." />
        } />
        <Route path="enrichment" element={
          <CutNotice title="Enrichment"
            reason="Third-party IP enrichment (OTX / AbuseIPDB) violates principle 5 (local by default / zero egress): it sends data about your logs to external services." />
        } />
        <Route path="logout" element={
          <CutNotice title="Logout"
            reason="itsoc is a local single-user tool with no accounts and no server session — a logout control that ends nothing was a fake control." />
        } />

        <Route path="*" element={<Placeholder title="Not found" />} />
      </Route>
    </Routes>
  );
}
