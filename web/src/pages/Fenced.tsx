import { Link, Navigate, useLocation } from "react-router-dom";
import { Card, CardContent } from "@/components/ui/card";

/** Phase 0 refocus surfaces (ITSOC_V2_SPEC.md §3/§8): honest pages for what
 *  was CUT (removed from the product because it broke a principle) and what
 *  is FENCED (kept, but hidden behind the off-by-default experimental flag).
 *  Nothing here is a 404 — old bookmarks land on the real reason instead. */

/** A page removed from the product. The code stays in the repo, unreferenced
 *  from the nav and routing, and its scan/egress actions are disabled by
 *  default — this notice says exactly why. */
export function CutNotice({ title, reason }: { title: string; reason: string }) {
  return (
    <Card className="max-w-2xl border-dashed" data-testid="cut-notice">
      <CardContent className="p-6">
        <h2 className="text-[16px] font-semibold">{title} was removed from itsoc</h2>
        <p className="mt-2 text-[12.5px] leading-normal text-muted-foreground">{reason}</p>
        <p className="mt-2 text-[12.5px] leading-normal text-muted-foreground">
          The code remains in the repository (fenced, not deleted) and its
          actions are disabled by default. Head back to{" "}
          <Link className="text-primary underline" to="/findings">Findings</Link> —
          the honest core of the product.
        </p>
      </CardContent>
    </Card>
  );
}

/** A fenced Command-Center page reached while the experimental flag is off.
 *  Honest state: the page exists, it is just not part of the default product. */
export function ExperimentalOff({ title }: { title: string }) {
  return (
    <Card className="max-w-2xl border-dashed" data-testid="experimental-off">
      <CardContent className="p-6">
        <h2 className="text-[16px] font-semibold">{title} is experimental — currently off</h2>
        <p className="mt-2 text-[12.5px] leading-normal text-muted-foreground">
          {title} is part of the fenced Command-Center: kept in the repo, hidden
          from the default nav. Turn on <b>Experimental features</b> in{" "}
          <Link className="text-primary underline" to="/settings">Settings</Link>{" "}
          to show it. Nothing was deleted and no data was lost.
        </p>
      </CardContent>
    </Card>
  );
}

/** Redirect an old top-level route into its new home, preserving the query
 *  string (?sel=… keeps working) and optionally pinning a Review facet. */
export function LegacyRedirect({ to, facet }: { to: string; facet?: string }) {
  const { search } = useLocation();
  const next = new URLSearchParams(search);
  if (facet) next.set("facet", facet);
  const qs = next.toString();
  return <Navigate replace to={{ pathname: to, search: qs ? `?${qs}` : "" }} />;
}
