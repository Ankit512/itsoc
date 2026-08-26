import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { LogOut } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { useUi } from "@/store/ui";
import { useJobs } from "@/store/jobs";

/** Logout — honest for a local, single-user tool. There is NO server auth,
 *  account, or session to end, so this does not fake one. What it offers is a
 *  real, clearly-labelled action: clear the local UI state (saved theme, the
 *  background upload job, search) back to a neutral default. */
export function Logout() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const resetUi = useUi((s) => s.resetUi);
  const resetJobs = useJobs((s) => s._reset);
  const [done, setDone] = useState(false);

  const clearLocal = () => {
    resetUi();
    resetJobs();
    // Server data is fetched fresh; drop any cached queries so nothing stale
    // lingers in the neutral state.
    queryClient.clear();
    setDone(true);
  };

  return (
    <div className="max-w-xl">
      <Card className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
        <CardContent className="p-6">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-muted/50 border border-border">
              <LogOut className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
            </div>
            <h2 className="text-[15px] font-semibold text-foreground">Sign out</h2>
          </div>

          <p className="mt-3.5 text-[12.5px] leading-relaxed text-muted-foreground">
            This console is a <span className="font-semibold text-foreground">local, single-user
            tool</span>. There is no account, no login, and no server session —
            so there is nothing to actually sign out of, and this screen does not
            pretend otherwise.
          </p>
          <p className="mt-2 text-[12.5px] leading-relaxed text-muted-foreground">
            What it can do is clear this browser’s local UI state back to a neutral
            default: forget your saved theme, dismiss any in-progress upload
            notification, and clear the current search. Your analyzed runs live on
            the backend and are untouched.
          </p>

          {done ? (
            <div className="mt-5 rounded-lg border border-border bg-muted/20 p-3.5 text-[12px] text-muted-foreground leading-relaxed">
              Local UI state cleared. You are on a neutral, signed-out screen —
              there was no session to end.
              <div className="mt-3">
                <button onClick={() => navigate("/")}
                  className="rounded-lg border border-primary bg-primary px-3 py-1.5 text-xs font-semibold text-primary-foreground hover:opacity-90 transition-opacity shadow-xs">
                  Back to dashboard
                </button>
              </div>
            </div>
          ) : (
            <div className="mt-5 flex items-center gap-2">
              <button onClick={clearLocal}
                className="rounded-lg border border-primary bg-primary px-3 py-1.5 text-xs font-semibold text-primary-foreground hover:opacity-90 transition-opacity shadow-xs">
                Clear local UI state
              </button>
              <button onClick={() => navigate("/")}
                className="rounded-lg border border-border px-3 py-1.5 text-xs font-semibold text-muted-foreground hover:text-foreground hover:bg-muted transition-colors">
                Cancel
              </button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
