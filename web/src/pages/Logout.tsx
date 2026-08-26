import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { LogOut, ShieldCheck } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { useUi } from "@/store/ui";
import { useJobs } from "@/store/jobs";
import { useAuth } from "@/context/AuthContext";

/** Logout — honest for a local, single-profile demo tool.
 *  Signs out of the active local demo session token, revokes backend session,
 *  and resets local browser UI state back to neutral default.
 */
export function Logout() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const resetUi = useUi((s) => s.resetUi);
  const resetJobs = useJobs((s) => s._reset);
  const { logout, user } = useAuth();
  const [done, setDone] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSignOut = async () => {
    setLoading(true);
    try {
      await logout();
      resetUi();
      resetJobs();
      queryClient.clear();
      setDone(true);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-xl">
      <Card className="overflow-hidden rounded-xl border border-border bg-card shadow-sm">
        <CardContent className="p-6">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-muted/50">
              <LogOut className="h-4 w-4 text-muted-foreground" strokeWidth={1.8} aria-hidden />
            </div>
            <h2 className="text-[15px] font-semibold text-foreground">Sign out</h2>
          </div>

          <p className="mt-3 text-[13px] leading-normal text-muted-foreground">
            Sign out of this <span className="font-semibold text-foreground">local demo session</span>.
            {user ? (
              <> Currently active as <code className="rounded bg-muted px-1.5 py-0.5 text-[12px] font-medium text-foreground">{user.username}</code> ({user.role}).</>
            ) : null}
          </p>
          <p className="mt-2 text-[13px] leading-normal text-muted-foreground">
            Signing out revokes your local session token and resets this browser’s UI state (saved theme,
            active notifications, and cached queries) back to a neutral default. Your analyzed runs,
            incidents, and findings live on the backend and are untouched.
          </p>

          {done ? (
            <div className="mt-4 rounded-md border bg-background p-3 text-[12.5px] text-muted-foreground">
              <div className="flex items-center gap-2 font-medium text-foreground">
                <ShieldCheck className="h-4 w-4 text-primary" />
                <span>Signed out of local demo session.</span>
              </div>
              <p className="mt-1 text-[12px]">Local UI state and session tokens have been cleared.</p>
              <div className="mt-3 flex gap-2">
                <button
                  onClick={() => navigate("/login")}
                  className="rounded-md border border-primary bg-primary px-3 py-1.5 text-[12.5px] font-semibold text-primary-foreground hover:opacity-90"
                >
                  Sign in again
                </button>
                <button
                  onClick={() => navigate("/")}
                  className="rounded-md border px-3 py-1.5 text-[12.5px] hover:border-primary"
                >
                  View dashboard
                </button>
              </div>
            </div>
          ) : (
            <div className="mt-4 flex items-center gap-2">
              <button
                onClick={handleSignOut}
                disabled={loading}
                className="rounded-md border border-primary bg-primary px-3 py-1.5 text-[12.5px] font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-50"
              >
                {loading ? "Signing out..." : "Sign out of local session"}
              </button>
              <button
                onClick={() => navigate("/")}
                className="rounded-md border px-3 py-1.5 text-[12.5px] hover:border-primary"
              >
                Cancel
              </button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
