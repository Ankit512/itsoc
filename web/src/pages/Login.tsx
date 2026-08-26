import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Shield, Key, User, Lock, AlertCircle, ArrowRight, CheckCircle2 } from "lucide-react";
import { useAuth } from "@/context/AuthContext";

export function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, signup, isAuthenticated, user } = useAuth();

  const [mode, setMode] = useState<"login" | "signup">("login");
  const [username, setUsername] = useState("analyst");
  const [passphrase, setPassphrase] = useState("");
  const [role, setRole] = useState<"analyst" | "admin" | "viewer">("analyst");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const from = (location.state as { from?: { pathname?: string } })?.from?.pathname || "/";

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!username.trim()) {
      setError("Please enter a username");
      return;
    }
    if (!passphrase) {
      setError("Please enter a passphrase");
      return;
    }
    if (mode === "signup" && passphrase.length < 4) {
      setError("Passphrase must be at least 4 characters");
      return;
    }

    setSubmitting(true);
    try {
      if (mode === "signup") {
        await signup(username.trim(), passphrase, role);
      } else {
        await login(username.trim(), passphrase);
      }
      navigate(from, { replace: true });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Authentication failed";
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  if (isAuthenticated && user) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background p-4 text-foreground">
        <div className="w-full max-w-md rounded-xl border bg-card p-6 shadow-sm">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="h-6 w-6 text-primary" />
            <div>
              <h2 className="text-[16px] font-semibold">Already signed in</h2>
              <p className="text-[13px] text-muted-foreground">
                Active profile: <span className="font-medium text-foreground">{user.username}</span> ({user.role})
              </p>
            </div>
          </div>
          <div className="mt-6 flex gap-3">
            <button
              onClick={() => navigate(from, { replace: true })}
              className="flex-1 rounded-md bg-primary py-2 text-[13px] font-medium text-primary-foreground hover:opacity-90"
            >
              Continue to console
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4 text-foreground">
      <div className="w-full max-w-[400px]">
        {/* Brand Header */}
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-primary/20 bg-primary/10 text-primary shadow-sm">
            <Shield className="h-6 w-6" strokeWidth={2} />
          </div>
          <h1 className="mt-3 text-[22px] font-bold tracking-tight">itsoc<span className="text-primary">.</span></h1>
          <p className="mt-0.5 text-[13px] text-muted-foreground">
            Local-first Security Operations &amp; Anomaly Detection
          </p>
        </div>

        {/* Card */}
        <div className="rounded-xl border bg-card p-6 shadow-sm">
          {/* Mode Switcher Tabs */}
          <div className="mb-5 flex rounded-lg border bg-muted/40 p-1">
            <button
              type="button"
              onClick={() => { setMode("login"); setError(null); }}
              className={`flex-1 rounded-md py-1.5 text-[12.5px] font-medium transition-all ${
                mode === "login"
                  ? "bg-card text-foreground shadow-xs"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => { setMode("signup"); setError(null); }}
              className={`flex-1 rounded-md py-1.5 text-[12.5px] font-medium transition-all ${
                mode === "signup"
                  ? "bg-card text-foreground shadow-xs"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Create Profile
            </button>
          </div>

          {error && (
            <div className="mb-4 flex items-start gap-2.5 rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-[12.5px] text-destructive">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
              <span className="leading-tight">{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-3.5">
            <div>
              <label className="block text-[12px] font-medium text-muted-foreground">Username</label>
              <div className="relative mt-1">
                <User className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g. analyst or admin"
                  required
                  className="w-full rounded-lg border bg-background py-2 pl-9 pr-3 text-[13px] placeholder:text-muted-foreground/50 focus:border-primary focus:outline-hidden"
                />
              </div>
            </div>

            <div>
              <label className="block text-[12px] font-medium text-muted-foreground">Passphrase</label>
              <div className="relative mt-1">
                <Lock className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                <input
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  className="w-full rounded-lg border bg-background py-2 pl-9 pr-3 text-[13px] placeholder:text-muted-foreground/50 focus:border-primary focus:outline-hidden"
                />
              </div>
            </div>

            {mode === "signup" && (
              <div>
                <label className="block text-[12px] font-medium text-muted-foreground">Role</label>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value as "analyst" | "admin" | "viewer")}
                  className="mt-1 w-full rounded-lg border bg-background py-2 px-3 text-[13px] focus:border-primary focus:outline-hidden"
                >
                  <option value="analyst">SOC Analyst</option>
                  <option value="admin">Administrator</option>
                  <option value="viewer">Read-only Viewer</option>
                </select>
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="mt-2 flex w-full items-center justify-center gap-2 rounded-lg bg-primary py-2 text-[13px] font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {submitting ? (
                <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary-foreground border-t-transparent" />
              ) : (
                <>
                  <span>{mode === "signup" ? "Create Local Profile" : "Sign In to Session"}</span>
                  <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          </form>

          {/* Quick Demo Hint */}
          <div className="mt-4 rounded-md border border-border/70 bg-muted/30 p-2.5 text-[11.5px] leading-relaxed text-muted-foreground">
            <span className="font-semibold text-foreground">Quick demo:</span> Log in with username{" "}
            <code className="rounded bg-muted px-1 py-0.5 font-mono text-[11px] text-foreground">analyst</code>{" "}
            and any passphrase. If no profile exists, one is auto-initialized.
          </div>
        </div>

        {/* Honesty & Swap-Seam Note */}
        <div className="mt-4 rounded-lg border border-border/50 bg-card/50 p-3 text-center text-[11.5px] leading-normal text-muted-foreground">
          <div className="flex items-center justify-center gap-1.5 font-medium text-foreground/80">
            <Key className="h-3.5 w-3.5 text-primary" />
            <span>Local demo — single profile on this machine</span>
          </div>
          <p className="mt-1 text-[11px]">
            Passphrase is salted &amp; scrypt-hashed locally. Client calls route through a single swap-seam module
            (<code className="font-mono text-[10.5px]">auth.ts</code>) ready for future token/passkey providers.
          </p>
        </div>
      </div>
    </div>
  );
}
