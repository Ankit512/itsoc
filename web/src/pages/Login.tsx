import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { useUi } from "@/store/ui";

/** Login — the itsoc. split auth screen (is-auth), mirroring the prototype login
 *  frame: left brand panel (wordmark + tagline + 3 checks + honest note), right
 *  card with Log in / Sign up tabs, username + passphrase, and the local-demo /
 *  scrypt / swap-seam honesty note. Auth logic is unchanged (P2 is presentation
 *  only): calls route through the single swap-seam (lib/auth.ts via useAuth).
 *
 *  Note: the handoff §3 prose mentions a "Name" field on Sign up, but the
 *  authoritative prototype login has none, the signup backend takes only
 *  (username, passphrase), and P2 forbids backend/auth changes — a field that
 *  goes nowhere would be dishonest, so it is intentionally omitted. */
export function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, signup, isAuthenticated, user } = useAuth();
  const theme = useUi((s) => s.theme);
  const toggleTheme = useUi((s) => s.toggleTheme);

  const [mode, setMode] = useState<"login" | "signup">("login");
  const [username, setUsername] = useState("analyst");
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const from = (location.state as { from?: { pathname?: string } })?.from?.pathname || "/";

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!username.trim()) { setError("Please enter a username"); return; }
    if (!passphrase) { setError("Please enter a passphrase"); return; }
    if (mode === "signup" && passphrase.length < 4) {
      setError("Passphrase must be at least 4 characters"); return;
    }
    setSubmitting(true);
    try {
      if (mode === "signup") await signup(username.trim(), passphrase);
      else await login(username.trim(), passphrase);
      navigate(from, { replace: true });
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setSubmitting(false);
    }
  };

  if (isAuthenticated && user) {
    return (
      <div className="is-auth">
        <div className="is-auth__brand">
          <div className="is-brand" style={{ fontSize: 30 }}>itsoc<span className="dot">.</span></div>
          <div className="tag">Local, honest, rules-first<br />security operations.</div>
        </div>
        <div className="is-auth__form">
          <div className="is-auth__card">
            <h1 style={{ margin: "6px 0 0", fontSize: 21 }}>Already signed in</h1>
            <p className="is-mut" style={{ margin: 0, fontSize: 12.5 }}>
              Active profile: <b style={{ color: "var(--ink)" }}>{user.username}</b> ({user.role}).
            </p>
            <button className="is-btn is-btn--primary" onClick={() => navigate(from, { replace: true })}>
              Continue to console →
            </button>
          </div>
        </div>
      </div>
    );
  }

  const dark = theme === "dark";
  return (
    <div className="is-auth">
      <div className="is-auth__brand">
        <div className="is-brand" style={{ fontSize: 30 }}>itsoc<span className="dot">.</span></div>
        <div className="tag">Local, honest, rules-first<br />security operations.</div>
        <ul className="pts">
          <li>Deterministic rules own every verdict</li>
          <li>The AI explains &amp; recommends — it never decides</li>
          <li>Runs on your machine · nothing leaves by default</li>
        </ul>
        <div className="is-auth__honest">
          Local demo — a single profile on this machine. No cloud account, no server session.
        </div>
      </div>

      <div className="is-auth__form" style={{ position: "relative" }}>
        <button className="is-icobtn" style={{ position: "absolute", top: 20, right: 20 }}
                onClick={toggleTheme} aria-label={dark ? "Switch to light mode" : "Switch to dark mode"}>
          {dark ? "☾" : "☀"}
        </button>
        <div className="is-auth__card">
          <div className="is-tabs">
            <button className={mode === "login" ? "on" : ""} type="button"
                    onClick={() => { setMode("login"); setError(null); }}>Log in</button>
            <button className={mode === "signup" ? "on" : ""} type="button"
                    onClick={() => { setMode("signup"); setError(null); }}>Sign up</button>
          </div>
          <h1 style={{ margin: "6px 0 0", fontSize: 21 }}>
            {mode === "signup" ? "Create your local profile" : "Welcome back"}
          </h1>
          <p className="is-mut" style={{ margin: 0, fontSize: 12.5 }}>
            {mode === "signup" ? "This is the single profile stored on this machine."
              : "Unlock this console to continue."}
          </p>

          {error && (
            <div className="is-note" style={{ borderColor: "var(--crit)", color: "var(--crit)" }} role="alert">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 13 }}>
            <label className="is-field"><span>Username</span>
              <input className="is-input" type="text" value={username} required
                     onChange={(e) => setUsername(e.target.value)} placeholder="e.g. analyst" />
            </label>
            <label className="is-field"><span>Passphrase</span>
              <input className="is-input" type="password" value={passphrase} required
                     onChange={(e) => setPassphrase(e.target.value)} placeholder="••••••••••••" />
            </label>
            <button className="is-btn is-btn--primary" type="submit" disabled={submitting}
                    style={{ justifyContent: "center", padding: 11 }}>
              {submitting ? "Working…" : mode === "signup" ? "Create local profile →" : "Sign in to session →"}
            </button>
          </form>

          <div className="is-note" style={{ fontSize: 11.5 }}>
            <b>Quick demo:</b> log in with username{" "}
            <span className="is-mono" style={{ color: "var(--ink)" }}>analyst</span> and its passphrase.
            If no profile exists, choose Sign up first.
          </div>

          <div className="is-auth__honest" style={{ marginTop: 2 }}>
            Passphrase is salted &amp; scrypt-hashed locally. Client calls route through one swap-seam
            module (<span className="is-mono">auth.ts</span>) ready for future token/passkey providers.
          </div>
        </div>
      </div>
    </div>
  );
}
