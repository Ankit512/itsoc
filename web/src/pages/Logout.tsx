import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { useUi } from "@/store/ui";
import { useJobs } from "@/store/jobs";
import { useAuth } from "@/context/AuthContext";

/** Logout — honest card for a local, single-profile demo tool, in the itsoc.
 *  design system. Signs out of the active local demo session token, revokes the
 *  backend session, and resets local browser UI state back to a neutral default.
 *  Nothing here pretends there is a cloud account to sign out of. */
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
    <div className="is-panel" style={{ maxWidth: 560 }}>
      <div className="is-panel__h"><h3>Sign out</h3></div>
      <p style={{ fontSize: 12.5, lineHeight: 1.55, margin: 0 }}>
        Sign out of this <b style={{ color: "var(--ink)" }}>local demo session</b>.
        {user && <> Currently active as <span className="is-mono" style={{ color: "var(--ink)" }}>{user.username}</span> ({user.role}).</>}
      </p>
      <p className="is-mut" style={{ fontSize: 12.5, lineHeight: 1.55, margin: "8px 0 0" }}>
        Signing out revokes your local session token and resets this browser’s UI state (saved theme,
        active notifications, and cached queries) back to a neutral default. Your analyzed runs,
        incidents, and findings live on the backend and are untouched.
      </p>

      {done ? (
        <div className="is-note" style={{ marginTop: 14 }}>
          <b>Signed out of local demo session.</b> Local UI state and session tokens have been cleared.
          <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
            <button className="is-btn is-btn--primary" onClick={() => navigate("/login")}>Sign in again</button>
            <button className="is-btn" onClick={() => navigate("/")}>View dashboard</button>
          </div>
        </div>
      ) : (
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 14 }}>
          <button className="is-btn is-btn--primary" onClick={handleSignOut} disabled={loading}>
            {loading ? "Signing out…" : "Sign out of local session"}
          </button>
          <button className="is-btn" onClick={() => navigate("/")}>Cancel</button>
        </div>
      )}
    </div>
  );
}
