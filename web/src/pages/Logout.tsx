import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { useUi } from "@/store/ui";
import { useJobs } from "@/store/jobs";
import { useAuth } from "@/context/AuthContext";

/** Logout — the design-v3 "Log out" screen: one centred 480px card (26px pad,
 *  14px stack, heading + explanation + a two-button row).
 *
 *  Copy deviation, on purpose: the dc mock says "there is nothing to sign out
 *  of … no account, no login, no server session". This build DOES keep a local
 *  profile (console/.soc/auth.json) and a session token, so that sentence would
 *  be a false surface. The card keeps the dc's shape and its "clear local UI
 *  state" framing, but states what is actually true here. */
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
    <div className="is-logout">
      <div className="is-logout__card">
        <h2 className="is-logout__h">Clear this machine&rsquo;s local UI state</h2>
        <p className="is-mut" style={{ fontSize: 12.5, lineHeight: 1.65, margin: 0 }}>
          itsoc. is a local, single-user tool
          {user && (
            <>
              {" "}&mdash; this machine&rsquo;s profile is{" "}
              <span className="is-mono" style={{ color: "var(--ink)" }}>{user.username}</span> ({user.role})
            </>
          )}
          . The login gate is off, so there is no session to end. What this clears is local UI
          state: your theme, dismissed notifications, and the current search. Analyzed runs,
          incidents, and findings live on the backend and are untouched.
        </p>

        {done ? (
          <div className="is-note">
            <b>Local UI state cleared.</b> Theme, notifications, cached queries and any stored token are gone.
            <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
              <button className="is-btn is-btn--primary" onClick={() => navigate("/")}>Back to the console</button>
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <button className="is-btn is-btn--primary" onClick={handleSignOut} disabled={loading}>
              {loading ? "Clearing…" : "Clear local UI state"}
            </button>
            <button className="is-btn" onClick={() => navigate("/")}>Cancel</button>
          </div>
        )}
      </div>
    </div>
  );
}
