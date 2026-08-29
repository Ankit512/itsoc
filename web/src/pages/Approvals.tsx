import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { ShieldCheck, X } from "lucide-react";
import { api, type Approval } from "@/lib/api";
import { cn } from "@/lib/utils";

/** The Approvals screen — the SINGLE authoritative surface where a pending
 *  runbook action is approved or rejected. Rules own eligibility (rendered
 *  verbatim from `eligibilityProof`); this UI never computes a verdict. The
 *  approve control exists in exactly ONE place: <ApprovalReviewModal> below.
 *  Master-detail like Findings, with J/K queue navigation and an honest empty
 *  state — no illustration filler. This is also the pattern the later C4
 *  presentational components copy, so its structure is deliberate. */

/** One line of the command preview / evidence, styled like finding evidence
 *  (mono, left-accent rule). Values are already redacted by the backend. */
function MonoBlock({ testid, lines }: { testid: string; lines: string[] }) {
  return (
    <pre className="is-evidence" data-testid={testid}>
      {lines.length
        ? lines.map((l, i) => <div key={i} className="eline">{l}</div>)
        : <div className="eline is-mut">— nothing to show</div>}
    </pre>
  );
}

/** The redacted request preview, the evidence chain and the eligible-by rule
 *  line — the AUTHORITATIVE, rule-owned bundle a decision is made against. It
 *  carries NO advisory element by construction; the selector-null test proves
 *  `.is-adv`/`.is-chip--adv` never appear inside `approval-authoritative`. */
function AuthoritativeBundle({ a }: { a: Approval }) {
  const rr = a.requestRedacted ?? {};
  const commandLines = rr.error
    ? [rr.error]
    : [rr.command ?? "—", ...(rr.description ? [`# ${rr.description}`] : [])];
  const proof = a.eligibilityProof ?? { eligible: false, missing: [] };

  return (
    <div className="is-approval-auth" data-testid="approval-authoritative">
      <div className="is-block low" data-testid="approval-eligibility">
        <div className="cap authoritative">Eligible by rule · authoritative</div>
        <div className="verdict">
          {proof.eligible ? "ELIGIBLE" : "NOT ELIGIBLE"} · {a.runbookId}
        </div>
        <p className="is-mut">
          {proof.eligible
            ? "The rules engine cleared every requirement for this runbook against the current incident evidence. Severity and eligibility are rule-owned — this screen only renders them."
            : `Missing: ${(proof.missing ?? []).join(", ") || "unspecified"}`}
        </p>
      </div>

      <div>
        <div className="is-approval-lbl">
          Request preview <span className="is-mut">— redacted · the raw command only ever travels over the connector transport</span>
        </div>
        <MonoBlock testid="approval-redacted" lines={commandLines} />
      </div>

      <div>
        <div className="is-approval-lbl">
          Evidence chain <span className="is-mut">— rule-owned record refs, cited like finding evidence</span>
        </div>
        <pre className="is-evidence" data-testid="approval-evidence">
          {(a.evidenceRefs ?? []).length
            ? (a.evidenceRefs ?? []).map((n, i) => (
                <div key={i} className="eline">
                  <span className="ln">{n}</span>record #{n}
                </div>
              ))
            : <div className="eline is-mut">— no evidence records cited</div>}
        </pre>
      </div>
    </div>
  );
}

/** The ONLY component in the app that carries an approve control. Approve is
 *  the single primary/accent button in this view; Reject is secondary. Both
 *  are step-up acts: the passphrase is submitted in the request body only,
 *  is cleared after every attempt, and is never rendered into state or any
 *  error message. Enter submits (approve) only when the field is non-empty;
 *  Esc closes. */
function ApprovalReviewModal({ approval, onClose }: { approval: Approval; onClose: () => void }) {
  const qc = useQueryClient();
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);

  const decide = useCallback(async (kind: "approve" | "reject") => {
    // Step-up is required for BOTH acts; an empty passphrase never leaves here.
    if (!passphrase.trim() || busy) return;
    setBusy(true);
    setError(null);
    const res = kind === "approve"
      ? await api.approveApproval(approval.id, passphrase)
      : await api.rejectApproval(approval.id, passphrase);
    // The passphrase is dropped immediately, on success and failure alike, so a
    // credential is never left in component state or the rendered DOM.
    setPassphrase("");
    setBusy(false);
    if (res.ok) {
      qc.invalidateQueries({ queryKey: ["approvals"] });
      onClose();
      return;
    }
    // The message is the backend's generic reason — it never contains the
    // passphrase. A stale re-evaluation surfaces the engine's `missing` array.
    const missing = (res as { missing?: string[] }).missing;
    setError(missing?.length
      ? `Re-evaluation failed — the incident no longer meets: ${missing.join(", ")}`
      : (res.error ?? "step-up verification failed"));
  }, [approval.id, passphrase, busy, qc, onClose]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
    };
    document.addEventListener("keydown", onKey);
    panelRef.current?.focus();
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  const canSubmit = Boolean(passphrase.trim()) && !busy;

  return (
    <div
      className="is-approval-overlay"
      data-testid="approval-modal-overlay"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        ref={panelRef}
        className="is-approval-modal"
        role="dialog"
        aria-modal="true"
        aria-label={`Review approval for ${approval.runbookId}`}
        tabIndex={-1}
        data-testid="approval-modal"
      >
        <div className="is-approval-modal__h">
          <div>
            <h2>Review approval</h2>
            <div className="is-approval-modal__sub is-mono">
              {approval.incidentId} · {approval.connector} · {approval.id}
            </div>
          </div>
          <button
            type="button"
            className="is-approval-x"
            onClick={onClose}
            aria-label="Close review"
          >
            <X size={13} aria-hidden />
          </button>
        </div>

        <div className="is-approval-modal__body">
          <AuthoritativeBundle a={approval} />

          <form
            className="is-approval-form"
            onSubmit={(e) => { e.preventDefault(); decide("approve"); }}
          >
            <label className="is-field">
              <span>Step-up passphrase</span>
              <input
                type="password"
                className="is-input is-mono"
                data-testid="approval-passphrase"
                aria-label="Step-up passphrase"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                autoComplete="off"
                autoFocus
              />
            </label>
            <p className="is-mut is-approval-hint">
              Re-authenticate for this one action. The passphrase authorizes a single
              approve or reject and is never stored.
            </p>

            {error && (
              <p className="is-approval-err" role="alert" data-testid="approval-error">
                {error}
              </p>
            )}

            <div className="is-approval-actions">
              <button
                type="submit"
                className="is-btn is-btn--primary"
                data-testid="approval-approve"
                disabled={!canSubmit}
              >
                <ShieldCheck size={14} aria-hidden />
                Approve
              </button>
              <button
                type="button"
                className="is-btn"
                data-testid="approval-reject"
                disabled={!canSubmit}
                onClick={() => decide("reject")}
              >
                Reject
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

function ApprovalDetail({ a, onReview }: { a: Approval; onReview: () => void }) {
  const rr = a.requestRedacted ?? {};
  return (
    <div className="is-md__detail" data-testid="approval-detail">
      <div className="is-detail-head">
        <span className="is-tag is-tag--info">{a.state.toUpperCase()}</span>
        <span className="is-mono is-mut">{a.runbookId}</span>
        <span className="id">{a.id}</span>
      </div>
      <h2>{a.incidentId}</h2>

      <div className="is-vgrid">
        <div className="is-block">
          <div className="cap">Connector</div>
          <p className="is-mono">{a.connector}</p>
        </div>
        <div className="is-block">
          <div className="cap">Requested</div>
          <p className="is-mono is-mut">{a.createdAt}</p>
        </div>
      </div>

      <div>
        <div className="is-approval-lbl">
          Redacted command <span className="is-mut">— preview only; raw params stay on the connector transport</span>
        </div>
        <MonoBlock
          testid="approval-detail-redacted"
          lines={rr.error ? [rr.error] : [rr.command ?? "—"]}
        />
      </div>

      {/* Opening the review is a plain (non-accent) action — the accent budget
          is spent on Approve inside the modal, the single consequential act. */}
      <div>
        <button
          type="button"
          className="is-btn"
          data-testid="approval-open-review"
          onClick={onReview}
        >
          <ShieldCheck size={14} aria-hidden />
          Open review →
        </button>
      </div>
    </div>
  );
}

export function Approvals() {
  const [params, setParams] = useSearchParams();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["approvals"],
    queryFn: () => api.approvals(),
    refetchInterval: 5000,
  });

  const pending = useMemo(
    () => (data?.approvals ?? []).filter((a) => a.state === "pending"),
    [data]);

  const selId = params.get("sel");
  const selected =
    pending.find((a) => a.id === selId) ?? pending[0] ?? null;

  const [modalOpen, setModalOpen] = useState(false);

  const select = useCallback((idx: number) => {
    const a = pending[idx];
    if (a) setParams({ sel: a.id });
  }, [pending, setParams]);

  // J/K queue navigation — inert while the modal is open or focus is in a
  // field, so it never fights the passphrase input.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (modalOpen) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
      const k = e.key.toLowerCase();
      if (k !== "j" && k !== "k") return;
      e.preventDefault();
      const cur = pending.findIndex((a) => a.id === selected?.id);
      const base = cur < 0 ? 0 : cur;
      const next = k === "j"
        ? Math.min(base + 1, pending.length - 1)
        : Math.max(base - 1, 0);
      select(next);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [pending, selected, modalOpen, select]);

  if (isLoading) return <p className="is-mut">Loading pending approvals…</p>;

  if (isError) {
    return (
      <div className="is-note" data-testid="approvals-error">
        The approvals API is unreachable — no approvals can be shown. Nothing is invented.
      </div>
    );
  }

  if (pending.length === 0) {
    // Honest empty state — a plain line, no illustration filler.
    return (
      <div className="is-approval-empty" data-testid="approvals-empty">
        No pending approvals.
      </div>
    );
  }

  return (
    <div data-testid="approvals-screen">
      <div className="flex flex-wrap items-center gap-2.5">
        <span className="is-panel__sub">
          {pending.length} pending approval(s) · use <kbd className="is-kbd">J</kbd>/<kbd className="is-kbd">K</kbd> to move the queue
        </span>
      </div>

      <div className={cn("is-md", !selected && "!grid-cols-1")}>
        <div className="is-md__list">
          <div className="max-h-[56vh] overflow-auto" data-testid="approvals-scroll">
            <table className="is-table">
              <thead>
                <tr>
                  <th>State</th>
                  <th>Incident</th>
                  <th>Runbook</th>
                  <th>Connector</th>
                </tr>
              </thead>
              <tbody>
                {pending.map((a) => (
                  <tr
                    key={a.id}
                    data-testid="approval-row"
                    data-approval-id={a.id}
                    className={cn(selected?.id === a.id && "active")}
                    onClick={() => setParams({ sel: a.id })}
                  >
                    <td><span className="is-tag is-tag--info">{a.state.toUpperCase()}</span></td>
                    <td className="is-mono">{a.incidentId}</td>
                    <td className="is-mono">{a.runbookId}</td>
                    <td className="is-mono is-mut">{a.connector}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {selected && (
          <ApprovalDetail a={selected} onReview={() => setModalOpen(true)} />
        )}
      </div>

      {modalOpen && selected && (
        <ApprovalReviewModal approval={selected} onClose={() => setModalOpen(false)} />
      )}
    </div>
  );
}
