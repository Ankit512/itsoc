import { useEffect, useRef, type ReactNode } from "react";
import { X } from "lucide-react";

/** A minimal accessible modal dialog, hand-rolled to match the app's existing
 *  shadcn-style components (which use only @radix-ui/react-slot — no
 *  react-dialog dep). Backdrop click and Escape close it; focus moves in on
 *  open; role="dialog" + aria-modal for assistive tech. */
export function Dialog({ open, onClose, title, subtitle, wide, children }:
  { open: boolean; onClose: () => void; title: string; subtitle?: string;
    wide?: boolean; children: ReactNode }) {
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    // Move focus into the dialog so keyboard users land inside it.
    panelRef.current?.focus();
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[60] flex items-start justify-center bg-black/40 p-4 pt-[12vh]"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        ref={panelRef}
        role="dialog" aria-modal="true" aria-label={title} tabIndex={-1}
        className={
          "is-modal rounded-lg bg-card shadow-[var(--shadow-modal)] outline-none " +
          (wide ? "w-full max-w-[680px]" : "w-full max-w-[440px] p-4")
        }
      >
        {/* dc modal head: title + mono provenance line, close on the right. */}
        <div className={wide ? "is-modal__h" : "mb-3 flex items-center gap-2"}>
          <div>
            <h2 className="text-[14px] font-semibold">{title}</h2>
            {subtitle && <div className="is-modal__sub is-mono">{subtitle}</div>}
          </div>
          <button
            onClick={onClose} aria-label="Close dialog"
            className="ml-auto inline-flex h-[26px] w-[26px] items-center justify-center rounded-md text-muted-foreground hover:bg-background"
          >
            <X className="h-[13px] w-[13px]" aria-hidden />
          </button>
        </div>
        {wide ? <div className="is-modal__body">{children}</div> : children}
      </div>
    </div>
  );
}
