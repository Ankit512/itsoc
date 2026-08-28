import { useRef, useState } from "react";
import { useLocation } from "react-router-dom";
import { Upload, Link as LinkIcon, TriangleAlert } from "lucide-react";
import { useJobs } from "@/store/jobs";
import { isBlobPageUrl, rawFileUrl } from "@/lib/rawUrl";
import { Collectors } from "@/pages/Collectors";

/** Sources — the merged log-intake screen (C1-T5). Collectors folds in here as
 *  a tab beside Uploads, so the two ways a log enters this console — an analyst
 *  handing it a file/URL, and a live listener receiving it — live on one screen.
 *  Both halves are surfaced HONESTLY and kept clearly labelled: nothing here
 *  invents a source, a running listener, or a parsed line.
 *
 *  This screen deliberately uses a TAB composition (per the card), not the
 *  master-detail of the C1-T2 template: Sources has two functional panels, not
 *  a list of items to drill into. The template's other contracts still hold —
 *  reuse the is-* system (here the shared `.is-tabs`), honest empty/error
 *  states, label the merged halves, and assert the honest surfaces in tests. */

const ACCEPTED_TITLE =
  "Accepted: .log .txt .out .csv .tsv .xml .json .jsonl .ndjson .html .evtx — max 64 MB";

/** Uploads tab — the analyst-supplied intake: a multi-format file drop (≤64 MB)
 *  and a URL fetch. Parsing happens locally by the rules engine; the URL path is
 *  SSRF/size/text-gated on the backend. Reuses the app's real intake store
 *  (useJobs) — the same pipeline the header's Upload dialog drives, so there is
 *  no second, divergent code path. */
function UploadsTab() {
  const startUpload = useJobs((s) => s.startUpload);
  const startUrl = useJobs((s) => s.startUrl);
  const startEvtx = useJobs((s) => s.startEvtx);
  const busy = useJobs((s) => s.busy);
  const [url, setUrl] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  const routeFiles = (files: FileList) => {
    const all = Array.from(files);
    const evtx = all.filter((f) => f.name.toLowerCase().endsWith(".evtx"));
    const rest = all.filter((f) => !f.name.toLowerCase().endsWith(".evtx"));
    if (rest.length) startUpload(rest);
    if (evtx.length) startEvtx(evtx);
  };

  const isBlob = isBlobPageUrl(url);
  const submitUrl = () => {
    const u = rawFileUrl(url);
    if (!u.trim()) return;
    startUrl(u);
    setUrl("");
  };

  return (
    <>
      <div className="is-note">
        <b>Parsed locally — nothing leaves this machine.</b> A file or URL you add becomes a new run;
        the rules engine on this machine sets every severity. No sample data is invented.
      </div>
      <div className="is-upload">
        <section>
          <div className="is-upload__lbl">UPLOAD FILES</div>
          <label title={ACCEPTED_TITLE} className="is-drop">
            <Upload className="h-5 w-5" strokeWidth={1.7} aria-hidden />
            <div className="t">Drop log files here or <span style={{ color: "var(--acc)" }}>browse</span></div>
            <div className="s">.log · .txt · .csv · .tsv · .json · .xml · .evtx — max 64 MB</div>
            <input
              ref={fileRef}
              type="file"
              multiple
              className="hidden"
              data-testid="sources-upload-file"
              aria-label="Upload logs"
              onChange={(e) => {
                if (e.target.files?.length) routeFiles(e.target.files);
                e.target.value = "";
              }}
            />
          </label>
          <button type="button" className="is-btn" disabled={busy} onClick={() => fileRef.current?.click()}>
            {busy ? "Analyzing…" : "Choose files…"}
          </button>
          <p className="is-mut" style={{ fontSize: 11, margin: 0, lineHeight: 1.5 }}>
            Files are parsed by the rules engine on this machine and become a new run. EVTX is ingested
            into the persistent store and appears on History.
          </p>
        </section>

        <section>
          <div className="is-upload__lbl">PASTE A LOG LINK</div>
          <form className="flex flex-col gap-2" onSubmit={(e) => { e.preventDefault(); submitUrl(); }}>
            <label className="is-field">
              <span>URL</span>
              <input
                className="is-input is-mono"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                aria-label="Log file URL"
                placeholder="https://host.local/var/log/auth.log"
                inputMode="url"
                autoComplete="off"
              />
            </label>
            {isBlob && (
              <p className="text-[11px]" style={{ color: "var(--high)" }}>
                That’s a web-page link, not the raw file — we’ll fetch the raw version instead:{" "}
                <span className="break-all font-mono">{rawFileUrl(url)}</span>
              </p>
            )}
            <p className="is-mut" style={{ fontSize: 11, margin: 0, lineHeight: 1.5 }}>
              The file is fetched once, read-only, then parsed locally (http/https only, public hosts,
              size- and text-gated). A page that isn’t a text log is rejected honestly.
            </p>
            <p style={{ display: "flex", gap: 7, fontSize: 11, margin: 0, color: "var(--high)", lineHeight: 1.5 }}>
              <TriangleAlert size={12} strokeWidth={1.7} aria-hidden style={{ flex: "none", marginTop: 2 }} />
              <span>A remote URL is an outbound request from this machine — only fetch sources you trust.</span>
            </p>
            <div>
              <button type="submit" disabled={!url.trim() || busy} className="is-btn is-btn--primary">
                <LinkIcon className="h-4 w-4" strokeWidth={1.8} aria-hidden /> Fetch &amp; parse →
              </button>
            </div>
          </form>
        </section>
      </div>
    </>
  );
}

type Tab = "uploads" | "collectors";

export function Sources() {
  const { pathname } = useLocation();
  // /collectors deep-links to the Collectors tab (and keeps existing bookmarks +
  // the collectors test working); /sources opens on Uploads, the first tab.
  const [tab, setTab] = useState<Tab>(pathname.includes("collector") ? "collectors" : "uploads");

  return (
    <>
      <div className="is-tabs" role="tablist" aria-label="Sources">
        <button role="tab" aria-selected={tab === "uploads"} className={tab === "uploads" ? "on" : ""}
                onClick={() => setTab("uploads")}>Uploads</button>
        <button role="tab" aria-selected={tab === "collectors"} className={tab === "collectors" ? "on" : ""}
                onClick={() => setTab("collectors")}>Collectors</button>
      </div>

      <div role="tabpanel" style={{ marginTop: 14, display: "flex", flexDirection: "column", gap: 14 }}>
        {tab === "uploads" ? <UploadsTab /> : <Collectors />}
      </div>
    </>
  );
}
