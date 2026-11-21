import React, { useEffect, useState } from "react";
import { readSafeJson } from "./safeJson";
import {
  CheckCircle2,
  Copy,
  Download,
  FileCode2,
  FolderCheck,
  ShieldCheck,
  Terminal,
  X,
} from "lucide-react";

export type ArtifactKind =
  | "vsix"
  | "browser_zip"
  | "bridge_py"
  | "project_zip"
  | "project_patch"
  | "project_cert"
  | "github_push_script";

export interface StagedArtifactInfo {
  artifact_kind: ArtifactKind;
  filename: string;
  size_bytes: number;
  saved_workspace_path: string;
  download_path: string;
  offline_powershell_cmd?: string | null;
  offline_bash_cmd?: string | null;
  is_text: boolean;
  is_html: boolean;
  text_content?: string | null;
}

/** Iframe-safe clipboard helper: tries Clipboard API first, then hidden textarea execCommand('copy'). */
export async function copyTextSafe(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fallback below for cross-origin / sandboxed iframes
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "true");
    ta.style.position = "fixed";
    ta.style.top = "-9999px";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

export async function triggerBlobDownload(downloadPath: string, filename: string): Promise<void> {
  try {
    const res = await fetch(downloadPath);
    if (!res.ok) return;
    const blob = await res.blob();
    const blobUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = blobUrl;
    a.download = filename;
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(blobUrl), 2500);
  } catch {
    // Sandboxed iframe may block browser download; offline installer & workspace export handle delivery!
  }
}

export async function stageAndFetchArtifact(params: {
  artifact_kind: ArtifactKind;
  project_id?: string;
  repo_url?: string;
  mode?: string;
  base_branch?: string;
}): Promise<StagedArtifactInfo> {
  const res = await fetch("/api/exports/stage", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  const data = await readSafeJson<any>(res, "Failed to prepare artifact.");
  if (!res.ok) {
    throw new Error(data?.detail || "Failed to prepare artifact.");
  }
  if (data.download_path && data.filename && !data.is_html) {
    triggerBlobDownload(data.download_path, data.filename);
  }
  return data as StagedArtifactInfo;
}

interface ModalProps {
  artifact: StagedArtifactInfo | null;
  onClose: () => void;
}

export const ArtifactDeliveryModal: React.FC<ModalProps> = ({ artifact, onClose }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    if (!artifact) return;
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [artifact, onClose]);

  if (!artifact) return null;

  const kb = (artifact.size_bytes / 1024).toFixed(1);

  async function handleCopy(key: string, val: string) {
    await copyTextSafe(val);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2400);
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-2xl bg-white border border-slate-200 shadow-2xl p-6 space-y-4"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="flex items-start justify-between gap-3 border-b border-slate-200 pb-3.5">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-emerald-100 text-emerald-700">
              <CheckCircle2 className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-slate-900">
                Artifact Ready · <code className="font-mono text-sm text-indigo-700">{artifact.filename}</code> ({kb} KB)
              </h3>
              <p className="text-xs text-slate-500">
                Staged in Arena Workspace:{" "}
                <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] font-semibold text-slate-800">
                  {artifact.saved_workspace_path}
                </code>
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700 cursor-pointer"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* PRIMARY: 100% Offline Self-Contained PowerShell 5.1/7 & Bash Installers (ZERO Network / ZERO TLS / ZERO '&&' Errors!) */}
        {(artifact.offline_powershell_cmd || artifact.offline_bash_cmd) && (
          <div className="rounded-2xl border-2 border-emerald-300 bg-emerald-50/70 p-4 space-y-3">
            <div className="flex items-start gap-2">
              <ShieldCheck className="h-4 w-4 text-emerald-700 shrink-0 mt-0.5" />
              <div>
                <div className="text-xs font-extrabold text-emerald-950">
                  Recommended · 1-Paste Self-Contained Offline Installer (Zero Network / Zero TLS Errors!)
                </div>
                <p className="text-[11px] text-emerald-900 leading-relaxed">
                  Embeds the verified binary directly in the command — works in <strong>Windows PowerShell 5.1 &amp; 7</strong>{" "}
                  (<code className="font-mono">PS C:\Users\DELL&gt;</code> or <code className="font-mono">PS C:\Windows\System32&gt;</code>), writes safely to your{" "}
                  <code className="font-mono">Downloads</code> folder, and auto-installs without calling <code className="font-mono">Invoke-WebRequest</code> or <code className="font-mono">&amp;&amp;</code>!
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {artifact.offline_powershell_cmd && (
                <button
                  type="button"
                  onClick={() => handleCopy("offline-ps", artifact.offline_powershell_cmd || "")}
                  className="inline-flex items-center justify-center gap-2 rounded-xl bg-slate-900 px-4 py-3 text-xs font-extrabold text-white shadow-sm hover:bg-indigo-700 transition cursor-pointer"
                >
                  <Terminal className="h-4 w-4 text-emerald-400" />
                  {copiedKey === "offline-ps"
                    ? "Copied PowerShell 5.1/7 Installer ✓ (Paste & Press Enter!)"
                    : "Copy 1-Paste Installer (Windows PowerShell)"}
                </button>
              )}

              {artifact.offline_bash_cmd && (
                <button
                  type="button"
                  onClick={() => handleCopy("offline-sh", artifact.offline_bash_cmd || "")}
                  className="inline-flex items-center justify-center gap-2 rounded-xl border border-emerald-400 bg-white px-4 py-3 text-xs font-extrabold text-slate-900 hover:bg-emerald-100 transition cursor-pointer"
                >
                  <Copy className="h-4 w-4 text-emerald-700" />
                  {copiedKey === "offline-sh"
                    ? "Copied macOS / Linux Installer ✓"
                    : "Copy 1-Paste Installer (macOS / Linux / Git Bash)"}
                </button>
              )}
            </div>
          </div>
        )}

        {/* SECONDARY: Download from Arena Workspace File Explorer or Browser Blob */}
        <div className="rounded-xl border border-indigo-200 bg-indigo-50/70 p-3.5 flex flex-wrap items-center justify-between gap-2">
          <div className="text-xs text-indigo-950 flex items-center gap-2">
            <FolderCheck className="h-4 w-4 text-indigo-600 shrink-0" />
            <span>
              <strong>Direct File Download:</strong> Open Arena&rsquo;s <strong>Files</strong> panel &rarr;{" "}
              <code className="rounded bg-white px-1.5 py-0.5 font-mono text-[11px] font-bold border border-indigo-200">
                {artifact.saved_workspace_path}
              </code>{" "}
              &rarr; click Download.
            </span>
          </div>
          <button
            type="button"
            onClick={() => triggerBlobDownload(artifact.download_path, artifact.filename)}
            className="inline-flex items-center gap-1 rounded-lg bg-indigo-600 px-3 py-1.5 text-[11px] font-bold text-white hover:bg-indigo-700 cursor-pointer"
          >
            <Download className="h-3.5 w-3.5" /> Trigger Browser Download
          </button>
        </div>

        {/* Inline Rendered HTML Audit Report */}
        {artifact.is_html && artifact.text_content && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-800">Live Security Audit Certificate Preview:</span>
              <button
                type="button"
                onClick={() => handleCopy("html", artifact.text_content || "")}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-300 bg-white px-2.5 py-1 text-[11px] font-bold text-slate-700 hover:bg-slate-50 cursor-pointer"
              >
                <Copy className="h-3 w-3" />
                {copiedKey === "html" ? "Copied HTML ✓" : "Copy HTML Source"}
              </button>
            </div>
            <iframe
              title="VibeArmor Security Audit Certificate"
              srcDoc={artifact.text_content}
              className="w-full h-96 rounded-xl border border-slate-200 bg-white"
            />
          </div>
        )}

        {/* Inline Source / Patch Viewer + Copy Full File */}
        {artifact.is_text && !artifact.is_html && artifact.text_content && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                <FileCode2 className="h-4 w-4 text-indigo-600" />
                Full File Contents ({artifact.filename}):
              </span>
              <button
                type="button"
                onClick={() => handleCopy("fulltext", artifact.text_content || "")}
                className="inline-flex items-center gap-1 rounded-lg bg-emerald-600 px-3 py-1.5 text-[11px] font-bold text-white hover:bg-emerald-700 cursor-pointer"
              >
                <Copy className="h-3 w-3" />
                {copiedKey === "fulltext" ? "Copied Full File ✓" : `Copy Full ${artifact.filename}`}
              </button>
            </div>
            <pre className="max-h-72 overflow-y-auto rounded-xl bg-[#0F172A] p-3.5 font-mono text-[11px] text-slate-100 leading-relaxed">
              {artifact.text_content}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};
