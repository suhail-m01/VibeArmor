import React, { useState } from "react";
import {
  Code2,
  Copy,
  Database,
  Play,
  Plus,
  Zap,
  CheckCircle2,
  Download,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Loader2,
} from "lucide-react";
import { SANDBOX_PRESETS } from "../presets";
import { ScanAndHealReport, SupabaseAuditResult } from "../types";
import { copyTextSafe } from "../utils/artifactDelivery";

interface SandboxProps {
  projectId?: string;
  projectName?: string;
}

export const SandboxAndSupabaseView: React.FC<SandboxProps> = ({
  projectId,
  projectName,
}) => {
  const [subMode, setSubMode] = useState<"sandbox" | "supabase">("sandbox");
  const [patchCopied, setPatchCopied] = useState<boolean>(false);

  // Sandbox state
  const [presetId, setPresetId] = useState<string>(SANDBOX_PRESETS[0].id);
  const [files, setFiles] = useState<Array<{ path: string; content: string }>>(SANDBOX_PRESETS[0].files);
  const [busy, setBusy] = useState<boolean>(false);
  const [report, setReport] = useState<ScanAndHealReport | null>(null);
  const [afterFiles, setAfterFiles] = useState<Record<string, string>>({});
  const [gitPatch, setGitPatch] = useState<string>("");

  // Live Supabase Auditor state
  const [sbUrl, setSbUrl] = useState<string>("");
  const [sbKey, setSbKey] = useState<string>("");
  const [sbBusy, setSbBusy] = useState<boolean>(false);
  const [sbError, setSbError] = useState<string | null>(null);
  const [sbResult, setSbResult] = useState<SupabaseAuditResult | null>(null);

  async function runSandbox(autoHeal: boolean) {
    setBusy(true);
    try {
      const res = await fetch("/api/sandbox/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ files, auto_heal: autoHeal, allow_slm: true }),
      });
      const data = await res.json();
      if (res.ok) {
        setReport(data.report);
        setAfterFiles(data.after_files || {});
        setGitPatch(data.git_patch || "");
      }
    } finally {
      setBusy(false);
    }
  }

  async function downloadSandboxPatch() {
    if (!gitPatch) return;
    await copyTextSafe(gitPatch);
    setPatchCopied(true);
    setTimeout(() => setPatchCopied(false), 2200);
    try {
      const blob = new Blob([gitPatch], { type: "text/x-diff" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "vibearmor-sandbox.patch";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    } catch {
      // Clipboard copy already succeeded above
    }
  }

  async function handleWorkspaceSqlAudit() {
    if (!projectId) return;
    setSbError(null);
    setSbBusy(true);
    try {
      const res = await fetch(`/api/projects/${encodeURIComponent(projectId)}/supabase-sql-audit`, {
        method: "POST",
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.detail || "Workspace SQL audit failed.");
      }
      setSbResult(data);
    } catch (err: unknown) {
      setSbError(err instanceof Error ? err.message : "Workspace SQL audit failed.");
    } finally {
      setSbBusy(false);
    }
  }

  async function handleSupabaseAudit(e: React.FormEvent) {
    e.preventDefault();
    setSbError(null);
    setSbBusy(true);
    try {
      const res = await fetch("/api/supabase-live/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ supabase_url: sbUrl, anon_key: sbKey }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.detail || "Live Supabase audit failed.");
      }
      setSbResult(data);
    } catch (err: unknown) {
      setSbError(err instanceof Error ? err.message : "Audit failed.");
    } finally {
      setSbBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Mode Toggle */}
      <div className="wiz-card rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-extrabold text-slate-900">
            Interactive Multi-File Code Sandbox &amp; Live Cloud BaaS Auditor
          </h2>
          <p className="text-xs text-slate-500">
            Paste custom application code across multiple layers, or perform a 100% read-only live Supabase PostgREST exposure audit
          </p>
        </div>
        <div className="inline-flex rounded-xl border border-slate-200 bg-slate-100/80 p-1">
          <button
            type="button"
            onClick={() => setSubMode("sandbox")}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-bold transition ${
              subMode === "sandbox" ? "bg-white text-slate-900 shadow-sm" : "text-slate-600 hover:text-slate-900"
            }`}
          >
            <Code2 className="h-3.5 w-3.5 text-indigo-600" /> Multi-File Paste Sandbox
          </button>
          <button
            type="button"
            onClick={() => setSubMode("supabase")}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-bold transition ${
              subMode === "supabase" ? "bg-white text-slate-900 shadow-sm" : "text-slate-600 hover:text-slate-900"
            }`}
          >
            <Database className="h-3.5 w-3.5 text-emerald-600" /> Live Supabase URL Auditor
          </button>
        </div>
      </div>

      {/* SUB-MODE A: MULTI-FILE CODE SANDBOX */}
      {subMode === "sandbox" && (
        <div className="space-y-5">
          <div className="wiz-card rounded-2xl p-5">
            <div className="mb-3 text-xs font-bold uppercase tracking-wider text-slate-500">
              Load Curated Scenario (Includes False-Positive Hard Negative &amp; Policy Abstention)
            </div>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
              {SANDBOX_PRESETS.map((pr) => (
                <button
                  key={pr.id}
                  type="button"
                  onClick={() => {
                    setPresetId(pr.id);
                    setFiles(pr.files.map((f) => ({ ...f })));
                    setReport(null);
                  }}
                  className={`rounded-xl border p-3 text-left transition ${
                    presetId === pr.id
                      ? "border-indigo-500 bg-indigo-50/60 ring-1 ring-indigo-500/20"
                      : "border-slate-200 bg-white hover:border-slate-300"
                  }`}
                >
                  <div className="text-xs font-bold text-slate-900">{pr.label}</div>
                  <div className="mt-1 inline-block rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-indigo-700">
                    {pr.badge}
                  </div>
                </button>
              ))}
            </div>

            <div className="mt-5 space-y-3">
              {files.map((f, idx) => (
                <div key={idx} className="rounded-xl border border-slate-200 bg-slate-50/70 p-3.5">
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <input
                      value={f.path}
                      onChange={(e) => {
                        const next = [...files];
                        next[idx] = { ...next[idx], path: e.target.value };
                        setFiles(next);
                      }}
                      className="w-full max-w-md rounded-lg border border-slate-300 bg-white px-3 py-1.5 font-mono text-xs font-semibold text-slate-900 focus:border-indigo-600 focus:outline-none"
                    />
                    {files.length > 1 && (
                      <button
                        type="button"
                        onClick={() => setFiles(files.filter((_, i) => i !== idx))}
                        className="text-xs font-semibold text-rose-600 hover:underline"
                      >
                        Remove File
                      </button>
                    )}
                  </div>
                  <textarea
                    rows={8}
                    value={f.content}
                    onChange={(e) => {
                      const next = [...files];
                      next[idx] = { ...next[idx], content: e.target.value };
                      setFiles(next);
                    }}
                    className="w-full rounded-xl border border-slate-200 bg-[#0F172A] p-3.5 font-mono text-xs text-slate-100 focus:border-indigo-500 focus:outline-none"
                  />
                </div>
              ))}
            </div>

            <div className="mt-4 flex flex-wrap items-center gap-2.5">
              <button
                type="button"
                onClick={() => setFiles([...files, { path: "src/module.ts", content: "" }])}
                className="inline-flex items-center gap-1.5 rounded-xl border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50"
              >
                <Plus className="h-3.5 w-3.5" /> Add File
              </button>

              <button
                type="button"
                disabled={busy}
                onClick={() => runSandbox(false)}
                className="inline-flex items-center gap-1.5 rounded-xl border border-slate-300 bg-white px-4 py-2 text-xs font-bold text-slate-800 hover:bg-slate-50"
              >
                <Play className="h-3.5 w-3.5 text-indigo-600" /> {busy ? "Scanning..." : "Fast Scan Only (<180ms)"}
              </button>

              <button
                type="button"
                disabled={busy}
                onClick={() => runSandbox(true)}
                className="inline-flex items-center gap-1.5 rounded-xl bg-indigo-600 px-4 py-2 text-xs font-bold text-white shadow-sm hover:bg-indigo-700"
              >
                <Zap className="h-3.5 w-3.5" /> {busy ? "Synthesizing & Verifying..." : "Scan + Auto-Heal + 3-Gate Verify"}
              </button>

              {gitPatch && report?.mode === "auto_heal" && (
                <button
                  type="button"
                  onClick={downloadSandboxPatch}
                  className="ml-auto inline-flex items-center gap-1.5 rounded-xl border border-emerald-300 bg-emerald-50 px-3.5 py-2 text-xs font-bold text-emerald-800 hover:bg-emerald-100 cursor-pointer"
                >
                  {patchCopied ? <Copy className="h-3.5 w-3.5" /> : <Download className="h-3.5 w-3.5" />}
                  {patchCopied ? "Copied & Exported .patch ✓" : "Copy / Download .patch"}
                </button>
              )}
            </div>
          </div>

          {report && (
            <div className="wiz-card rounded-2xl p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-3">
                <div className="flex items-center gap-2 text-sm font-bold text-slate-900">
                  {report.summary.actionable_before === 0 && report.summary.abstained_policy_count === 0 ? (
                    <span className="inline-flex items-center gap-1.5 text-emerald-700">
                      <CheckCircle2 className="h-4 w-4 text-emerald-600" /> Clean Fast-Path Verified in {report.scan_latency_ms} ms (0 False Positives)
                    </span>
                  ) : (
                    <span>
                      {report.findings_before.length} Signal(s) Analyzed · Scan {report.scan_latency_ms} ms · Total {report.total_latency_ms} ms
                    </span>
                  )}
                </div>
                <span className="font-mono text-xs text-slate-600">
                  Verified Fixes: {report.summary.verified_fixed_count} · Abstained: {report.summary.abstained_policy_count} · Broken Builds: 0
                </span>
              </div>

              {report.abstentions.map((ab) => (
                <div key={ab.id} className="rounded-xl border border-amber-300 bg-amber-50 p-3.5 text-xs text-amber-950 flex items-start gap-2">
                  <AlertTriangle className="h-4 w-4 shrink-0 text-amber-600 mt-0.5" />
                  <div>
                    <div className="font-bold">[{ab.rule_id}] Honest Boundary Abstention — {ab.title}</div>
                    <div className="mt-0.5">{ab.abstention_reason}</div>
                  </div>
                </div>
              ))}

              {report.mode === "auto_heal" && Object.keys(afterFiles).length > 0 && (
                <div className="space-y-3">
                  {Object.entries(afterFiles).map(([fp, content]) => (
                    <div key={fp} className="rounded-xl border border-slate-200 overflow-hidden">
                      <div className="bg-slate-100 px-3.5 py-2 font-mono text-xs font-bold text-slate-800">{fp}</div>
                      <pre className="max-h-64 overflow-auto bg-[#0F172A] p-3.5 font-mono text-xs text-slate-100">{content}</pre>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* SUB-MODE B: LIVE SUPABASE URL + ANON KEY AUDITOR */}
      {subMode === "supabase" && (
        <div className="space-y-5">
          <form onSubmit={handleSupabaseAudit} className="wiz-card rounded-2xl p-6 space-y-4">
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Read-Only Live Supabase PostgREST Exposure Auditor (CVE-2025-48757)
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Performs non-destructive <code className="rounded bg-slate-100 px-1 py-0.5">GET /rest/v1/</code> OpenAPI &amp; <code className="rounded bg-slate-100 px-1 py-0.5">limit=2</code> checks using your public <code className="rounded bg-slate-100 px-1 py-0.5">anon</code> key to detect world-readable PII tables and synthesize PostgreSQL RLS policies.
              </p>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Supabase Project URL</label>
                <input
                  value={sbUrl}
                  onChange={(e) => setSbUrl(e.target.value)}
                  placeholder="https://your-project-ref.supabase.co"
                  className="w-full rounded-xl border border-slate-300 bg-white px-3.5 py-2.5 font-mono text-xs focus:border-indigo-600 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Public Anon / Publishable Key</label>
                <input
                  value={sbKey}
                  onChange={(e) => setSbKey(e.target.value)}
                  placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                  className="w-full rounded-xl border border-slate-300 bg-white px-3.5 py-2.5 font-mono text-xs focus:border-indigo-600 focus:outline-none"
                />
              </div>
            </div>

            {sbError && (
              <div className="rounded-xl border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-xs text-rose-800">{sbError}</div>
            )}

            <div className="flex flex-wrap items-center gap-2.5">
              <button
                type="submit"
                disabled={sbBusy || !sbUrl.trim() || !sbKey.trim()}
                className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-xs font-bold text-white hover:bg-indigo-700 disabled:opacity-50 cursor-pointer"
              >
                {sbBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Database className="h-4 w-4" />}
                {sbBusy ? "Inspecting Live PostgREST..." : "Run Non-Destructive Exposure Audit"}
              </button>

              {projectId && (
                <button
                  type="button"
                  disabled={sbBusy}
                  onClick={handleWorkspaceSqlAudit}
                  className="inline-flex items-center gap-2 rounded-xl border border-emerald-300 bg-emerald-50 px-4 py-2.5 text-xs font-bold text-emerald-900 hover:bg-emerald-100 disabled:opacity-50 cursor-pointer"
                >
                  <Database className="h-4 w-4 text-emerald-700" />
                  Audit Active Workspace SQL Schema ({projectName || projectId})
                </button>
              )}
            </div>
          </form>

          {sbResult && (
            <div className="wiz-card rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                <span className="text-sm font-bold text-slate-900">
                  Discovered {sbResult.tables_discovered} PostgREST Endpoints ({sbResult.latency_ms} ms)
                </span>
                <span className="font-mono text-xs text-slate-500">{sbResult.supabase_url}</span>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {sbResult.tables.map((t) => (
                  <div key={t.table} className="rounded-xl border border-slate-200 bg-slate-50/70 p-3.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-slate-900">public.{t.table}</span>
                      <span
                        className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-bold ${
                          t.risk === "SAFE" ? "bg-emerald-100 text-emerald-800" : "bg-rose-100 text-rose-800"
                        }`}
                      >
                        {t.risk === "SAFE" ? <ShieldCheck className="h-3 w-3" /> : <ShieldAlert className="h-3 w-3" />}
                        {t.risk}
                      </span>
                    </div>
                    <div className="mt-1 text-[11px] text-slate-600">
                      Columns: <span className="font-mono">{t.columns.join(", ") || "—"}</span>
                    </div>
                    {t.dpdp_pii_columns.length > 0 && (
                      <div className="mt-1 text-[11px] font-semibold text-rose-700">
                        DPDP PII: {t.dpdp_pii_columns.join(", ")}
                      </div>
                    )}
                  </div>
                ))}
              </div>

              <div>
                <div className="text-xs font-bold text-slate-800 mb-1.5">Recommended Hardening SQL Migration</div>
                <pre className="rounded-xl bg-[#0F172A] p-4 font-mono text-xs text-emerald-300 overflow-x-auto">
                  {sbResult.recommended_rls_migration}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
