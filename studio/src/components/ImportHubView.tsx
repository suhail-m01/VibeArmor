import React, { useRef, useState } from "react";
import {
  GitBranch,
  UploadCloud,
  ArrowRight,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  FolderArchive,
  Globe,
  Layers,
  CheckCircle2,
  Loader2,
  Trash2,
} from "lucide-react";
import { ProjectDetailPayload, ProjectSummary } from "../types";
import { readSafeJson } from "../utils/safeJson";

interface Props {
  projects: ProjectSummary[];
  activeProjectId: string;
  onSelectProject: (id: string, targetView?: "topology" | "ide") => void;
  onImported: (detail: ProjectDetailPayload) => void;
  onDeleteProject?: (id: string) => void;
}

function ScoreRing({ score }: { score: number }) {
  const radius = 19;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;
  const strokeColor = score >= 85 ? "#059669" : score >= 55 ? "#D97706" : "#E11D48";
  const textColor = score >= 85 ? "text-emerald-700" : score >= 55 ? "text-amber-700" : "text-rose-700";

  return (
    <div className="relative inline-flex h-12 w-12 items-center justify-center">
      <svg className="h-12 w-12 -rotate-90" viewBox="0 0 48 48">
        <circle cx="24" cy="24" r={radius} fill="none" stroke="#E2E8F0" strokeWidth="4" />
        <circle
          cx="24"
          cy="24"
          r={radius}
          fill="none"
          stroke={strokeColor}
          strokeWidth="4"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <span className={`absolute font-mono text-xs font-extrabold ${textColor}`}>{score}</span>
    </div>
  );
}

const SAMPLE_GITHUB_REPOS = [
  { label: "suhail-m01/Knot", url: "https://github.com/suhail-m01/Knot" },
  { label: "suhail-m01/NeXGen-Coders-RAG", url: "https://github.com/suhail-m01/NeXGen-Coders-RAG" },
  { label: "suhail-m01/Presidency-DAC-BOS-MoM", url: "https://github.com/suhail-m01/Presidency-DAC-BOS-MoM" },
];

export const ImportHubView: React.FC<Props> = ({ projects, activeProjectId, onSelectProject, onImported, onDeleteProject }) => {
  const [repoUrl, setRepoUrl] = useState<string>("");
  const [branch, setBranch] = useState<string>("");
  const [subpath, setSubpath] = useState<string>("");
  const [ghBusy, setGhBusy] = useState<boolean>(false);
  const [zipBusy, setZipBusy] = useState<boolean>(false);
  const [dragActive, setDragActive] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  async function handleGitHubClone(e: React.FormEvent, overrideUrl?: string) {
    e.preventDefault();
    const targetUrl = (overrideUrl ?? repoUrl).trim();
    if (!targetUrl) return;
    setErrorMsg(null);
    setGhBusy(true);
    try {
      const res = await fetch("/api/projects/github", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_url: targetUrl,
          branch: branch.trim() || null,
          subpath: subpath.trim() || null,
        }),
      });
      const data = await readSafeJson<any>(res, "Failed to clone GitHub repository.");
      if (!res.ok) {
        throw new Error(data?.detail || "Failed to clone GitHub repository.");
      }
      onImported(data);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to clone repository.");
    } finally {
      setGhBusy(false);
    }
  }

  async function uploadZipFile(file: File) {
    setErrorMsg(null);
    setZipBusy(true);
    try {
      const form = new FormData();
      form.append("file", file);
      form.append("project_name", file.name.replace(/\.zip$/i, ""));
      const res = await fetch("/api/projects/upload-zip", {
        method: "POST",
        body: form,
      });
      const data = await readSafeJson<any>(res, "ZIP upload failed.");
      if (!res.ok) {
        throw new Error(data?.detail || "ZIP upload failed.");
      }
      onImported(data);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "ZIP upload failed.");
    } finally {
      setZipBusy(false);
    }
  }

  return (
    <div className="space-y-8">
      {/* Editorial Hero Header */}
      <div className="wiz-card rounded-2xl p-7 sm:p-8 relative overflow-hidden">
        <div className="absolute right-0 top-0 h-56 w-96 bg-gradient-to-bl from-indigo-50/90 via-sky-50/40 to-transparent pointer-events-none" />
        <div className="relative max-w-3xl">
          <div className="inline-flex items-center gap-2 rounded-full border border-indigo-200 bg-indigo-50/80 px-3 py-1 text-xs font-semibold text-indigo-700">
            <Sparkles className="h-3.5 w-3.5" />
            Closed-Loop Neuro-Symbolic DevSecOps · Zero Cloud Code Exfiltration
          </div>
          <h1 className="mt-3.5 text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900">
            Scan, Slice &amp; Auto-Heal Vibe-Coded Repositories in Seconds
          </h1>
          <p className="mt-2.5 text-sm leading-relaxed text-slate-600">
            Connect any public GitHub repository or upload a Lovable / Bolt / Cursor <code className="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-800">.zip</code> export. VibeArmor builds a unified AST + PostgreSQL RLS + Supply-Chain property graph, synthesizes surgical fixes with local{" "}
            <span className="font-semibold text-slate-800">Qwen2.5-Coder</span>, verifies every patch across 3 safety gates, and exports a clean{" "}
            <code className="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-800">git apply</code> patch.
          </p>

          <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { label: "Tier-1 Fast Scan", val: "< 35 ms", sub: "0 LLM calls on clean code" },
              { label: "Prompt Token Cut", val: "98.5%", sub: "~25-line Minimal Security Slice" },
              { label: "Verified Auto-Fix", val: "88.0%", sub: "Across 64 benchmark cases" },
              { label: "Broken Builds", val: "0.0%", sub: "3-Gate atomic rollback" },
            ].map((stat) => (
              <div key={stat.label} className="rounded-xl border border-slate-200/90 bg-slate-50/70 px-3.5 py-2.5">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{stat.label}</div>
                <div className="mt-0.5 font-mono text-lg font-extrabold text-slate-900">{stat.val}</div>
                <div className="text-[11px] text-slate-500">{stat.sub}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {errorMsg && (
        <div className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-xs font-medium text-rose-800 flex items-center justify-between">
          <span>{errorMsg}</span>
          <button type="button" onClick={() => setErrorMsg(null)} className="text-rose-600 underline ml-4">
            Dismiss
          </button>
        </div>
      )}

      {/* Two Primary Ingestion Cards: GitHub URL Clone + ZIP Archive Upload */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Card 1: Public GitHub Repository Cloner */}
        <form onSubmit={handleGitHubClone} className="wiz-card rounded-2xl p-6 lg:col-span-7 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2.5">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-600 text-white shadow-sm">
                  <Globe className="h-4 w-4" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-slate-900">Import Public GitHub Repository</h2>
                  <p className="text-xs text-slate-500">Shallow-clones, builds Cross-Layer Property Graph &amp; audits DPDP/OWASP posture</p>
                </div>
              </div>
              <span className="rounded-full bg-slate-100 px-2.5 py-1 font-mono text-[11px] font-semibold text-slate-600">
                git clone --depth 1
              </span>
            </div>

            <div className="mt-5 space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">GitHub Repository URL or owner/repo</label>
                <input
                  type="text"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  placeholder="https://github.com/owner/vibe-coded-app"
                  className="w-full rounded-xl border border-slate-300 bg-white px-3.5 py-2.5 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus:border-indigo-600 focus:outline-none focus:ring-2 focus:ring-indigo-500/15"
                />
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label className="block text-[11px] font-medium text-slate-600 mb-1">Branch (Optional)</label>
                  <div className="relative">
                    <GitBranch className="h-3.5 w-3.5 text-slate-400 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      value={branch}
                      onChange={(e) => setBranch(e.target.value)}
                      placeholder="main"
                      className="w-full rounded-xl border border-slate-200 bg-slate-50 pl-8 pr-3 py-2 font-mono text-xs text-slate-800 focus:border-indigo-500 focus:bg-white focus:outline-none"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-[11px] font-medium text-slate-600 mb-1">Monorepo Subpath (Optional)</label>
                  <input
                    type="text"
                    value={subpath}
                    onChange={(e) => setSubpath(e.target.value)}
                    placeholder="apps/web"
                    className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-800 focus:border-indigo-500 focus:bg-white focus:outline-none"
                  />
                </div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[11px] font-medium text-slate-500 mr-1">Quick test:</span>
              {SAMPLE_GITHUB_REPOS.map((sr) => (
                <button
                  key={sr.url}
                  type="button"
                  disabled={ghBusy}
                  onClick={(ev) => {
                    setRepoUrl(sr.url);
                    handleGitHubClone(ev, sr.url);
                  }}
                  className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1 font-mono text-[11px] text-slate-700 hover:border-indigo-300 hover:bg-indigo-50 hover:text-indigo-700 transition"
                >
                  {sr.label}
                </button>
              ))}
            </div>

            <button
              type="submit"
              disabled={ghBusy || !repoUrl.trim()}
              className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-xs font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-50 transition"
            >
              {ghBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ArrowRight className="h-4 w-4" />}
              {ghBusy ? "Cloning & Scanning..." : "Clone & Audit Repo"}
            </button>
          </div>
        </form>

        {/* Card 2: Drag-and-Drop ZIP Archive Upload */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragActive(true);
          }}
          onDragLeave={() => setDragActive(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragActive(false);
            const f = e.dataTransfer.files?.[0];
            if (f) uploadZipFile(f);
          }}
          className={`wiz-card rounded-2xl p-6 lg:col-span-5 flex flex-col justify-between transition ${
            dragActive ? "border-indigo-500 ring-2 ring-indigo-500/20 bg-indigo-50/30" : ""
          }`}
        >
          <div>
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-emerald-600 text-white shadow-sm">
                <FolderArchive className="h-4 w-4" />
              </div>
              <div>
                <h2 className="text-base font-bold text-slate-900">Upload Project .ZIP Archive</h2>
                <p className="text-xs text-slate-500">Drop a Lovable, Bolt.new, v0, or local codebase archive</p>
              </div>
            </div>

            <div
              onClick={() => fileInputRef.current?.click()}
              className="mt-5 cursor-pointer rounded-2xl border-2 border-dashed border-slate-300 bg-slate-50/70 p-6 text-center hover:border-indigo-400 hover:bg-indigo-50/30 transition"
            >
              <UploadCloud className="mx-auto h-8 w-8 text-indigo-600" />
              <div className="mt-2 text-xs font-semibold text-slate-800">
                {zipBusy ? "Extracting & Scanning Archive..." : "Click to browse or drag & drop a .zip archive"}
              </div>
              <p className="mt-1 text-[11px] text-slate-500">
                Zip-Slip protected · Skips node_modules/.git · Up to 35 MB
              </p>
              <input
                ref={fileInputRef}
                type="file"
                accept=".zip,application/zip"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) uploadZipFile(f);
                }}
              />
            </div>
          </div>

          <div className="mt-4 flex items-center justify-between text-[11px] text-slate-500 pt-3 border-t border-slate-100">
            <span className="inline-flex items-center gap-1 text-emerald-700 font-medium">
              <CheckCircle2 className="h-3.5 w-3.5" /> Exports git .patch &amp; healed .zip
            </span>
            <span>Supports TS/TSX · Py · SQL · JSON</span>
          </div>
        </div>
      </div>

      {/* Active Workspace Inventory Table */}
      <div className="wiz-card rounded-2xl overflow-hidden">
        <div className="border-b border-slate-200 px-6 py-4 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-bold text-slate-900">Audited Workspaces &amp; Reference Targets</h2>
            <p className="text-xs text-slate-500">
              Select any repository to inspect its Cross-Layer Security Graph, Side-by-Side Split Diffs, or run Auto-Heal
            </p>
          </div>
          <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-700">
            {projects.length} Workspace{projects.length === 1 ? "" : "s"} Ready
          </span>
        </div>

        <div className="divide-y divide-slate-200/80">
          {projects.map((p) => {
            const isCurrent = p.id === activeProjectId;
            return (
              <div
                key={p.id}
                className={`flex flex-col gap-4 px-6 py-4 sm:flex-row sm:items-center sm:justify-between transition ${
                  isCurrent ? "bg-indigo-50/40" : "hover:bg-slate-50/80"
                }`}
              >
                <div className="flex items-center gap-4">
                  <ScoreRing score={p.security_score} />
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-bold text-slate-900">{p.name}</span>
                      {isCurrent && (
                        <span className="rounded-md bg-indigo-600 px-2 py-0.5 font-mono text-[10px] font-bold uppercase text-white">
                          ACTIVE
                        </span>
                      )}
                      <span className="rounded-md border border-slate-200 bg-white px-2 py-0.5 font-mono text-[10px] font-semibold uppercase text-slate-600">
                        {p.source_type}
                      </span>
                      {p.actionable_open > 0 ? (
                        <span className="inline-flex items-center gap-1 rounded-full bg-rose-50 border border-rose-200 px-2.5 py-0.5 text-[11px] font-semibold text-rose-700">
                          <ShieldAlert className="h-3 w-3" /> {p.actionable_open} Open Vulnerabilities
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 border border-emerald-200 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-700">
                          <ShieldCheck className="h-3 w-3" /> Hardened ({p.verified_fixed} Verified Fixes)
                        </span>
                      )}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-slate-500">
                      <span className="font-mono text-[11px]">{p.source_label}</span>
                      <span>·</span>
                      <span className="inline-flex items-center gap-1">
                        <Layers className="h-3.5 w-3.5 text-slate-400" /> {p.node_count} Graph Nodes
                      </span>
                      <span>·</span>
                      <span className="font-mono">Scan: {p.scan_latency_ms} ms</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => onSelectProject(p.id, "topology")}
                    className="rounded-xl border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition"
                  >
                    1. Code Structure Graph
                  </button>
                  <button
                    type="button"
                    onClick={() => onSelectProject(p.id, "ide")}
                    className="inline-flex items-center gap-1.5 rounded-xl bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-600 transition"
                  >
                    2. Analyze &amp; Fix <ArrowRight className="h-3.5 w-3.5" />
                  </button>
                  {p.source_type !== "reference" && onDeleteProject && (
                    <button
                      type="button"
                      title="Remove workspace"
                      onClick={() => onDeleteProject(p.id)}
                      className="rounded-xl border border-slate-200 bg-white p-2 text-slate-400 hover:border-rose-200 hover:bg-rose-50 hover:text-rose-600 transition"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
