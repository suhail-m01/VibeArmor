import React, { useMemo } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Sparkles,
  PlusCircle,
  Network,
  FileDiff,
  GitPullRequest,
  PlugZap,
  Crosshair,
  FolderCode,
  Code2,
  FlaskConical,
  ArrowRight,
  CheckCircle2,
  Layers,
  Activity,
  Building2,
} from "lucide-react";
import { EvalResults, ProjectDetailPayload, ProjectSummary } from "../types";
import { AuthUserProfile } from "./AuthGatewayView";

export type DashboardTargetView =
  | "dashboard"
  | "hub"
  | "step1_graph"
  | "step2_analysis"
  | "step3_diff"
  | "step4_deliver"
  | "evidence"
  | "extension"
  | "ide"
  | "exploit"
  | "sandbox"
  | "research";

interface Props {
  user: AuthUserProfile;
  projects: ProjectSummary[];
  activeProjectId: string;
  detail: ProjectDetailPayload | null;
  evalData: EvalResults | null;
  slmLabel: string;
  onNavigate: (target: DashboardTargetView) => void;
  onSelectWorkspace: (projectId: string, nextView?: DashboardTargetView) => void;
}

export const HomeDashboardView: React.FC<Props> = ({
  user,
  projects,
  activeProjectId,
  detail,
  evalData,
  slmLabel,
  onNavigate,
  onSelectWorkspace,
}) => {
  const greeting = useMemo(() => {
    const hr = new Date().getHours();
    if (hr < 12) return "Good morning";
    if (hr < 17) return "Good afternoon";
    return "Good evening";
  }, []);

  const firstName = user.name.split(" ")[0] || "Architect";
  const activeScore = detail?.project.security_score ?? 0;
  const openThreats = detail
    ? detail.report.mode === "auto_heal"
      ? detail.report.summary.actionable_after
      : detail.report.summary.actionable_before
    : 0;
  const verifiedFixes = detail?.report.summary.verified_fixed_count ?? 0;
  const nodeCount = detail?.report.nodes.length ?? 0;
  const edgeCount = detail?.report.edges.length ?? 0;
  const scanMs = detail?.report.scan_latency_ms ?? 0;

  const readyReposCount = projects.filter((p) => p.actionable_open === 0).length;
  const radius = 26;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (Math.max(0, Math.min(100, activeScore)) / 100) * circumference;

  const scoreColor =
    openThreats === 0 && activeScore >= 85
      ? "#10B981"
      : activeScore >= 55
      ? "#F59E0B"
      : "#F43F5E";

  const pillarCounts = useMemo(() => {
    const activeFindings =
      detail?.report.mode === "auto_heal"
        ? detail.report.findings_after
        : detail?.report.findings_before || [];
    const map = {
      secret_boundary: 0,
      rls_dpdp: 0,
      taint_payment: 0,
      supply_chain: 0,
    };
    for (const f of activeFindings) {
      if (f.pillar in map) {
        map[f.pillar as keyof typeof map] += 1;
      }
    }
    return map;
  }, [detail]);

  return (
    <div className="space-y-6">
      {/* Breathable Luxury Hero */}
      <section className="relative overflow-hidden rounded-3xl border border-slate-200/90 bg-white/95 backdrop-blur-xl px-7 py-6 shadow-[0_14px_40px_-12px_rgba(15,23,42,0.055)] animate-lux-fade-up">
        <div className="pointer-events-none absolute -right-12 -top-16 h-64 w-64 rounded-full bg-indigo-100/70 blur-3xl animate-lux-aurora" />
        <div
          className="pointer-events-none absolute right-52 -bottom-20 h-48 w-48 rounded-full bg-emerald-100/50 blur-3xl animate-lux-aurora"
          style={{ animationDelay: "-6s" }}
        />

        <div className="relative flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-indigo-200/80 bg-indigo-50/80 px-3 py-1 text-[11px] font-bold text-indigo-700">
                <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
                Command Center
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-[11px] font-semibold text-slate-600">
                <Building2 className="h-3 w-3 text-slate-400" />
                {user.organization}
              </span>
            </div>

            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900">
              {greeting},{" "}
              <span className="lux-gradient-text">{firstName}</span>
            </h1>

            <p className="text-xs sm:text-sm text-slate-500">
              Real-time AST &amp; RAG protection across your workspaces.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={() => onNavigate("hub")}
              className="inline-flex items-center gap-2 rounded-2xl border border-slate-200 bg-white px-4 py-2.5 text-xs font-bold text-slate-800 shadow-sm hover:border-indigo-300 hover:text-indigo-700 cursor-pointer"
            >
              <PlusCircle className="h-4 w-4 text-indigo-600" />
              Import Repo
            </button>

            <button
              type="button"
              onClick={() => onNavigate(openThreats > 0 ? "step2_analysis" : "step1_graph")}
              className="lux-btn-shimmer inline-flex items-center gap-2 rounded-2xl bg-gradient-to-r from-indigo-600 to-violet-600 px-5 py-2.5 text-xs font-extrabold text-white shadow-md shadow-indigo-500/20 hover:from-indigo-700 hover:to-violet-700 cursor-pointer"
            >
              <Sparkles className="h-4 w-4 text-indigo-200" />
              {openThreats > 0 ? `Audit & Heal (${openThreats})` : "Open Graph"}
              <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </section>

      {/* 4 Animated KPI Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {/* KPI 1: Radial Score + Orbit Halo */}
        <div
          onClick={() => onNavigate("step1_graph")}
          className="lux-card-interactive rounded-2xl p-5 flex items-center justify-between gap-3 cursor-pointer animate-lux-fade-up lux-delay-1"
        >
          <div className="space-y-1 min-w-0">
            <div className="text-[10.5px] font-bold uppercase tracking-wider text-slate-400">Security Score</div>
            <div className="text-2xl font-extrabold text-slate-900 font-mono">{activeScore}/100</div>
            <div className="text-[11px] font-semibold truncate text-slate-500">
              {detail?.project.name ?? "Loading..."}
            </div>
          </div>
          <div className="relative h-16 w-16 shrink-0 flex items-center justify-center">
            <div className="absolute inset-0 rounded-full border border-dashed border-slate-200 animate-lux-orbit" />
            <svg className="h-14 w-14 -rotate-90" viewBox="0 0 64 64">
              <circle cx="32" cy="32" r={radius} stroke="#EEF2F6" strokeWidth="6" fill="none" />
              <circle
                cx="32"
                cy="32"
                r={radius}
                stroke={scoreColor}
                strokeWidth="6"
                strokeLinecap="round"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                fill="none"
                style={{ transition: "stroke-dashoffset 0.9s cubic-bezier(0.16, 1, 0.3, 1)" }}
              />
            </svg>
            <span className="absolute font-mono text-[11px] font-extrabold text-slate-800">{activeScore}%</span>
          </div>
        </div>

        {/* KPI 2: Push Gate with Live Radar Pulse */}
        <div
          onClick={() => onNavigate(openThreats > 0 ? "step2_analysis" : "step4_deliver")}
          className="lux-card-interactive rounded-2xl p-5 flex flex-col justify-between cursor-pointer animate-lux-fade-up lux-delay-2"
        >
          <div className="flex items-center justify-between">
            <span className="text-[10.5px] font-bold uppercase tracking-wider text-slate-400">Push Gate</span>
            <div className="relative flex h-8 w-8 items-center justify-center">
              <span
                className={`absolute inset-0 rounded-xl animate-lux-pulse-ring ${
                  openThreats > 0 ? "bg-rose-400/35" : "bg-emerald-400/35"
                }`}
              />
              <div
                className={`relative flex h-8 w-8 items-center justify-center rounded-xl ${
                  openThreats > 0 ? "bg-rose-50 text-rose-600" : "bg-emerald-50 text-emerald-600"
                }`}
              >
                {openThreats > 0 ? <ShieldAlert className="h-4 w-4" /> : <ShieldCheck className="h-4 w-4" />}
              </div>
            </div>
          </div>
          <div className="pt-2">
            <div className="font-mono text-2xl font-extrabold text-slate-900">
              {openThreats > 0 ? `${openThreats} Open` : "Clear"}
            </div>
            <div className={`text-[11px] font-bold mt-0.5 ${openThreats > 0 ? "text-rose-600" : "text-emerald-600"}`}>
              {openThreats > 0 ? "Blocked · Review Fixes →" : "Verified Ready ✓"}
            </div>
          </div>
        </div>

        {/* KPI 3: AST Graph */}
        <div
          onClick={() => onNavigate("evidence")}
          className="lux-card-interactive rounded-2xl p-5 flex flex-col justify-between cursor-pointer animate-lux-fade-up lux-delay-3"
        >
          <div className="flex items-center justify-between">
            <span className="text-[10.5px] font-bold uppercase tracking-wider text-slate-400">AST &amp; RAG Graph</span>
            <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-indigo-50 text-indigo-600">
              <Layers className="h-4 w-4" />
            </div>
          </div>
          <div className="pt-2">
            <div className="font-mono text-2xl font-extrabold text-slate-900">
              {nodeCount} <span className="text-xs font-semibold text-slate-400">nodes</span> · {edgeCount}{" "}
              <span className="text-xs font-semibold text-slate-400">edges</span>
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5">
              {Math.round(scanMs)} ms · {verifiedFixes} verified
            </div>
          </div>
        </div>

        {/* KPI 4: Workspaces */}
        <div
          onClick={() => onNavigate("research")}
          className="lux-card-interactive rounded-2xl p-5 flex flex-col justify-between cursor-pointer animate-lux-fade-up lux-delay-4"
        >
          <div className="flex items-center justify-between">
            <span className="text-[10.5px] font-bold uppercase tracking-wider text-slate-400">Workspaces</span>
            <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-sky-50 text-sky-600">
              <Activity className="h-4 w-4" />
            </div>
          </div>
          <div className="pt-2">
            <div className="font-mono text-2xl font-extrabold text-slate-900">
              {projects.length} <span className="text-xs font-semibold text-slate-400">repos</span>{" "}
              <span className="text-[10.5px] font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-full ml-1">
                {readyReposCount} clean
              </span>
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5 truncate">
              {evalData ? `${evalData.datasets.total_evaluated_cases} benchmark cases` : slmLabel}
            </div>
          </div>
        </div>
      </section>

      {/* Animated 4-Stage Pipeline with Flowing Laser Beam */}
      <section className="wiz-card rounded-3xl p-5 sm:p-6 space-y-4 animate-lux-fade-up lux-delay-2">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-indigo-600 animate-pulse" />
            <h2 className="text-sm font-extrabold text-slate-900">Closed-Loop Pipeline</h2>
          </div>
          <span className="rounded-full bg-slate-100 px-2.5 py-0.5 font-mono text-[10.5px] font-semibold text-slate-600 truncate max-w-xs">
            {detail?.project.name ?? activeProjectId}
          </span>
        </div>

        <div className="relative">
          {/* Animated Flowing Beam Track (Desktop) */}
          <div className="hidden lg:block pointer-events-none absolute top-1/2 left-8 right-8 -translate-y-1/2 h-[2px] bg-slate-200/80 overflow-hidden rounded-full">
            <div className="h-full w-1/3 bg-gradient-to-r from-transparent via-indigo-500 to-transparent animate-lux-beam" />
          </div>

          <div className="relative z-10 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {[
              {
                step: "01",
                id: "step1_graph" as DashboardTargetView,
                title: "Structure Graph",
                tag: `${nodeCount} AST Nodes`,
                icon: Network,
                accent: "text-indigo-600 bg-indigo-50 border-indigo-100",
              },
              {
                step: "02",
                id: "step2_analysis" as DashboardTargetView,
                title: "Threat Audit",
                tag: openThreats > 0 ? `${openThreats} Actionable` : "All Pillars Clear",
                icon: ShieldAlert,
                accent:
                  openThreats > 0
                    ? "text-rose-600 bg-rose-50 border-rose-100"
                    : "text-emerald-600 bg-emerald-50 border-emerald-100",
              },
              {
                step: "03",
                id: "step3_diff" as DashboardTargetView,
                title: "Surgical Diff",
                tag: "Line-Exact Patch",
                icon: FileDiff,
                accent: "text-violet-600 bg-violet-50 border-violet-100",
              },
              {
                step: "04",
                id: "step4_deliver" as DashboardTargetView,
                title: "Push & Export",
                tag: "GitHub PR · .ZIP",
                icon: GitPullRequest,
                accent: "text-emerald-600 bg-emerald-50 border-emerald-100",
              },
            ].map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => onNavigate(item.id)}
                  className="group text-left rounded-2xl border border-slate-200/90 bg-white/95 hover:bg-white p-4 transition-all hover:-translate-y-1 hover:border-indigo-300 hover:shadow-md cursor-pointer flex items-center justify-between gap-3"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div
                      className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border ${item.accent} group-hover:scale-105 transition`}
                    >
                      <Icon className="h-4 w-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="font-mono text-[10px] font-bold text-slate-400">STEP {item.step}</div>
                      <div className="text-xs font-extrabold text-slate-900 group-hover:text-indigo-700 truncate">
                        {item.title}
                      </div>
                      <div className="text-[10.5px] font-medium text-slate-500 truncate">{item.tag}</div>
                    </div>
                  </div>
                  <ArrowRight className="h-4 w-4 text-slate-300 group-hover:text-indigo-600 group-hover:translate-x-0.5 transition shrink-0" />
                </button>
              );
            })}
          </div>
        </div>
      </section>

      {/* Bottom 2-Column Bento: Workspaces + Security Modules */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left 7 Cols */}
        <div className="lg:col-span-7 space-y-5">
          <div className="wiz-card rounded-3xl p-5 sm:p-6 space-y-3.5">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-extrabold text-slate-900">Monitored Workspaces</h3>
              <button
                type="button"
                onClick={() => onNavigate("hub")}
                className="inline-flex items-center gap-1 rounded-xl border border-indigo-200 bg-indigo-50/80 px-3 py-1.5 text-xs font-bold text-indigo-700 hover:bg-indigo-100 cursor-pointer"
              >
                <PlusCircle className="h-3.5 w-3.5" /> Add
              </button>
            </div>

            <div className="space-y-2">
              {projects.map((p) => {
                const isSelected = p.id === activeProjectId;
                const clean = p.actionable_open === 0;
                return (
                  <div
                    key={p.id}
                    onClick={() => onSelectWorkspace(p.id, "step1_graph")}
                    className={`group rounded-2xl border p-3 flex items-center justify-between gap-3 transition-all hover:-translate-y-0.5 cursor-pointer ${
                      isSelected
                        ? "border-indigo-300 bg-indigo-50/45 shadow-sm"
                        : "border-slate-200/80 bg-white hover:border-indigo-200 hover:bg-slate-50/60"
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div
                        className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl font-mono text-xs font-extrabold ${
                          clean
                            ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                            : "bg-rose-50 text-rose-700 border border-rose-200"
                        }`}
                      >
                        {p.security_score}
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-extrabold text-slate-900 truncate">{p.name}</span>
                          {isSelected && (
                            <span className="rounded-full bg-indigo-600 px-2 py-0.5 text-[9px] font-bold text-white">
                              ACTIVE
                            </span>
                          )}
                        </div>
                        <div className="text-[10.5px] text-slate-400 truncate">
                          {p.node_count} nodes · {Math.round(p.scan_latency_ms)} ms
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span
                        className={`rounded-full px-2.5 py-0.5 text-[10.5px] font-bold ${
                          clean
                            ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                            : "bg-rose-50 text-rose-700 border border-rose-200"
                        }`}
                      >
                        {clean ? "✓ Ready" : `${p.actionable_open} Open`}
                      </span>
                      <ArrowRight className="h-4 w-4 text-slate-300 group-hover:text-indigo-600 group-hover:translate-x-0.5 transition" />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Compact 4-Pillar Strip */}
          <div className="wiz-card rounded-3xl p-5 space-y-3">
            <h3 className="text-xs font-extrabold uppercase tracking-wider text-slate-400">Threat Pillars</h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
              {[
                { label: "Secrets", count: pillarCounts.secret_boundary },
                { label: "Supabase RLS", count: pillarCounts.rls_dpdp },
                { label: "SQLi & HMAC", count: pillarCounts.taint_payment },
                { label: "Supply Chain", count: pillarCounts.supply_chain },
              ].map((pil) => (
                <div
                  key={pil.label}
                  className="rounded-2xl border border-slate-200/80 bg-slate-50/70 px-3.5 py-2.5 flex items-center justify-between"
                >
                  <div>
                    <div className="text-[10.5px] font-bold text-slate-500">{pil.label}</div>
                    <div className="font-mono text-base font-extrabold text-slate-900">{pil.count}</div>
                  </div>
                  {pil.count === 0 ? (
                    <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                  ) : (
                    <ShieldAlert className="h-4 w-4 text-rose-500 animate-pulse" />
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right 5 Cols: Compact Interactive Security Modules */}
        <div className="lg:col-span-5 wiz-card rounded-3xl p-5 sm:p-6 space-y-3.5">
          <h3 className="text-sm font-extrabold text-slate-900">Security Labs &amp; Guards</h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-1 gap-2">
            {[
              {
                id: "evidence" as DashboardTargetView,
                title: "Evidence & Agentic RAG",
                sub: "FAISS · LangGraph",
                icon: Sparkles,
                badge: "AI",
              },
              {
                id: "extension" as DashboardTargetView,
                title: "IDE & Browser Guards",
                sub: "VS Code · Chrome MV3",
                icon: PlugZap,
                badge: "Sync",
              },
              {
                id: "exploit" as DashboardTargetView,
                title: "Live Exploit Lab",
                sub: "SQLi · Webhook Probe",
                icon: Crosshair,
                badge: "Gate 3",
              },
              {
                id: "ide" as DashboardTargetView,
                title: "Repository Split-IDE",
                sub: "Source · Security Slice",
                icon: FolderCode,
                badge: "IDE",
              },
              {
                id: "sandbox" as DashboardTargetView,
                title: "Sandbox & Supabase",
                sub: "Snippet · Live RLS",
                icon: Code2,
                badge: "BaaS",
              },
              {
                id: "research" as DashboardTargetView,
                title: "SecurityEval Metrics",
                sub: "Recall · Benchmarks",
                icon: FlaskConical,
                badge: "Data",
              },
            ].map((mod) => {
              const Icon = mod.icon;
              return (
                <button
                  key={mod.id}
                  type="button"
                  onClick={() => onNavigate(mod.id)}
                  className="group w-full rounded-2xl border border-slate-200/80 bg-slate-50/50 hover:bg-white hover:border-indigo-300 px-3.5 py-2.5 text-left flex items-center justify-between gap-3 transition-all hover:-translate-y-0.5 hover:shadow-sm cursor-pointer"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-white border border-slate-200 text-indigo-600 group-hover:bg-indigo-600 group-hover:text-white group-hover:border-indigo-600 group-hover:scale-105 transition">
                      <Icon className="h-4 w-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-extrabold text-slate-900 truncate">{mod.title}</div>
                      <div className="text-[10px] text-slate-400 truncate">{mod.sub}</div>
                    </div>
                  </div>
                  <span className="shrink-0 rounded-full bg-indigo-50 border border-indigo-100 px-2 py-0.5 font-mono text-[9.5px] font-bold text-indigo-700">
                    {mod.badge}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      </section>
    </div>
  );
};
