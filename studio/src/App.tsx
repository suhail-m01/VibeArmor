import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  Shield,
  LayoutGrid,
  Network,
  ShieldAlert,
  FileDiff,
  GitPullRequest,
  PlugZap,
  Crosshair,
  Code2,
  FlaskConical,
  Cpu,
  CheckCircle2,
  PlusCircle,
  ChevronRight,
  FolderCode,
  Sparkles,
} from "lucide-react";
import {
  BreachSimulation,
  EvalResults,
  ProjectDetailPayload,
  ProjectSummary,
  StagedProposalBundle,
  StreamEventItem,
} from "./types";
import { ImportHubView } from "./components/ImportHubView";
import { TopologyCanvas } from "./components/TopologyCanvas";
import { ThreatAnalysisView } from "./components/ThreatAnalysisView";
import { SurgicalDiffConsentView } from "./components/SurgicalDiffConsentView";
import { DeliverUpdatesView } from "./components/DeliverUpdatesView";
import { EditorExtensionView } from "./components/EditorExtensionView";
import { SplitDiffIdeView } from "./components/SplitDiffIdeView";
import { LiveExploitLabView } from "./components/LiveExploitLabView";
import { SandboxAndSupabaseView } from "./components/SandboxAndSupabaseView";
import { ResearchBenchmarkView } from "./components/ResearchBenchmarkView";
import { EvidenceCenterView } from "./components/EvidenceCenterView";
import { readSafeJson } from "./utils/safeJson";

type StudioView =
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

const VALID_VIEWS = new Set<StudioView>([
  "hub",
  "step1_graph",
  "step2_analysis",
  "step3_diff",
  "step4_deliver",
  "evidence",
  "extension",
  "ide",
  "exploit",
  "sandbox",
  "research",
]);

const ACTIVE_PROJECT_STORAGE_KEY = "vibearmor_active_project_id";

const WORKFLOW_STEPS: Array<{ id: StudioView; num: string; label: string; sub: string }> = [
  { id: "step1_graph", num: "01", label: "Code Structure Graph", sub: "Full Architecture Map" },
  { id: "step2_analysis", num: "02", label: "Analyze Vulnerabilities", sub: "5-Point Threat Audit" },
  { id: "step3_diff", num: "03", label: "Vulnerable vs. Correct", sub: "Surgical Diff & Consent" },
  { id: "step4_deliver", num: "04", label: "Update GitHub / .ZIP", sub: "Push PR or Download" },
];

export default function App() {
  const [view, setView] = useState<StudioView>("hub");
  const [slmLabel, setSlmLabel] = useState<string>("Qwen2.5-Coder GGUF · Local");

  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [activeProjectId, setActiveProjectId] = useState<string>("");
  const [projectDetail, setProjectDetail] = useState<ProjectDetailPayload | null>(null);
  const [selectedFile, setSelectedFile] = useState<string>("");

  // Non-destructive Surgical Staging & Adoption state
  const [stagedByProject, setStagedByProject] = useState<Record<string, StagedProposalBundle>>({});
  const [stagingBusy, setStagingBusy] = useState<boolean>(false);
  const [adoptingBusy, setAdoptingBusy] = useState<boolean>(false);
  const [healing, setHealing] = useState<boolean>(false);
  const [streamEvents, setStreamEvents] = useState<StreamEventItem[]>([]);
  const [evalData, setEvalData] = useState<EvalResults | null>(null);

  const bootedRef = useRef<boolean>(false);
  const loadSeqRef = useRef<number>(0);

  const persistActiveId = useCallback((pid: string) => {
    setActiveProjectId(pid);
    try {
      sessionStorage.setItem(ACTIVE_PROJECT_STORAGE_KEY, pid);
    } catch {
      // ignore storage errors
    }
  }, []);

  const refreshProjectsList = useCallback(async (): Promise<ProjectSummary[]> => {
    for (let attempt = 0; attempt < 6; attempt++) {
      try {
        const res = await fetch("/api/projects");
        if (res.ok) {
          const data = await readSafeJson<{ projects?: ProjectSummary[] }>(res);
          const list: ProjectSummary[] = data.projects || [];
          setProjects(list);
          return list;
        }
      } catch {
        // retry while local Python backend warms up
      }
      await new Promise((r) => setTimeout(r, 450));
    }
    return [];
  }, []);

  /** Race-safe, zero-dependency workspace loader — NEVER resets on selectedFile changes! */
  const loadProjectDetail = useCallback(
    async (pid: string): Promise<ProjectDetailPayload | null> => {
      if (!pid) return null;
      const seq = ++loadSeqRef.current;
      persistActiveId(pid);
      try {
        const res = await fetch(`/api/projects/${encodeURIComponent(pid)}`);
        if (!res.ok) return null;
        const detail: ProjectDetailPayload = await readSafeJson<ProjectDetailPayload>(res);
        if (seq !== loadSeqRef.current) {
          return detail;
        }
        setActiveProjectId(detail.project.id);
        setProjectDetail(detail);
        const allPaths = Object.keys(detail.files || {});
        setSelectedFile((prev) => (prev && detail.files?.[prev] ? prev : allPaths[0] || ""));
        return detail;
      } catch {
        return null;
      }
    },
    [persistActiveId]
  );

  /** Step 3: Stream non-destructive surgical proposals in memory (0 workspace disk mutations!) */
  const generateSurgicalProposals = useCallback(async (pid: string) => {
    if (!pid) return;
    setStagingBusy(true);
    setStreamEvents([]);
    try {
      const res = await fetch(`/api/projects/${encodeURIComponent(pid)}/propose-fixes-stream`, { method: "POST" });
      if (!res.ok || !res.body) {
        const syncRes = await fetch(`/api/projects/${encodeURIComponent(pid)}/propose-fixes`, { method: "POST" });
        if (syncRes.ok) {
          const bundle: StagedProposalBundle = await syncRes.json();
          setStagedByProject((prev) => ({ ...prev, [pid]: bundle }));
        }
        return;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const ln of lines) {
          if (!ln.trim()) continue;
          try {
            const msg = JSON.parse(ln);
            if (msg.type === "progress" && msg.event) {
              setStreamEvents((prev) => [...prev, msg.event]);
            } else if (msg.type === "complete" && msg.payload) {
              const bundle: StagedProposalBundle = msg.payload;
              setStagedByProject((prev) => ({ ...prev, [pid]: bundle }));
            }
          } catch {
            // ignore partial line
          }
        }
      }
    } finally {
      setStagingBusy(false);
    }
  }, []);

  // Single-run initialization (supports ?project=...&step=... deep links + sessionStorage persistence!)
  useEffect(() => {
    if (bootedRef.current) return;
    bootedRef.current = true;

    fetch("/api/health")
      .then((r) => r.json())
      .then((d) => {
        if (d?.slm?.gguf_model_cached) {
          setSlmLabel("Qwen2.5-Coder GGUF · On-Device");
        } else if (d?.slm?.ollama_online) {
          setSlmLabel("Ollama Qwen2.5-Coder · Local");
        }
      })
      .catch(() => {});

    fetch("/api/eval/results")
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d && setEvalData(d))
      .catch(() => {});

    (async () => {
      const params = new URLSearchParams(window.location.search);
      const urlProj = params.get("project") || "";
      const urlStep = (params.get("step") || "") as StudioView;

      let storedProj = "";
      try {
        storedProj = sessionStorage.getItem(ACTIVE_PROJECT_STORAGE_KEY) || "";
      } catch {
        // ignore
      }

      const list = await refreshProjectsList();
      const byId = new Set(list.map((p) => p.id));
      const userImported = list.filter((p) => p.source_type !== "reference");

      let initialPid = "vibebazaar-india";
      if (urlProj && byId.has(urlProj)) {
        initialPid = urlProj;
      } else if (storedProj && byId.has(storedProj)) {
        initialPid = storedProj;
      } else if (userImported.length > 0) {
        initialPid = userImported[userImported.length - 1].id;
      } else if (list.length > 0) {
        initialPid = list[0].id;
      }

      await loadProjectDetail(initialPid);

      if (urlStep && VALID_VIEWS.has(urlStep)) {
        setView(urlStep);
        if (urlStep === "step3_diff") {
          generateSurgicalProposals(initialPid);
        }
      }
    })();
  }, [generateSurgicalProposals, loadProjectDetail, refreshProjectsList]);

  /** Step 3 -> Step 4: User explicitly approves & adopts selected surgical fixes */
  async function handleAdoptSelectedFixes(selectedFindingIds: string[]) {
    if (!activeProjectId || adoptingBusy || selectedFindingIds.length === 0) return;
    setAdoptingBusy(true);
    try {
      const res = await fetch(`/api/projects/${encodeURIComponent(activeProjectId)}/adopt-fixes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ selected_finding_ids: selectedFindingIds }),
      });
      if (res.ok) {
        const updatedDetail: ProjectDetailPayload = await res.json();
        setProjectDetail(updatedDetail);
        await refreshProjectsList();
        setView("step4_deliver");
      }
    } finally {
      setAdoptingBusy(false);
    }
  }

  /** Direct streaming heal (used inside Full Repository IDE) */
  async function triggerDirectHeal() {
    if (!activeProjectId || healing) return;
    setHealing(true);
    setStreamEvents([]);
    try {
      const res = await fetch(`/api/projects/${encodeURIComponent(activeProjectId)}/heal-stream`, {
        method: "POST",
      });
      if (!res.ok || !res.body) return;
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const ln of lines) {
          if (!ln.trim()) continue;
          try {
            const msg = JSON.parse(ln);
            if (msg.type === "progress" && msg.event) {
              setStreamEvents((prev) => [...prev, msg.event]);
            } else if (msg.type === "complete" && msg.payload) {
              setProjectDetail(msg.payload);
              refreshProjectsList();
            }
          } catch {
            // ignore
          }
        }
      }
    } finally {
      setHealing(false);
    }
  }

  async function triggerProjectReset() {
    if (!activeProjectId || healing || adoptingBusy) return;
    const res = await fetch(`/api/projects/${encodeURIComponent(activeProjectId)}/reset`, {
      method: "POST",
    });
    if (res.ok) {
      const payload: ProjectDetailPayload = await res.json();
      setProjectDetail(payload);
      setStreamEvents([]);
      setStagedByProject((prev) => {
        const next = { ...prev };
        delete next[activeProjectId];
        return next;
      });
      await refreshProjectsList();
    }
  }

  async function handleDeleteProject(pid: string) {
    const res = await fetch(`/api/projects/${encodeURIComponent(pid)}`, { method: "DELETE" });
    if (!res.ok) return;
    setStagedByProject((prev) => {
      const next = { ...prev };
      delete next[pid];
      return next;
    });
    const nextList = await refreshProjectsList();
    if (pid === activeProjectId && nextList.length > 0) {
      await loadProjectDetail(nextList[0].id);
    }
  }

  const openStep3AndPropose = useCallback(
    (pidOverride?: string) => {
      const targetPid = pidOverride || activeProjectId;
      setView("step3_diff");
      if (targetPid && !stagedByProject[targetPid]) {
        generateSurgicalProposals(targetPid);
      }
    },
    [activeProjectId, stagedByProject, generateSurgicalProposals]
  );

  const navGroups: Array<{
    section: string;
    items: Array<{ id: StudioView; label: string; sub: string; icon: React.ComponentType<{ className?: string }> }>;
  }> = [
    {
      section: "GUIDED REPO WORKFLOW",
      items: [
        { id: "hub", label: "Upload GitHub / .ZIP", sub: "Import & Workspaces", icon: LayoutGrid },
        { id: "step1_graph", label: "1. Code Structure Graph", sub: "Complete Repo Map", icon: Network },
        { id: "step2_analysis", label: "2. Vulnerability Audit", sub: "5-Point Threat Scan", icon: ShieldAlert },
        { id: "step3_diff", label: "3. Vulnerable vs Correct", sub: "Surgical Diff & Consent", icon: FileDiff },
        { id: "step4_deliver", label: "4. Update GitHub / .ZIP", sub: "Push PR or Download", icon: GitPullRequest },
      ],
    },
    {
      section: "EXTENSIONS & LABS",
      items: [
        { id: "evidence", label: "Evidence & Agentic RAG", sub: "FAISS · LangGraph · Policy", icon: Sparkles },
        { id: "extension", label: "IDE & Browser Extensions", sub: ".vsix · Chrome · 2-Way Sync", icon: PlugZap },
        { id: "ide", label: "Full Repository IDE", sub: "Files · MSS · 3-Gate", icon: FolderCode },
        { id: "exploit", label: "Live Exploit Lab", sub: "SQLite & Webhook Probe", icon: Crosshair },
        { id: "sandbox", label: "Sandbox & Supabase", sub: "Paste Code · Live BaaS", icon: Code2 },
        { id: "research", label: "Empirical Benchmarks", sub: "SecurityEval · Recharts", icon: FlaskConical },
      ],
    },
  ];

  const openActionable = projectDetail
    ? projectDetail.report.mode === "auto_heal"
      ? projectDetail.report.summary.actionable_after
      : projectDetail.report.summary.actionable_before
    : 0;

  const isWorkflowStep = WORKFLOW_STEPS.some((s) => s.id === view);

  return (
    <div className="min-h-screen bg-[#F7F9FC] text-[#0F172A] flex flex-col lg:flex-row">
      {/* Left Precision SaaS Sidebar Rail */}
      <aside className="w-full lg:w-64 lg:shrink-0 border-b lg:border-b-0 lg:border-r border-slate-200 bg-white flex flex-col justify-between lg:sticky lg:top-0 lg:h-screen overflow-y-auto">
        <div>
          {/* Brand Header */}
          <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-600 text-white shadow-sm shadow-indigo-600/20">
                <Shield className="h-5 w-5 stroke-[2.2]" />
              </div>
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="text-base font-extrabold tracking-tight text-slate-900">VibeArmor</span>
                  <span className="rounded bg-indigo-50 px-1.5 py-0.5 font-mono text-[10px] font-bold text-indigo-700">
                    v3.0
                  </span>
                </div>
                <div className="text-[11px] font-medium text-slate-500">Pre-Push &amp; Deploy Guard</div>
              </div>
            </div>
          </div>

          {/* Active Workspace Selector */}
          <div className="px-4 py-3 border-b border-slate-100 bg-slate-50/60">
            <div className="flex items-center justify-between text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1.5">
              <span>Active Workspace</span>
              <button
                type="button"
                onClick={() => setView("hub")}
                className="inline-flex items-center gap-0.5 text-indigo-600 hover:underline"
              >
                <PlusCircle className="h-3 w-3" /> Import
              </button>
            </div>
            <select
              value={activeProjectId}
              onChange={async (e) => {
                const nextId = e.target.value;
                setStreamEvents([]);
                await loadProjectDetail(nextId);
                if (view === "step3_diff" && !stagedByProject[nextId]) {
                  generateSurgicalProposals(nextId);
                }
              }}
              className="w-full rounded-xl border border-slate-200 bg-white px-2.5 py-2 text-xs font-bold text-slate-800 shadow-sm focus:border-indigo-500 focus:outline-none"
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.security_score}/100)
                </option>
              ))}
            </select>
          </div>

          {/* Grouped Navigation Links */}
          <div className="p-3 space-y-4">
            {navGroups.map((grp) => (
              <div key={grp.section}>
                <div className="px-2.5 mb-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-400">
                  {grp.section}
                </div>
                <nav className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-1 gap-1">
                  {grp.items.map((item) => {
                    const Icon = item.icon;
                    const active = view === item.id;
                    return (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => {
                          if (item.id === "step3_diff") {
                            openStep3AndPropose();
                          } else {
                            setView(item.id);
                          }
                        }}
                        className={`group flex items-center justify-between rounded-xl px-2.5 py-2 text-left transition ${
                          active
                            ? "bg-indigo-50/90 text-indigo-950 ring-1 ring-indigo-200"
                            : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
                        }`}
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <Icon
                            className={`h-4 w-4 shrink-0 ${
                              active ? "text-indigo-600" : "text-slate-400 group-hover:text-slate-600"
                            }`}
                          />
                          <div className="min-w-0">
                            <div className={`text-xs truncate ${active ? "font-bold" : "font-semibold"}`}>
                              {item.label}
                            </div>
                            <div className="hidden lg:block text-[10px] text-slate-400 truncate">{item.sub}</div>
                          </div>
                        </div>
                        {active && <ChevronRight className="hidden lg:block h-3.5 w-3.5 text-indigo-500 shrink-0" />}
                      </button>
                    );
                  })}
                </nav>
              </div>
            ))}
          </div>
        </div>

        {/* Bottom Telemetry Footer */}
        <div className="hidden lg:block p-4 border-t border-slate-100 space-y-2 bg-slate-50/50">
          <div className="rounded-xl border border-slate-200 bg-white p-2.5 space-y-1">
            <div className="flex items-center gap-1.5 text-[11px] font-bold text-slate-800">
              <Cpu className="h-3.5 w-3.5 text-indigo-600" />
              {slmLabel}
            </div>
            <div className="flex items-center gap-1.5 text-[10.5px] font-medium text-emerald-700">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />
              Strict Surgical Guard Active
            </div>
          </div>
          <div className="px-1 text-[10px] text-slate-400 leading-snug">
            <strong className="text-slate-600">Team NeXGen Coder&apos;s</strong> · Presidency Univ.
          </div>
        </div>
      </aside>

      {/* Main Content Workspace */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Top Context & Readiness Strip */}
        <header className="sticky top-0 z-20 border-b border-slate-200/90 bg-white/95 backdrop-blur-md px-5 py-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <span className="font-semibold text-slate-800">Active Workspace</span>
            <span>/</span>
            <span className="rounded-md bg-slate-900 px-2.5 py-0.5 font-mono text-xs font-bold text-white truncate max-w-sm">
              {projectDetail?.project.name ?? "Loading..."}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 text-xs">
            <button
              type="button"
              onClick={() => setView("extension")}
              className="inline-flex items-center gap-1.5 rounded-full border border-indigo-200 bg-indigo-50 px-3 py-1 font-semibold text-indigo-700 hover:bg-indigo-100 transition"
            >
              <PlugZap className="h-3.5 w-3.5" /> Extensions (.vsix + Chrome + 2-Way Sync)
            </button>

            {projectDetail && (
              <span
                className={`rounded-full px-3 py-1 font-bold ${
                  openActionable > 0
                    ? "bg-rose-50 text-rose-700 border border-rose-200"
                    : "bg-emerald-50 text-emerald-700 border border-emerald-200"
                }`}
              >
                {openActionable > 0
                  ? `Push Blocked (${openActionable} Open Threats)`
                  : `Ready to Push & Deploy (${projectDetail.project.security_score}/100)`}
              </span>
            )}
          </div>
        </header>

        {/* Interactive 4-Step Pipeline Stepper Bar (shown across Steps 1–4!) */}
        {isWorkflowStep && (
          <div className="border-b border-slate-200 bg-white px-5 py-3">
            <div className="max-w-[1440px] mx-auto grid grid-cols-2 sm:grid-cols-4 gap-2">
              {WORKFLOW_STEPS.map((st, idx) => {
                const active = view === st.id;
                const currentIdx = WORKFLOW_STEPS.findIndex((x) => x.id === view);
                const completed = idx < currentIdx || (idx === 3 && Boolean(projectDetail?.project.adopted));
                return (
                  <button
                    key={st.id}
                    type="button"
                    onClick={() => {
                      if (st.id === "step3_diff") {
                        openStep3AndPropose();
                      } else {
                        setView(st.id);
                      }
                    }}
                    className={`flex items-center gap-2.5 rounded-xl border px-3 py-2 text-left transition ${
                      active
                        ? "border-indigo-600 bg-indigo-50/70 text-indigo-950 shadow-sm"
                        : completed
                        ? "border-emerald-200 bg-emerald-50/40 text-emerald-900 hover:bg-emerald-50"
                        : "border-slate-200 bg-slate-50/60 text-slate-600 hover:bg-slate-100"
                    }`}
                  >
                    <span
                      className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full font-mono text-[11px] font-bold ${
                        active
                          ? "bg-indigo-600 text-white"
                          : completed
                          ? "bg-emerald-600 text-white"
                          : "bg-slate-200 text-slate-700"
                      }`}
                    >
                      {completed && !active ? "✓" : st.num}
                    </span>
                    <div className="min-w-0">
                      <div className="text-xs font-bold truncate">{st.label}</div>
                      <div className="text-[10px] opacity-75 truncate">{st.sub}</div>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Active View Body */}
        <main className="flex-1 p-5 sm:p-7 max-w-[1440px] w-full mx-auto">
          {view === "hub" && (
            <ImportHubView
              projects={projects}
              activeProjectId={activeProjectId}
              onDeleteProject={handleDeleteProject}
              onSelectProject={async (pid, target) => {
                setStreamEvents([]);
                await loadProjectDetail(pid);
                if (target === "ide") setView("step2_analysis");
                else setView("step1_graph");
              }}
              onImported={(detail) => {
                // Cancel any older in-flight load & lock active workspace to the newly imported project!
                loadSeqRef.current += 1;
                persistActiveId(detail.project.id);
                setProjectDetail(detail);
                const firstKey = Object.keys(detail.files || {})[0] || "";
                setSelectedFile(firstKey);
                setStreamEvents([]);
                refreshProjectsList();
                // Immediately open Step 1: Complete Code Structure Graph of THIS imported repository!
                setView("step1_graph");
              }}
            />
          )}

          {view === "step1_graph" && projectDetail && (
            <TopologyCanvas
              key={projectDetail.project.id}
              projectName={projectDetail.project.name}
              securityScore={projectDetail.project.security_score}
              report={projectDetail.report}
              onJumpToFile={(fp) => {
                setSelectedFile(fp);
                setView("ide");
              }}
              onTriggerHeal={() => {
                if (projectDetail.report.mode === "auto_heal") {
                  setView("step4_deliver");
                } else {
                  setView("step2_analysis");
                }
              }}
              healing={stagingBusy}
            />
          )}

          {view === "step2_analysis" && projectDetail && (
            <ThreatAnalysisView
              key={projectDetail.project.id}
              detail={projectDetail}
              onBackToGraph={() => setView("step1_graph")}
              onContinueToSurgicalDiff={() => openStep3AndPropose(projectDetail.project.id)}
            />
          )}

          {view === "step3_diff" && projectDetail && (
            <SurgicalDiffConsentView
              key={projectDetail.project.id}
              detail={projectDetail}
              stagedBundle={stagedByProject[projectDetail.project.id] || null}
              stagingBusy={stagingBusy}
              adoptingBusy={adoptingBusy}
              streamEvents={streamEvents}
              onGenerateProposals={() => generateSurgicalProposals(projectDetail.project.id)}
              onAdoptSelected={handleAdoptSelectedFixes}
              onSkipToDelivery={() => setView("step4_deliver")}
            />
          )}

          {view === "step4_deliver" && projectDetail && (
            <DeliverUpdatesView
              key={projectDetail.project.id}
              detail={projectDetail}
              onResetWorkspace={triggerProjectReset}
              onGoToDiffStep={() => openStep3AndPropose(projectDetail.project.id)}
            />
          )}

          {view === "evidence" && activeProjectId && (
            <EvidenceCenterView
              key={activeProjectId}
              projectId={activeProjectId}
              onGoToDiffStep={() => openStep3AndPropose(activeProjectId)}
            />
          )}

          {view === "extension" && (
            <EditorExtensionView
              projects={projects}
              activeProjectId={activeProjectId}
              activeGithubUrl={projectDetail?.project.github_repo_url}
              onProjectsMutated={async () => {
                await refreshProjectsList();
                if (activeProjectId) {
                  await loadProjectDetail(activeProjectId);
                }
              }}
              onSelectProjectStep={async (pid, step) => {
                await loadProjectDetail(pid);
                if (step === "step3_diff") {
                  openStep3AndPropose(pid);
                } else {
                  setView(step);
                }
              }}
            />
          )}

          {view === "ide" && projectDetail && (
            <SplitDiffIdeView
              key={projectDetail.project.id}
              detail={projectDetail}
              selectedFile={selectedFile}
              onSelectFile={setSelectedFile}
              onTriggerHeal={triggerDirectHeal}
              onTriggerReset={triggerProjectReset}
              healing={healing}
              streamEvents={streamEvents}
            />
          )}

          {view === "exploit" && (
            <LiveExploitLabView
              projectId={projectDetail?.project.id}
              projectName={projectDetail?.project.name}
              breach={projectDetail?.breach ?? null}
              onUpdateBreach={(b: BreachSimulation) =>
                setProjectDetail((prev) => (prev ? { ...prev, breach: b } : prev))
              }
              onTriggerHeal={triggerDirectHeal}
              onTriggerReset={triggerProjectReset}
              healing={healing}
            />
          )}

          {view === "sandbox" && (
            <SandboxAndSupabaseView
              projectId={projectDetail?.project.id}
              projectName={projectDetail?.project.name}
            />
          )}

          {view === "research" && <ResearchBenchmarkView data={evalData} />}
        </main>
      </div>
    </div>
  );
}
