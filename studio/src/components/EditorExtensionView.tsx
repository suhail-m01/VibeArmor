import React, { useCallback, useEffect, useState } from "react";
import {
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  Chrome,
  Copy,
  Download,
  FolderSync,
  GitBranch,
  Globe,
  Laptop,
  Link2,
  Loader2,
  Lock,
  Play,
  PlugZap,
  RefreshCw,
  Rocket,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import {
  BrowserCheckResult,
  ExtensionStatusPayload,
  ExtensionVerifyResult,
  PairingSessionRecord,
  ProjectSummary,
} from "../types";
import {
  ArtifactDeliveryModal,
  ArtifactKind,
  copyTextSafe,
  stageAndFetchArtifact,
  StagedArtifactInfo,
} from "../utils/artifactDelivery";

interface Props {
  projects: ProjectSummary[];
  activeProjectId: string;
  activeGithubUrl?: string | null;
  onSelectProjectStep: (projectId: string, step: "step1_graph" | "step3_diff" | "step4_deliver") => void;
  onProjectsMutated: () => void;
}

type ExtTab = "pairing" | "ide_vsix" | "browser_ext";

export const EditorExtensionView: React.FC<Props> = ({
  projects,
  activeProjectId,
  activeGithubUrl,
  onSelectProjectStep,
  onProjectsMutated,
}) => {
  const [activeTab, setActiveTab] = useState<ExtTab>("pairing");
  const [extStatus, setExtStatus] = useState<ExtensionStatusPayload | null>(null);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  // Tab 1: Live Two-Way Pairing state
  const [pairEditor, setPairEditor] = useState<string>("Cursor");
  const [pairWorkspaceName, setPairWorkspaceName] = useState<string>("my-local-repo");
  const [pairLinkProjectId, setPairLinkProjectId] = useState<string>(activeProjectId);
  const [pairCreating, setPairCreating] = useState<boolean>(false);
  const [latestCreatedPair, setLatestCreatedPair] = useState<PairingSessionRecord | null>(null);
  const [syncAckBusy, setSyncAckBusy] = useState<string | null>(null);

  // Tab 2: In-Editor Sidebar Live Simulator state
  const [simEditor, setSimEditor] = useState<string>("Cursor AI IDE");
  const [simProjectId, setSimProjectId] = useState<string>(activeProjectId);
  const [simBranch, setSimBranch] = useState<string>("main");
  const [verifying, setVerifying] = useState<boolean>(false);
  const [adoptingInSim, setAdoptingInSim] = useState<boolean>(false);
  const [verifyResult, setVerifyResult] = useState<ExtensionVerifyResult | null>(null);
  const [uncheckedSimIds, setUncheckedSimIds] = useState<Record<string, boolean>>({});
  const [pushBannerMsg, setPushBannerMsg] = useState<string | null>(null);

  // Tab 3: Browser Extension Live Gate Simulator state
  const [browserRepoUrl, setBrowserRepoUrl] = useState<string>(
    activeGithubUrl || "https://github.com/suhail-m01/Knot"
  );
  const [browserPageHost, setBrowserPageHost] = useState<string>("github.com");
  const [browserBusy, setBrowserBusy] = useState<boolean>(false);
  const [browserResult, setBrowserResult] = useState<BrowserCheckResult | null>(null);
  const [interceptedAction, setInterceptedAction] = useState<string | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      const r = await fetch("/api/extension/status");
      if (r.ok) {
        const d: ExtensionStatusPayload = await r.json();
        setExtStatus(d);
      }
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    loadStatus();
  }, [loadStatus]);

  useEffect(() => {
    setSimProjectId(activeProjectId);
    setPairLinkProjectId(activeProjectId);
    const activeSummary = projects.find((p) => p.id === activeProjectId);
    if (activeSummary) {
      setPairWorkspaceName(activeSummary.name);
    }
  }, [activeProjectId, projects]);

  useEffect(() => {
    if (activeGithubUrl) {
      setBrowserRepoUrl(activeGithubUrl);
    }
  }, [activeGithubUrl]);

  const [activeArtifact, setActiveArtifact] = useState<StagedArtifactInfo | null>(null);
  const [downloadingKind, setDownloadingKind] = useState<ArtifactKind | null>(null);

  async function handleDeliverExtension(kind: ArtifactKind) {
    setDownloadingKind(kind);
    try {
      const staged = await stageAndFetchArtifact({ artifact_kind: kind });
      setActiveArtifact(staged);
    } catch {
      // ignore
    } finally {
      setDownloadingKind(null);
    }
  }

  function copyCmd(cmd: string) {
    copyTextSafe(cmd);
    setCopiedCmd(cmd);
    setTimeout(() => setCopiedCmd(null), 1800);
  }

  const originUrl = typeof window !== "undefined" ? window.location.origin : "http://127.0.0.1:8000";

  // --- Tab 1 Handlers ---
  async function handleCreatePairing(linkExisting: boolean) {
    setPairCreating(true);
    try {
      const res = await fetch("/api/extension/pair/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          editor: pairEditor,
          workspace_name: pairWorkspaceName || "local-workspace",
          project_id: linkExisting ? pairLinkProjectId : null,
        }),
      });
      if (res.ok) {
        const created: PairingSessionRecord = await res.json();
        setLatestCreatedPair(created);
        await loadStatus();
      }
    } finally {
      setPairCreating(false);
    }
  }

  async function handleSimulateEditorPullAck(sess: PairingSessionRecord) {
    setSyncAckBusy(sess.pair_token);
    try {
      await fetch(`/api/extension/pair/${encodeURIComponent(sess.pair_token)}/ack-fixes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ applied_files: sess.pending_file_names }),
      });
      await loadStatus();
    } finally {
      setSyncAckBusy(null);
    }
  }

  // --- Tab 2 Handlers ---
  async function runInEditorVerification(targetPid?: string) {
    const pid = targetPid || simProjectId;
    setVerifying(true);
    setPushBannerMsg(null);
    setUncheckedSimIds({});
    try {
      const res = await fetch("/api/extension/verify-readiness", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          editor: simEditor,
          project_id: pid,
          branch: simBranch,
          include_proposals: true,
        }),
      });
      if (res.ok) {
        const data: ExtensionVerifyResult = await res.json();
        setVerifyResult(data);
        await loadStatus();
      }
    } finally {
      setVerifying(false);
    }
  }

  async function handleAdoptInsideEditorSim() {
    if (!verifyResult) return;
    const chosenIds = (verifyResult.proposals || [])
      .filter((p) => p.adoptable && !uncheckedSimIds[p.finding_id])
      .map((p) => p.finding_id);
    if (chosenIds.length === 0) return;
    setAdoptingInSim(true);
    try {
      const res = await fetch(`/api/projects/${simProjectId}/adopt-fixes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ selected_finding_ids: chosenIds }),
      });
      if (res.ok) {
        onProjectsMutated();
        await runInEditorVerification(simProjectId);
        setPushBannerMsg(
          `✓ Adopted ${chosenIds.length} surgical fix(es) with 0 unrelated code changes. Hard Push Gate is now UNLOCKED!`
        );
      }
    } finally {
      setAdoptingInSim(false);
    }
  }

  // --- Tab 3 Handlers ---
  async function handleBrowserGateCheck() {
    setBrowserBusy(true);
    setInterceptedAction(null);
    try {
      const res = await fetch("/api/extension/browser/check-repo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_url: browserRepoUrl.trim(),
          page_host: browserPageHost,
          scan_if_missing: true,
        }),
      });
      if (res.ok) {
        const d: BrowserCheckResult = await res.json();
        setBrowserResult(d);
        onProjectsMutated();
        await loadStatus();
      }
    } finally {
      setBrowserBusy(false);
    }
  }

  const pairedSessions = extStatus?.paired_sessions || [];

  return (
    <div className="space-y-6">
      {/* Top Executive Extension Suite Header + 3 Direct Artifact Downloads */}
      <div className="wiz-card rounded-2xl p-6 sm:p-7 bg-gradient-to-br from-white via-white to-indigo-50/60">
        <div className="flex flex-col gap-5 xl:flex-row xl:items-center xl:justify-between">
          <div className="max-w-3xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-indigo-200 bg-indigo-50 px-3 py-1 text-xs font-bold text-indigo-700">
              <PlugZap className="h-3.5 w-3.5" />
              Complete Extension Suite · IDE (.vsix) + Browser (Chrome/Edge) + Live 2-Way Sync
            </div>
            <h2 className="mt-2.5 text-xl sm:text-2xl font-extrabold text-slate-900">
              Hard-Block Unsafe GitHub Pushes &amp; Deployments Across Every Editor &amp; Browser
            </h2>
            <p className="mt-1.5 text-xs sm:text-sm text-slate-600 leading-relaxed">
              Install the <strong>Desktop Code Editor Extension (.vsix)</strong> for VS Code, Cursor &amp; Windsurf, the{" "}
              <strong>Chrome / Edge Browser Extension</strong> for GitHub PRs &amp; Vercel/Netlify/Render deploys, or pair any local project folder with{" "}
              <strong>Live Two-Way Sync</strong> so surgical fixes approved in VibeArmor write straight back to your editor files.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 xl:grid-cols-1 gap-2 shrink-0 min-w-[265px]">
            <button
              type="button"
              disabled={downloadingKind !== null}
              onClick={() => handleDeliverExtension("vsix")}
              className="inline-flex items-center justify-between gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-60 transition cursor-pointer"
            >
              <span className="inline-flex items-center gap-2">
                {downloadingKind === "vsix" ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Download className="h-4 w-4" />
                )}{" "}
                Code Editor (.vsix)
              </span>
              <span className="font-mono text-[10px] opacity-85">VS Code · Cursor</span>
            </button>

            <button
              type="button"
              disabled={downloadingKind !== null}
              onClick={() => handleDeliverExtension("browser_zip")}
              className="inline-flex items-center justify-between gap-2 rounded-xl bg-slate-900 px-4 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-slate-800 disabled:opacity-60 transition cursor-pointer"
            >
              <span className="inline-flex items-center gap-2">
                {downloadingKind === "browser_zip" ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Chrome className="h-4 w-4" />
                )}{" "}
                Browser Guard (.zip)
              </span>
              <span className="font-mono text-[10px] opacity-85">Chrome · Edge</span>
            </button>

            <button
              type="button"
              disabled={downloadingKind !== null}
              onClick={() => handleDeliverExtension("bridge_py")}
              className="inline-flex items-center justify-between gap-2 rounded-xl border border-slate-300 bg-white px-4 py-2 text-xs font-bold text-slate-800 hover:bg-slate-50 disabled:opacity-60 transition cursor-pointer"
            >
              <span className="inline-flex items-center gap-2">
                {downloadingKind === "bridge_py" ? (
                  <Loader2 className="h-4 w-4 animate-spin text-indigo-600" />
                ) : (
                  <Terminal className="h-4 w-4 text-indigo-600" />
                )}{" "}
                2-Way Bridge (.py)
              </span>
              <span className="font-mono text-[10px] text-slate-500">Any Editor</span>
            </button>
          </div>
        </div>

        {/* 3-Mode Selector Tabs */}
        <div className="mt-6 pt-4 border-t border-slate-200/80 grid grid-cols-1 sm:grid-cols-3 gap-2.5">
          {[
            {
              id: "pairing" as ExtTab,
              title: "1. Live Two-Way Pairing",
              sub: "Editor Folder ⇄ Web Studio Sync",
              icon: FolderSync,
            },
            {
              id: "ide_vsix" as ExtTab,
              title: "2. Code Editor Extension (.vsix)",
              sub: "Rich In-Editor Panel & Hard Git Gate",
              icon: Laptop,
            },
            {
              id: "browser_ext" as ExtTab,
              title: "3. Browser Extension (MV3)",
              sub: "GitHub Merge & Vercel/Render Gate",
              icon: Globe,
            },
          ].map((t) => {
            const Icon = t.icon;
            const active = activeTab === t.id;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setActiveTab(t.id)}
                className={`flex items-center gap-3 rounded-xl border p-3 text-left transition ${
                  active
                    ? "border-indigo-600 bg-indigo-50/90 text-indigo-950 shadow-sm"
                    : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                }`}
              >
                <div
                  className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${
                    active ? "bg-indigo-600 text-white" : "bg-slate-100 text-slate-600"
                  }`}
                >
                  <Icon className="h-4 w-4" />
                </div>
                <div>
                  <div className="text-xs font-extrabold">{t.title}</div>
                  <div className="text-[11px] opacity-75">{t.sub}</div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* ==================== TAB 1: LIVE TWO-WAY WORKSPACE PAIRING ==================== */}
      {activeTab === "pairing" && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* Left: Generate Pairing Token & Connect Local Folder */}
          <div className="wiz-card rounded-2xl p-6 lg:col-span-5 space-y-4">
            <div className="flex items-center gap-2.5 border-b border-slate-100 pb-3">
              <Link2 className="h-5 w-5 text-indigo-600" />
              <div>
                <h3 className="text-sm font-extrabold text-slate-900">
                  Pair Local Editor Folder with VibeArmor Studio
                </h3>
                <p className="text-xs text-slate-500">
                  Syncs Graph + Diffs up to Web Studio &amp; writes approved surgical fixes straight back to your editor
                </p>
              </div>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">Code Editor</label>
                <select
                  value={pairEditor}
                  onChange={(e) => setPairEditor(e.target.value)}
                  className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-800"
                >
                  <option value="Cursor">Cursor AI IDE</option>
                  <option value="VS Code">Visual Studio Code</option>
                  <option value="Windsurf">Windsurf Editor</option>
                  <option value="Antigravity / VSCodium">Antigravity / VSCodium</option>
                  <option value="Zed / Neovim Bridge">Zed / Neovim / JetBrains (CLI Bridge)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Link Workspace (or enter local folder name)
                </label>
                <select
                  value={pairLinkProjectId}
                  onChange={(e) => {
                    setPairLinkProjectId(e.target.value);
                    const found = projects.find((p) => p.id === e.target.value);
                    if (found) setPairWorkspaceName(found.name);
                  }}
                  className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-800"
                >
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.actionable_open} open threats · {p.security_score}/100)
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1">
                <button
                  type="button"
                  disabled={pairCreating}
                  onClick={() => handleCreatePairing(true)}
                  className="inline-flex items-center justify-center gap-1.5 rounded-xl bg-indigo-600 px-3.5 py-2.5 text-xs font-bold text-white hover:bg-indigo-700 disabled:opacity-50 transition"
                >
                  {pairCreating ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlugZap className="h-4 w-4" />}
                  Pair Selected Workspace
                </button>
                <button
                  type="button"
                  disabled={pairCreating}
                  onClick={() => handleCreatePairing(false)}
                  className="inline-flex items-center justify-center gap-1.5 rounded-xl border border-slate-300 bg-white px-3.5 py-2.5 text-xs font-bold text-slate-700 hover:bg-slate-50 disabled:opacity-50 transition"
                >
                  Generate Blank Folder Token
                </button>
              </div>
            </div>

            {latestCreatedPair && (
              <div className="rounded-xl border border-indigo-200 bg-indigo-50/70 p-4 space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-extrabold uppercase tracking-wider text-indigo-800">
                    Active Pairing Token
                  </span>
                  <button
                    type="button"
                    onClick={() => copyCmd(latestCreatedPair.pair_token)}
                    className="inline-flex items-center gap-1 text-[11px] font-bold text-indigo-700 hover:underline"
                  >
                    <Copy className="h-3 w-3" />
                    {copiedCmd === latestCreatedPair.pair_token ? "Copied ✓" : "Copy Token"}
                  </button>
                </div>
                <div className="rounded-lg bg-white border border-indigo-200 px-3 py-2 font-mono text-xs font-bold text-slate-900">
                  {latestCreatedPair.pair_token}
                </div>
                <div className="text-[11px] text-slate-700 font-semibold">
                  Paste in VS Code / Cursor (<code className="font-mono">VibeArmor: Pair Editor Folder</code>) OR run in any local repo:
                </div>
                {(() => {
                  const bridgeCmd = `python3 vibearmor_bridge.py --server ${originUrl} --token ${latestCreatedPair.pair_token} --dir . --watch`;
                  return (
                    <div className="rounded-lg bg-slate-900 p-2.5 text-[11px] font-mono text-slate-100 flex items-center justify-between gap-2">
                      <span className="truncate">{bridgeCmd}</span>
                      <button
                        type="button"
                        onClick={() => copyCmd(bridgeCmd)}
                        className="shrink-0 rounded bg-indigo-600 px-2 py-1 text-[10px] font-bold text-white"
                      >
                        {copiedCmd === bridgeCmd ? "Copied" : "Copy"}
                      </button>
                    </div>
                  );
                })()}
              </div>
            )}
          </div>

          {/* Right: Live Connected Editor Sessions & Two-Way Outbox */}
          <div className="wiz-card rounded-2xl p-6 lg:col-span-7 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div>
                <h3 className="text-sm font-extrabold text-slate-900">
                  Connected Editor Sessions &amp; Two-Way Surgical Outbox ({pairedSessions.length})
                </h3>
                <p className="text-xs text-slate-500">
                  When you approve fixes in Step 3, VibeArmor queues ONLY the patched files here so your paired editor writes them locally
                </p>
              </div>
              <button
                type="button"
                onClick={loadStatus}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-100"
              >
                <RefreshCw className="h-3.5 w-3.5" /> Refresh
              </button>
            </div>

            {pairedSessions.length === 0 ? (
              <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50/70 p-8 text-center space-y-2">
                <FolderSync className="h-8 w-8 text-indigo-500 mx-auto" />
                <div className="text-xs font-bold text-slate-800">No Paired Editor Session Yet</div>
                <p className="text-xs text-slate-500 max-w-md mx-auto">
                  Click <strong>&ldquo;Pair Selected Workspace&rdquo;</strong> on the left to connect a workspace (such as{" "}
                  <code className="font-mono">suhail-m01/Knot</code>) and watch live two-way sync in action.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {pairedSessions.map((sess) => (
                  <div
                    key={sess.pair_token}
                    className="rounded-xl border border-slate-200 bg-slate-50/60 p-4 space-y-3"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="rounded-md bg-indigo-600 px-2 py-0.5 font-mono text-[10px] font-bold text-white">
                          {sess.editor}
                        </span>
                        <span className="text-xs font-extrabold text-slate-900">{sess.workspace_name}</span>
                        <span className="font-mono text-[10.5px] text-slate-400">({sess.pair_token})</span>
                      </div>
                      <span
                        className={`rounded-full px-2.5 py-0.5 text-[11px] font-bold ${
                          sess.ready_to_push
                            ? "bg-emerald-100 text-emerald-800"
                            : "bg-rose-100 text-rose-800"
                        }`}
                      >
                        {sess.ready_to_push
                          ? `✓ Ready to Push & Deploy (${sess.security_score}/100)`
                          : `🛑 Push Blocked (${sess.open_threats} Open Threats)`}
                      </span>
                    </div>

                    <div className="text-xs text-slate-600 flex flex-wrap items-center justify-between gap-2">
                      <span>{sess.last_event}</span>
                      <span className="font-mono text-[11px] text-slate-400">
                        Synced back: {sess.synced_fixes_total} file(s)
                      </span>
                    </div>

                    {sess.pending_fixes_count > 0 && (
                      <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 flex flex-wrap items-center justify-between gap-2">
                        <div className="text-xs text-amber-950">
                          <strong>{sess.pending_fixes_count} approved surgical file(s)</strong> queued for editor write-back:{" "}
                          <code className="font-mono text-[11px]">{sess.pending_file_names.join(", ")}</code>
                        </div>
                        <button
                          type="button"
                          disabled={syncAckBusy === sess.pair_token}
                          onClick={() => handleSimulateEditorPullAck(sess)}
                          className="rounded-lg bg-amber-600 px-3 py-1.5 text-[11px] font-bold text-white hover:bg-amber-700"
                        >
                          {syncAckBusy === sess.pair_token ? "Writing..." : "Confirm Editor Sync Pull ✓"}
                        </button>
                      </div>
                    )}

                    {sess.project_id && (
                      <div className="flex flex-wrap items-center gap-2 pt-1">
                        <button
                          type="button"
                          onClick={() => onSelectProjectStep(sess.project_id!, "step1_graph")}
                          className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-bold text-slate-700 hover:bg-slate-100"
                        >
                          1. Open Code Structure Graph
                        </button>
                        <button
                          type="button"
                          onClick={() => onSelectProjectStep(sess.project_id!, "step3_diff")}
                          className="inline-flex items-center gap-1 rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-indigo-700"
                        >
                          3. Review Vulnerable vs. Correct &amp; Adopt <ArrowRight className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ==================== TAB 2: DESKTOP CODE EDITOR EXTENSION (.VSIX) ==================== */}
      {activeTab === "ide_vsix" && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* Left: Multi-Editor Install Commands + Hard Git Hook */}
          <div className="wiz-card rounded-2xl p-6 lg:col-span-5 space-y-4">
            <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
              <Terminal className="h-5 w-5 text-indigo-600" />
              <div>
                <h3 className="text-sm font-extrabold text-slate-900">
                  Install <code className="font-mono text-xs">vibearmor-guard-3.6.0.vsix</code> (v3.6)
                </h3>
                <p className="text-xs text-slate-500">
                  Works 100% Standalone Offline + Auto Git Init &amp; <code className="font-mono">.gitignore</code> Shield · Quick-Fix Lightbulb (<code className="font-mono">Ctrl+.</code>)
                </p>
              </div>
            </div>

            <div className="rounded-xl border-2 border-emerald-300 bg-emerald-50/70 p-3.5 space-y-2">
              <div className="text-xs font-extrabold text-emerald-950">
                Recommended · 1-Paste Self-Contained Installer (Zero ENOENT / Zero TLS Errors!)
              </div>
              <p className="text-[11px] text-emerald-900 leading-relaxed">
                Writes <code className="font-mono">vibearmor-guard-3.6.0.vsix</code> directly into your{" "}
                <code className="font-mono">Downloads</code> folder, replaces any older 3.0.0 build, and auto-installs into VS Code, Cursor &amp; Windsurf:
              </p>
              <button
                type="button"
                onClick={() => handleDeliverExtension("vsix")}
                className="w-full inline-flex items-center justify-center gap-1.5 rounded-xl bg-slate-900 px-3.5 py-2.5 text-xs font-extrabold text-white hover:bg-indigo-700 cursor-pointer"
              >
                <Download className="h-3.5 w-3.5 text-emerald-400" />
                Open 1-Paste Windows PowerShell &amp; macOS Installer
              </button>
            </div>

            <div className="space-y-2.5">
              {(extStatus?.supported_editors || []).map((ed) => (
                <div
                  key={ed.id}
                  className="rounded-xl border border-slate-200 bg-slate-50/70 p-3 space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-800">{ed.name}</span>
                    <button
                      type="button"
                      onClick={() => copyCmd(ed.install_cmd)}
                      className="inline-flex items-center gap-1 text-[11px] font-semibold text-indigo-600 hover:underline"
                    >
                      <Copy className="h-3 w-3" />
                      {copiedCmd === ed.install_cmd ? "Copied!" : "Copy"}
                    </button>
                  </div>
                  <div className="rounded-lg bg-slate-900 px-2.5 py-1.5 font-mono text-[11px] text-slate-100 overflow-x-auto">
                    {ed.install_cmd}
                  </div>
                </div>
              ))}
            </div>

            <div className="rounded-xl border border-emerald-200 bg-emerald-50/70 p-3.5 text-xs text-emerald-950 space-y-1">
              <div className="font-bold flex items-center gap-1.5">
                <Lock className="h-3.5 w-3.5 text-emerald-700" /> Hard Pre-Push Gate Behavior
              </div>
              <p className="text-[11px] text-emerald-900 leading-relaxed">
                Intercepts <code className="font-mono">git push</code> from both terminal and editor Git buttons. Blocks unsafe pushes when threats exist, then unlocks <strong>1-Click Safe Push to GitHub</strong> (auto-excluding raw <code className="font-mono">.env</code> files) once resolved.
              </p>
            </div>
          </div>

          {/* Right: Live Interactive In-Editor Sidebar Panel Simulator */}
          <div className="wiz-card rounded-2xl p-6 lg:col-span-7 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-3">
              <div className="flex items-center gap-2">
                <Laptop className="h-5 w-5 text-indigo-600" />
                <div>
                  <h3 className="text-sm font-extrabold text-slate-900">
                    Interactive In-Editor Sidebar Panel (Live Connected to Workspace)
                  </h3>
                  <p className="text-xs text-slate-500">
                    Test the exact VS Code / Cursor sidebar experience against any workspace right here
                  </p>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div>
                <label className="block text-[11px] font-bold text-slate-700 mb-1">Editor</label>
                <select
                  value={simEditor}
                  onChange={(e) => setSimEditor(e.target.value)}
                  className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-800"
                >
                  <option value="Cursor AI IDE">Cursor AI IDE</option>
                  <option value="Visual Studio Code">Visual Studio Code</option>
                  <option value="Windsurf Editor">Windsurf Editor</option>
                </select>
              </div>
              <div>
                <label className="block text-[11px] font-bold text-slate-700 mb-1">Active Project Folder</label>
                <select
                  value={simProjectId}
                  onChange={(e) => {
                    setSimProjectId(e.target.value);
                    setVerifyResult(null);
                    setPushBannerMsg(null);
                  }}
                  className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-800"
                >
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.security_score}/100)
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-[11px] font-bold text-slate-700 mb-1">Target Branch</label>
                <div className="relative">
                  <GitBranch className="h-3.5 w-3.5 text-slate-400 absolute left-2.5 top-2.5" />
                  <input
                    type="text"
                    value={simBranch}
                    onChange={(e) => setSimBranch(e.target.value)}
                    className="w-full rounded-xl border border-slate-300 bg-white pl-8 pr-3 py-2 font-mono text-xs text-slate-800"
                  />
                </div>
              </div>
            </div>

            <button
              type="button"
              disabled={verifying}
              onClick={() => runInEditorVerification()}
              className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-slate-900 px-4 py-2.5 text-xs font-bold text-white hover:bg-indigo-600 disabled:opacity-50 transition"
            >
              {verifying ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {verifying
                ? "Running In-Editor 5-Point Security Gate..."
                : `Run In-Editor Push & Deploy Gate on '${projects.find((p) => p.id === simProjectId)?.name || simProjectId}'`}
            </button>

            {pushBannerMsg && (
              <div className="rounded-xl border border-emerald-300 bg-emerald-50 px-4 py-3 text-xs font-bold text-emerald-900">
                {pushBannerMsg}
              </div>
            )}

            {verifyResult && (
              <div className="rounded-2xl border-2 border-slate-200 bg-[#F8FAFC] p-4 space-y-3.5">
                {/* Editor Sidebar Header Bar */}
                <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-bold text-slate-500 border-b border-slate-200 pb-2">
                  <span>{simEditor.toUpperCase()} · VIBEARMOR SIDEBAR PANEL</span>
                  <button
                    type="button"
                    onClick={() => onSelectProjectStep(simProjectId, "step1_graph")}
                    className="inline-flex items-center gap-1 text-indigo-600 hover:underline"
                  >
                    Open {verifyResult.node_count ?? ""} Node Graph <ArrowUpRight className="h-3.5 w-3.5" />
                  </button>
                </div>

                {/* Hard Push Verdict Banner */}
                <div
                  className={`rounded-xl border p-3.5 flex flex-wrap items-center justify-between gap-2 ${
                    verifyResult.ready_to_push
                      ? "border-emerald-300 bg-emerald-50 text-emerald-950"
                      : "border-rose-300 bg-rose-50 text-rose-950"
                  }`}
                >
                  <div className="flex items-center gap-2 font-extrabold text-xs">
                    {verifyResult.ready_to_push ? (
                      <ShieldCheck className="h-5 w-5 text-emerald-600" />
                    ) : (
                      <ShieldAlert className="h-5 w-5 text-rose-600" />
                    )}
                    {verifyResult.ready_to_push
                      ? `✓ READY TO PUSH & DEPLOY (Score ${verifyResult.security_score}/100)`
                      : `🛑 HARD GATE: GIT PUSH & DEPLOY BLOCKED (${verifyResult.blocking_count} Open Threats)`}
                  </div>
                  <span className="font-mono text-[11px] font-bold">
                    {verifyResult.scan_latency_ms} ms
                  </span>
                </div>

                {/* 5-Point Checklist */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {Object.entries(verifyResult.checks).map(([k, ch]) => (
                    <div
                      key={k}
                      className="flex items-center justify-between rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs"
                    >
                      <span className="font-medium text-slate-700 truncate pr-2">{ch.label}</span>
                      {ch.passed ? (
                        <span className="shrink-0 font-bold text-emerald-700">PASS</span>
                      ) : (
                        <span className="shrink-0 font-bold text-rose-700">{ch.count} open</span>
                      )}
                    </div>
                  ))}
                </div>

                {/* Surgical Diff Cards inside Editor Panel */}
                {(verifyResult.proposals || []).filter((p) => p.adoptable).length > 0 && (
                  <div className="space-y-2">
                    <div className="text-xs font-extrabold text-slate-900">
                      Surgical Fixes Ready ({verifyResult.proposals.filter((p) => p.adoptable).length}) — Unrelated Code 100% Untouched:
                    </div>
                    <div className="max-h-64 overflow-y-auto space-y-2 pr-1">
                      {verifyResult.proposals
                        .filter((p) => p.adoptable)
                        .map((prop) => {
                          const checked = !uncheckedSimIds[prop.finding_id];
                          return (
                            <div
                              key={prop.finding_id}
                              className="rounded-xl border border-slate-200 bg-white p-3 space-y-1.5"
                            >
                              <label className="flex items-start gap-2 cursor-pointer">
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  onChange={() =>
                                    setUncheckedSimIds((prev) => ({
                                      ...prev,
                                      [prop.finding_id]: !prev[prop.finding_id],
                                    }))
                                  }
                                  className="mt-0.5 rounded border-slate-300 text-indigo-600"
                                />
                                <div className="min-w-0 flex-1">
                                  <div className="text-xs font-bold text-slate-900">
                                    [{prop.rule_id}] {prop.title}
                                  </div>
                                  <div className="font-mono text-[10.5px] text-slate-500">
                                    {prop.file_path}:{prop.line_start} ·{" "}
                                    {prop.precision?.preservation_pct ?? 100}% non-vulnerable lines preserved
                                  </div>
                                </div>
                              </label>
                              {prop.precision && (
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 pt-1">
                                  <pre className="rounded bg-rose-50 border border-rose-200 p-2 font-mono text-[10px] text-rose-900 overflow-x-auto">
                                    {prop.precision.vulnerable_excerpt}
                                  </pre>
                                  <pre className="rounded bg-emerald-50 border border-emerald-200 p-2 font-mono text-[10px] text-emerald-900 overflow-x-auto">
                                    {prop.precision.corrected_excerpt}
                                  </pre>
                                </div>
                              )}
                            </div>
                          );
                        })}
                    </div>

                    <button
                      type="button"
                      disabled={adoptingInSim}
                      onClick={handleAdoptInsideEditorSim}
                      className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-xs font-bold text-white hover:bg-indigo-700 disabled:opacity-50"
                    >
                      {adoptingInSim ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <CheckCircle2 className="h-4 w-4" />
                      )}
                      {adoptingInSim
                        ? "Applying Surgical Fixes & Verifying 3 Gates..."
                        : "Adopt Checked Surgical Fixes Directly in Editor"}
                    </button>
                  </div>
                )}

                {/* 1-Click Safe Push Button */}
                <button
                  type="button"
                  onClick={() => {
                    if (verifyResult.ready_to_push) {
                      onSelectProjectStep(simProjectId, "step4_deliver");
                    } else {
                      setPushBannerMsg(
                        `🛑 Push Hard-Blocked: Adopt the surgical fixes above first before pushing '${verifyResult.workspace_name}' to GitHub!`
                      );
                    }
                  }}
                  className={`w-full inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-xs font-extrabold text-white transition ${
                    verifyResult.ready_to_push
                      ? "bg-emerald-600 hover:bg-emerald-700"
                      : "bg-slate-400 hover:bg-slate-500"
                  }`}
                >
                  <Rocket className="h-4 w-4" />
                  {verifyResult.ready_to_push
                    ? "🚀 1-Click Safe Push to GitHub / Download Ready .ZIP →"
                    : "🔒 Git Push Locked Until Threats Are Fixed"}
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ==================== TAB 3: CHROME / EDGE BROWSER EXTENSION ==================== */}
      {activeTab === "browser_ext" && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* Left: Install Guide + Covered Platforms */}
          <div className="wiz-card rounded-2xl p-6 lg:col-span-5 space-y-4">
            <div className="flex items-center gap-2.5 border-b border-slate-100 pb-3">
              <Chrome className="h-5 w-5 text-indigo-600" />
              <div>
                <h3 className="text-sm font-extrabold text-slate-900">
                  Browser Extension (Chrome · Edge · Brave · MV3)
                </h3>
                <p className="text-xs text-slate-500">
                  Overlays GitHub PRs/Commits, Vercel, Netlify, Render, Railway, Lovable &amp; Bolt.new
                </p>
              </div>
            </div>

            <ol className="space-y-2.5 text-xs text-slate-700 list-decimal list-inside">
              <li>
                Click <strong>Browser Guard (.zip)</strong> above to download{" "}
                <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px]">
                  vibearmor-browser-guard-3.0.0.zip
                </code>{" "}
                and extract it.
              </li>
              <li>
                Open <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px]">chrome://extensions</code>{" "}
                (or <code className="font-mono text-[11px]">edge://extensions</code>) and toggle{" "}
                <strong>Developer mode</strong> ON.
              </li>
              <li>
                Click <strong>Load unpacked</strong> and select the extracted{" "}
                <code className="font-mono text-[11px]">vibearmor-browser-guard</code> folder.
              </li>
              <li>
                Visit any <strong>GitHub repository / PR</strong> or <strong>Vercel / Netlify / Render</strong> dashboard — unsafe{" "}
                <em>Merge PR</em>, <em>Commit changes</em>, and <em>Deploy</em> clicks are automatically intercepted until threats are resolved!
              </li>
            </ol>

            <button
              type="button"
              disabled={downloadingKind !== null}
              onClick={() => handleDeliverExtension("browser_zip")}
              className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-xs font-bold text-white hover:bg-indigo-700 disabled:opacity-60 transition cursor-pointer"
            >
              {downloadingKind === "browser_zip" ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Download className="h-4 w-4" />
              )}{" "}
              Download vibearmor-browser-guard-3.0.0.zip
            </button>
          </div>

          {/* Right: Live Browser Guard & Deploy Interceptor Simulator */}
          <div className="wiz-card rounded-2xl p-6 lg:col-span-7 space-y-4">
            <div className="border-b border-slate-100 pb-3">
              <h3 className="text-sm font-extrabold text-slate-900">
                Test Live Browser Extension Gate on Any GitHub Repo / Cloud Dashboard
              </h3>
              <p className="text-xs text-slate-500">
                Runs the exact <code className="font-mono">/api/extension/browser/check-repo</code> check used by the Manifest V3 service worker
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="sm:col-span-2">
                <label className="block text-[11px] font-bold text-slate-700 mb-1">
                  Active Browser Tab Repository URL
                </label>
                <input
                  type="text"
                  value={browserRepoUrl}
                  onChange={(e) => setBrowserRepoUrl(e.target.value)}
                  placeholder="https://github.com/suhail-m01/Knot"
                  className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2 font-mono text-xs text-slate-900"
                />
              </div>
              <div>
                <label className="block text-[11px] font-bold text-slate-700 mb-1">Simulated Host</label>
                <select
                  value={browserPageHost}
                  onChange={(e) => setBrowserPageHost(e.target.value)}
                  className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-800"
                >
                  <option value="github.com">github.com (PR / Commit)</option>
                  <option value="vercel.com">vercel.com (Deploy)</option>
                  <option value="dashboard.render.com">render.com (Deploy)</option>
                  <option value="app.netlify.com">netlify.com (Deploy)</option>
                </select>
              </div>
            </div>

            <button
              type="button"
              disabled={browserBusy || !browserRepoUrl.trim()}
              onClick={handleBrowserGateCheck}
              className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-slate-900 px-4 py-2.5 text-xs font-bold text-white hover:bg-indigo-600 disabled:opacity-50 transition"
            >
              {browserBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Globe className="h-4 w-4" />}
              {browserBusy ? "Auditing Repository for Browser Gate..." : "Verify Browser Push & Deploy Gate"}
            </button>

            {browserResult && (
              <div className="rounded-2xl border-2 border-slate-200 bg-[#F8FAFC] p-4 space-y-3.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-xs font-bold text-slate-800">
                    {browserPageHost} · {browserResult.repo_slug}
                  </span>
                  <span
                    className={`rounded-full px-3 py-1 text-xs font-extrabold ${
                      browserResult.ready_to_push
                        ? "bg-emerald-100 text-emerald-800"
                        : "bg-rose-100 text-rose-800"
                    }`}
                  >
                    {browserResult.ready_to_push
                      ? `✓ VibeArmor Ready (${browserResult.security_score}/100)`
                      : `🛑 VibeArmor Blocked (${browserResult.open_threats} Open Threats · ${browserResult.security_score}/100)`}
                  </span>
                </div>

                {/* Test Clicking GitHub Merge / Vercel Deploy Button! */}
                <div className="rounded-xl border border-slate-200 bg-white p-3 flex flex-wrap items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-slate-700">
                    Simulate clicking button on <strong>{browserPageHost}</strong>:
                  </span>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() =>
                        setInterceptedAction(
                          browserResult.ready_to_push ? "ALLOWED_MERGE" : "BLOCKED_MERGE"
                        )
                      }
                      className="rounded-lg bg-emerald-700 px-3 py-1.5 text-xs font-bold text-white hover:bg-emerald-800"
                    >
                      Merge pull request
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        setInterceptedAction(
                          browserResult.ready_to_push ? "ALLOWED_DEPLOY" : "BLOCKED_DEPLOY"
                        )
                      }
                      className="rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-bold text-white hover:bg-slate-800"
                    >
                      Deploy to Production
                    </button>
                  </div>
                </div>

                {interceptedAction?.startsWith("BLOCKED") && (
                  <div className="rounded-xl border-2 border-rose-300 bg-rose-50 p-4 space-y-2.5">
                    <div className="text-xs font-extrabold text-rose-900">
                      🛑 HARD-BLOCK MODAL TRIGGERED BY CONTENT SCRIPT: Unsafe{" "}
                      {interceptedAction === "BLOCKED_MERGE" ? "GitHub Merge" : "Cloud Deployment"} Prevented!
                    </div>
                    <div className="space-y-1">
                      {browserResult.top_findings.slice(0, 4).map((tf, i) => (
                        <div key={i} className="text-[11px] font-mono text-rose-800">
                          ✖ [{tf.rule_id}] {tf.file_path}:{tf.line_start} — {tf.title}
                        </div>
                      ))}
                    </div>
                    {browserResult.project_id && (
                      <button
                        type="button"
                        onClick={() => onSelectProjectStep(browserResult.project_id!, "step3_diff")}
                        className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-2 text-xs font-bold text-white hover:bg-indigo-700"
                      >
                        Fix Surgically in VibeArmor Studio &rarr;
                      </button>
                    )}
                  </div>
                )}

                {interceptedAction?.startsWith("ALLOWED") && (
                  <div className="rounded-xl border border-emerald-300 bg-emerald-50 p-3 text-xs font-bold text-emerald-900">
                    ✓ VibeArmor Verified ({browserResult.security_score}/100 · 0 Open Threats) — Merge / Production Deploy Permitted!
                  </div>
                )}

                {browserResult.project_id && (
                  <div className="flex flex-wrap gap-2 pt-1">
                    <button
                      type="button"
                      onClick={() => onSelectProjectStep(browserResult.project_id!, "step1_graph")}
                      className="rounded-xl border border-slate-300 bg-white px-3.5 py-2 text-xs font-bold text-slate-700 hover:bg-slate-50"
                    >
                      1. View Repo Structure Graph
                    </button>
                    <button
                      type="button"
                      onClick={() => onSelectProjectStep(browserResult.project_id!, "step3_diff")}
                      className="inline-flex items-center gap-1.5 rounded-xl bg-indigo-600 px-3.5 py-2 text-xs font-bold text-white hover:bg-indigo-700"
                    >
                      3. Review Vulnerable vs. Correct Diff <ArrowRight className="h-3.5 w-3.5" />
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      <ArtifactDeliveryModal
        artifact={activeArtifact}
        onClose={() => setActiveArtifact(null)}
      />
    </div>
  );
};
