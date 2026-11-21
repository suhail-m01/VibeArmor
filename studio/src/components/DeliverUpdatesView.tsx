import React, { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Download,
  ExternalLink,
  Eye,
  EyeOff,
  FileCheck2,
  FolderArchive,
  GitBranch,
  GitPullRequest,
  Loader2,
  Lock,
  RotateCcw,
  ShieldCheck,
  Terminal,
  Trash2,
  XCircle,
} from "lucide-react";
import { GitHubPushResult, ProjectDetailPayload } from "../types";
import {
  ArtifactDeliveryModal,
  ArtifactKind,
  copyTextSafe,
  stageAndFetchArtifact,
  StagedArtifactInfo,
} from "../utils/artifactDelivery";

const CLASSIC_TOKEN_SETUP_URL =
  "https://github.com/settings/tokens/new?description=VibeArmor+Surgical+Security+Sync&scopes=repo";
const FINE_GRAINED_SETTINGS_URL = "https://github.com/settings/personal-access-tokens";

interface PermissionCheckRow {
  id: string;
  label: string;
  status: "PASS" | "FAIL" | "WARN" | "NOT_RUN";
  detail: string;
}

interface SavedGitHubConfig {
  configured: boolean;
  repo_url: string;
  default_mode: string;
  base_branch: string;
  authenticated_user: string;
  token_kind: string;
  token_masked: string;
  write_verified: boolean;
}

interface Props {
  detail: ProjectDetailPayload;
  onResetWorkspace: () => void;
  onGoToDiffStep: () => void;
}

export const DeliverUpdatesView: React.FC<Props> = ({
  detail,
  onResetWorkspace,
  onGoToDiffStep,
}) => {
  const { project, report, files, before_files } = detail;

  const [repoUrl, setRepoUrl] = useState<string>(project.github_repo_url || "");
  const [ghToken, setGhToken] = useState<string>("");
  const [savedCfg, setSavedCfg] = useState<SavedGitHubConfig | null>(null);
  const [showToken, setShowToken] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [inlineHelperUrl, setInlineHelperUrl] = useState<string | null>(null);
  const [pushMode, setPushMode] = useState<"pull_request" | "direct_commit">("pull_request");
  const [baseBranch, setBaseBranch] = useState<string>(project.github_branch || "main");
  const [pushBusy, setPushBusy] = useState<boolean>(false);
  const [pushError, setPushError] = useState<string | null>(null);
  const [pushResult, setPushResult] = useState<GitHubPushResult | null>(null);
  const [verifyBusy, setVerifyBusy] = useState<boolean>(false);
  const [verifyInfo, setVerifyInfo] = useState<{
    ok: boolean;
    status: string;
    message: string;
    authenticated_user?: string;
    token_kind?: string;
    permission_checks?: PermissionCheckRow[];
  } | null>(null);

  const [offlinePushCmds, setOfflinePushCmds] = useState<{
    powershell_cmd: string;
    bash_cmd: string;
    compressed_patch_chars: string;
  } | null>(null);
  const [offlineBusy, setOfflineBusy] = useState<boolean>(false);

  const [activeArtifact, setActiveArtifact] = useState<StagedArtifactInfo | null>(null);
  const [busyArtifact, setBusyArtifact] = useState<ArtifactKind | null>(null);

  const { changedFiles, untouchedFiles } = useMemo(() => {
    const allKeys = Array.from(new Set([...Object.keys(before_files), ...Object.keys(files)])).sort();
    const changed: string[] = [];
    const untouched: string[] = [];
    for (const k of allKeys) {
      if ((before_files[k] ?? "") !== (files[k] ?? "")) {
        changed.push(k);
      } else {
        untouched.push(k);
      }
    }
    return { changedFiles: changed, untouchedFiles: untouched };
  }, [before_files, files]);

  // Load persisted GitHub configuration
  useEffect(() => {
    fetch("/api/github/config")
      .then((r) => (r.ok ? r.json() : null))
      .then((cfg: SavedGitHubConfig | null) => {
        if (cfg && cfg.configured) {
          setSavedCfg(cfg);
          if (!project.github_repo_url && cfg.repo_url) {
            setRepoUrl(cfg.repo_url);
          }
        }
      })
      .catch(() => {});
  }, [project.github_repo_url]);

  // Sync repo URL, branch & generate 1-Paste Offline Git Push commands whenever active workspace or mode changes
  useEffect(() => {
    const nextRepo = project.github_repo_url || savedCfg?.repo_url || "";
    setRepoUrl(nextRepo);
    setBaseBranch(project.github_branch || "main");
    setPushError(null);
    setPushResult(null);
    setVerifyInfo(null);
  }, [project.id, project.github_repo_url, project.github_branch]);

  useEffect(() => {
    if (changedFiles.length === 0 || !repoUrl.trim().includes("github.com/")) {
      setOfflinePushCmds(null);
      return;
    }
    setOfflineBusy(true);
    fetch(`/api/projects/${encodeURIComponent(project.id)}/offline-git-push`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        repo_url: repoUrl.trim(),
        mode: pushMode,
        base_branch: baseBranch.trim() || "main",
      }),
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d && d.powershell_cmd) setOfflinePushCmds(d);
      })
      .catch(() => {})
      .finally(() => setOfflineBusy(false));
  }, [project.id, changedFiles.length, repoUrl, pushMode, baseBranch]);

  const trimmedToken = ghToken.trim();
  const hasUsableSavedToken = Boolean(!trimmedToken && savedCfg?.configured && savedCfg?.write_verified);

  const openActionable =
    report.mode === "auto_heal"
      ? report.summary.actionable_after
      : report.summary.actionable_before;

  async function copyItem(key: string, text: string) {
    await copyTextSafe(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2400);
  }

  async function openOrCopyExternalUrl(key: string, targetUrl: string) {
    await copyItem(key, targetUrl);
    setInlineHelperUrl(targetUrl);
    try {
      window.open(targetUrl, "_blank", "noopener,noreferrer");
    } catch {
      // Sandboxed iframe blocked popup — URL is already copied & displayed inline!
    }
  }

  async function handleClearSavedConfig() {
    await fetch("/api/github/config", { method: "DELETE" });
    setSavedCfg(null);
    setVerifyInfo(null);
  }

  async function handleDeliverArtifact(kind: ArtifactKind) {
    setBusyArtifact(kind);
    try {
      const staged = await stageAndFetchArtifact({
        artifact_kind: kind,
        project_id: project.id,
        repo_url: repoUrl.trim() || project.github_repo_url || "",
        mode: pushMode,
        base_branch: baseBranch.trim() || undefined,
      });
      setActiveArtifact(staged);
    } catch (err: unknown) {
      setPushError(err instanceof Error ? err.message : "Failed to export artifact.");
    } finally {
      setBusyArtifact(null);
    }
  }

  async function handleVerifyToken() {
    setPushError(null);
    setVerifyInfo(null);
    const tokenToTest = trimmedToken || (savedCfg?.configured ? "__SAVED__" : "");
    if (!repoUrl.trim() || !tokenToTest) {
      setPushError("Enter both the Target GitHub Repository URL and a Personal Access Token.");
      return;
    }
    setVerifyBusy(true);
    try {
      const res = await fetch("/api/github/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_url: repoUrl.trim(),
          github_token: tokenToTest,
          save_if_valid: true,
          default_mode: pushMode,
          base_branch: baseBranch.trim() || "main",
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.detail || "Token verification failed.");
      }
      setVerifyInfo(data);
      if (data.saved_config) {
        setSavedCfg(data.saved_config);
      }
    } catch (err: unknown) {
      setPushError(err instanceof Error ? err.message : "Failed to verify GitHub token.");
    } finally {
      setVerifyBusy(false);
    }
  }

  async function handlePushGitHub(e: React.FormEvent) {
    e.preventDefault();
    setPushError(null);
    setPushResult(null);
    const tokenToUse = trimmedToken || (savedCfg?.configured ? "__SAVED__" : "");
    if (!tokenToUse) {
      setPushError("Enter a write-capable GitHub Token above, or use the 1-Paste Offline Git Push below!");
      return;
    }
    setPushBusy(true);
    try {
      const res = await fetch(`/api/projects/${project.id}/push-github`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_url: repoUrl.trim(),
          github_token: tokenToUse,
          mode: pushMode,
          base_branch: baseBranch.trim() || null,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.detail || "GitHub repository update failed.");
      }
      setPushResult(data);
    } catch (err: unknown) {
      setPushError(err instanceof Error ? err.message : "Failed to push to GitHub.");
    } finally {
      setPushBusy(false);
    }
  }

  // Block pushing if user explicitly verified the current token and it came back read-only (prevents duplicate yellow+red error boxes!)
  const tokenExplicitlyReadOnly = verifyInfo !== null && !verifyInfo.ok;

  return (
    <div className="space-y-6">
      {/* Top Readiness Summary Banner */}
      <div className="wiz-card rounded-2xl p-6 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="rounded-full bg-indigo-50 px-2.5 py-0.5 font-mono text-[11px] font-bold text-indigo-700 border border-indigo-200">
              STEP 4 OF 4 · DELIVER VERIFIED CODE
            </span>
            <span className="rounded-full bg-slate-900 px-3 py-0.5 font-mono text-[11px] font-bold text-white">
              Workspace: {project.name}
            </span>
            {openActionable === 0 ? (
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-100 px-3 py-0.5 text-xs font-bold text-emerald-800">
                <ShieldCheck className="h-3.5 w-3.5" /> Ready to Push &amp; Deploy ({project.security_score}/100)
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-3 py-0.5 text-xs font-bold text-amber-900">
                <AlertTriangle className="h-3.5 w-3.5" /> {openActionable} Open Flaw(s) — Review &amp; Adopt Fixes First
              </span>
            )}
          </div>
          <h2 className="mt-2 text-lg font-extrabold text-slate-900">
            Update in GitHub Repository or Export Verified Project Bundle
          </h2>
          <p className="mt-1 text-xs text-slate-600 max-w-3xl">
            <strong>{changedFiles.length} surgical file(s)</strong> verified across all 3 safety gates;{" "}
            <strong>{untouchedFiles.length} clean file(s)</strong> preserved 100% untouched.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          {changedFiles.length === 0 && (
            <button
              type="button"
              onClick={onGoToDiffStep}
              className="rounded-xl bg-indigo-600 px-4 py-2.5 text-xs font-bold text-white hover:bg-indigo-700 cursor-pointer"
            >
              &larr; Review &amp; Adopt Surgical Fixes First
            </button>
          )}
          <button
            type="button"
            onClick={onResetWorkspace}
            className="inline-flex items-center gap-1.5 rounded-xl border border-slate-300 bg-white px-3.5 py-2.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 cursor-pointer"
          >
            <RotateCcw className="h-3.5 w-3.5" /> Reset to Original Baseline
          </button>
        </div>
      </div>

      {/* Two Primary Delivery Cards */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Option A: Update Directly in GitHub Repository */}
        <form onSubmit={handlePushGitHub} className="wiz-card rounded-2xl p-6 lg:col-span-7 space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 pb-3.5">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-600 text-white shadow-sm">
                <GitPullRequest className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900">
                  Option A · Update Directly in GitHub Repository
                </h3>
                <p className="text-xs text-slate-500">
                  Method 1: 1-Paste Local Git Push (No Token!) &middot; Method 2: Write-Verified GitHub PAT
                </p>
              </div>
            </div>

            {savedCfg?.configured && (
              <div className="inline-flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-1.5 text-[11px] text-emerald-900">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />
                <span>
                  Saved: <strong>@{savedCfg.authenticated_user}</strong> (<code>{savedCfg.token_masked}</code>)
                </span>
                <button
                  type="button"
                  onClick={handleClearSavedConfig}
                  className="text-slate-400 hover:text-rose-600 cursor-pointer"
                  title="Forget saved token"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            )}
          </div>

          {/* Target Repo + Strategy + Branch */}
          <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-12">
            <div className="sm:col-span-12">
              <label className="block text-xs font-bold text-slate-700 mb-1">
                Target GitHub Repository URL
              </label>
              <input
                type="text"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/owner/your-repo"
                className="w-full rounded-xl border border-slate-300 bg-white px-3.5 py-2.5 font-mono text-xs text-slate-900 focus:border-indigo-600 focus:outline-none"
              />
            </div>

            <div className="sm:col-span-8">
              <label className="block text-xs font-bold text-slate-700 mb-1">
                Update Strategy
              </label>
              <select
                value={pushMode}
                onChange={(e) => setPushMode(e.target.value as "pull_request" | "direct_commit")}
                className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-xs font-semibold text-slate-800 focus:border-indigo-600 focus:outline-none"
              >
                <option value="pull_request">Open Safe Pull Request (PR)</option>
                <option value="direct_commit">Commit Directly to Target Branch</option>
              </select>
            </div>

            <div className="sm:col-span-4">
              <label className="block text-xs font-bold text-slate-700 mb-1">
                Base Branch
              </label>
              <div className="relative">
                <GitBranch className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                <input
                  type="text"
                  value={baseBranch}
                  onChange={(e) => setBaseBranch(e.target.value)}
                  placeholder="main"
                  className="w-full rounded-xl border border-slate-300 bg-white pl-9 pr-3 py-2.5 font-mono text-xs text-slate-900 focus:border-indigo-600 focus:outline-none"
                />
              </div>
            </div>
          </div>

          {/* METHOD 1 (FASTEST & ZERO TOKEN): 1-Paste Self-Contained Offline Local Git Push */}
          {changedFiles.length > 0 && repoUrl.trim().includes("github.com/") && (
            <div className="rounded-2xl border-2 border-emerald-300 bg-emerald-50/70 p-4 space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs font-extrabold text-emerald-950 flex items-center gap-1.5">
                  <Terminal className="h-4 w-4 text-emerald-700" />
                  Method 1 (Instant · Zero Token!) — 1-Paste Self-Contained Local Git Push
                </div>
                <button
                  type="button"
                  disabled={busyArtifact !== null}
                  onClick={() => handleDeliverArtifact("github_push_script")}
                  className="inline-flex items-center gap-1 rounded-lg border border-emerald-300 bg-white px-2.5 py-1 text-[11px] font-bold text-emerald-900 hover:bg-emerald-100 cursor-pointer"
                >
                  <Download className="h-3 w-3" /> Inspect Full Push Script (.py)
                </button>
              </div>
              <p className="text-[11px] text-emerald-900 leading-relaxed">
                Embeds the compressed surgical diff (~{offlinePushCmds ? Math.max(1, Math.round(Number(offlinePushCmds.compressed_patch_chars) / 1024)) : 4} KB) directly in the command — <strong>zero network call to Arena</strong>, <strong>zero Personal Access Token needed</strong>, uses your PC&rsquo;s existing Git login, pushes branch &amp; opens your GitHub PR!
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <button
                  type="button"
                  disabled={!offlinePushCmds || offlineBusy}
                  onClick={() => offlinePushCmds && copyItem("offline-ps-git", offlinePushCmds.powershell_cmd)}
                  className="inline-flex items-center justify-center gap-1.5 rounded-xl bg-slate-900 px-3.5 py-2.5 text-xs font-extrabold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-50 cursor-pointer"
                >
                  <Copy className="h-3.5 w-3.5 text-emerald-400" />
                  {copiedKey === "offline-ps-git"
                    ? "Copied PowerShell Push ✓ (Paste in Terminal!)"
                    : "Copy 1-Paste Git Push (Windows PowerShell)"}
                </button>
                <button
                  type="button"
                  disabled={!offlinePushCmds || offlineBusy}
                  onClick={() => offlinePushCmds && copyItem("offline-sh-git", offlinePushCmds.bash_cmd)}
                  className="inline-flex items-center justify-center gap-1.5 rounded-xl border border-emerald-400 bg-white px-3.5 py-2.5 text-xs font-extrabold text-slate-900 hover:bg-emerald-100 disabled:opacity-50 cursor-pointer"
                >
                  <Copy className="h-3.5 w-3.5 text-emerald-700" />
                  {copiedKey === "offline-sh-git"
                    ? "Copied Bash Push ✓"
                    : "Copy 1-Paste Git Push (macOS / Linux / Git Bash)"}
                </button>
              </div>
            </div>
          )}

          {/* METHOD 2: Direct Browser Push via Write-Capable GitHub Personal Access Token */}
          <div className="rounded-2xl border border-slate-200 bg-slate-50/70 p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <label className="block text-xs font-extrabold text-slate-800">
                Method 2 · Push Directly from VibeArmor Server via GitHub Token
              </label>
              <div className="flex flex-wrap items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => openOrCopyExternalUrl("classic-url", CLASSIC_TOKEN_SETUP_URL)}
                  className="inline-flex items-center gap-1 rounded-lg border border-indigo-200 bg-indigo-50 px-2.5 py-1 text-[10.5px] font-bold text-indigo-700 hover:bg-indigo-100 cursor-pointer"
                >
                  {copiedKey === "classic-url" ? "Copied Classic URL ✓" : "1-Click Classic Token (`repo` Scope)"}{" "}
                  <ExternalLink className="h-3 w-3" />
                </button>
                <button
                  type="button"
                  onClick={() => openOrCopyExternalUrl("fg-url", FINE_GRAINED_SETTINGS_URL)}
                  className="inline-flex items-center gap-1 rounded-lg border border-slate-300 bg-white px-2.5 py-1 text-[10.5px] font-bold text-slate-700 hover:bg-slate-100 cursor-pointer"
                >
                  {copiedKey === "fg-url" ? "Copied Settings URL ✓" : "Edit Fine-Grained Token"}{" "}
                  <ExternalLink className="h-3 w-3" />
                </button>
              </div>
            </div>

            {inlineHelperUrl && (
              <div className="rounded-lg border border-indigo-200 bg-white px-3 py-2 text-[11px] text-indigo-950 space-y-1">
                <div className="font-bold">
                  Link copied! Paste in a new browser tab if preview iframe blocked the popup:
                </div>
                <div className="font-mono text-[10.5px] bg-indigo-50/70 rounded px-2 py-1 break-all">
                  {inlineHelperUrl}
                </div>
              </div>
            )}

            <div className="flex flex-col gap-2 sm:flex-row">
              <div className="relative flex-1">
                <input
                  type={showToken ? "text" : "password"}
                  value={ghToken}
                  onChange={(e) => {
                    setGhToken(e.target.value);
                    setVerifyInfo(null);
                    setPushError(null);
                  }}
                  placeholder={
                    hasUsableSavedToken
                      ? `Using saved verified token (${savedCfg?.token_masked}) — or paste a new token`
                      : "Paste ghp_... (Classic 'repo') or github_pat_... ('Contents: Read and write')"
                  }
                  className="w-full rounded-xl border border-slate-300 bg-white pl-3.5 pr-9 py-2.5 font-mono text-xs text-slate-900 focus:border-indigo-600 focus:outline-none"
                />
                <button
                  type="button"
                  onClick={() => setShowToken((v) => !v)}
                  className="absolute right-2.5 top-2.5 text-slate-400 hover:text-slate-700 cursor-pointer"
                >
                  {showToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              <button
                type="button"
                onClick={handleVerifyToken}
                disabled={verifyBusy || (!trimmedToken && !savedCfg?.configured) || !repoUrl.trim()}
                className="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-xl border border-indigo-300 bg-white px-3.5 py-2.5 text-xs font-bold text-indigo-800 hover:bg-indigo-50 disabled:opacity-50 cursor-pointer"
              >
                {verifyBusy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5 text-indigo-600" />}
                Verify &amp; Save Access
              </button>
            </div>

            {/* Structured 4-Row Permission Diagnostic Checklist (Replaces duplicate yellow/red text walls!) */}
            {verifyInfo?.permission_checks && (
              <div
                className={`rounded-xl border p-3.5 space-y-2 ${
                  verifyInfo.ok ? "border-emerald-300 bg-emerald-50/80" : "border-amber-300 bg-amber-50/90"
                }`}
              >
                <div className="flex items-center justify-between text-xs font-extrabold text-slate-900">
                  <span>
                    {verifyInfo.ok
                      ? "✅ GitHub Write Access Confirmed & Saved!"
                      : "⚠️ Token Verified Read-Only — Grant 'Contents: Read and write' or Use Method 1 Above"}
                  </span>
                </div>
                <div className="divide-y divide-slate-200/70 rounded-lg bg-white border border-slate-200 px-3 py-1">
                  {verifyInfo.permission_checks.map((chk) => (
                    <div key={chk.id} className="flex items-center justify-between gap-2 py-1.5 text-[11px]">
                      <span className="font-semibold text-slate-800 flex items-center gap-1.5">
                        {chk.status === "PASS" ? (
                          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 shrink-0" />
                        ) : chk.status === "FAIL" ? (
                          <XCircle className="h-3.5 w-3.5 text-rose-600 shrink-0" />
                        ) : (
                          <AlertTriangle className="h-3.5 w-3.5 text-amber-500 shrink-0" />
                        )}
                        {chk.label}
                      </span>
                      <span
                        className={`font-mono text-[10.5px] text-right ${
                          chk.status === "FAIL" ? "text-rose-700 font-bold" : "text-slate-600"
                        }`}
                      >
                        {chk.detail}
                      </span>
                    </div>
                  ))}
                </div>
                {!verifyInfo.ok && (
                  <div className="text-[11px] text-amber-950 leading-relaxed pt-0.5">
                    <strong>3-Click Fix for Fine-Grained PAT (<code>github_pat_...</code>):</strong> Click{" "}
                    <em>Edit Fine-Grained Token</em> above &rarr; set <strong>Repository access</strong> to{" "}
                    <em>All repositories</em> or <em>Only select repositories ({repoUrl.replace("https://github.com/", "")})</em> &rarr; set{" "}
                    <strong>Permissions &rarr; Contents = Read and write</strong> &rarr; Save!{" "}
                    <em>(Or just click <strong>Copy 1-Paste Git Push</strong> in Method 1 above!)</em>
                  </div>
                )}
              </div>
            )}

            {pushError && !tokenExplicitlyReadOnly && (
              <div className="rounded-xl border border-rose-200 bg-rose-50 p-3 text-xs font-semibold text-rose-900">
                {pushError}
              </div>
            )}

            {pushResult && (
              <div className="rounded-xl border border-emerald-300 bg-emerald-50 p-4 space-y-2 text-xs text-emerald-950">
                <div className="font-bold flex items-center gap-1.5 text-emerald-900">
                  <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                  Successfully Updated {pushResult.repo} ({pushResult.files_pushed.length} surgical files)!
                </div>
                <div className="font-mono text-[11px]">
                  Branch: <strong>{pushResult.branch}</strong> &middot; Commit: {pushResult.commit_sha.slice(0, 10)}
                </div>
                {(pushResult.pr_url || pushResult.commit_url) && (
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    <button
                      type="button"
                      onClick={() => openOrCopyExternalUrl("pr-url", pushResult.pr_url || pushResult.commit_url || "")}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-700 px-3 py-1.5 text-xs font-bold text-white hover:bg-emerald-800 cursor-pointer"
                    >
                      {pushResult.compare_only ? "Branch Pushed — Open PR on GitHub" : "Open on GitHub"}{" "}
                      <ExternalLink className="h-3.5 w-3.5" />
                    </button>
                  </div>
                )}
              </div>
            )}

            <button
              type="submit"
              disabled={
                pushBusy ||
                changedFiles.length === 0 ||
                !repoUrl.trim() ||
                (!trimmedToken && !hasUsableSavedToken) ||
                tokenExplicitlyReadOnly
              }
              className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-indigo-600 px-5 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-50 transition cursor-pointer"
            >
              {pushBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <GitPullRequest className="h-4 w-4" />}
              {tokenExplicitlyReadOnly
                ? "Token is Read-Only — Grant 'Contents: Read & write' or Use Method 1 Above"
                : pushBusy
                ? "Pushing Surgical Update to GitHub..."
                : pushMode === "pull_request"
                ? "Push Branch & Open Pull Request via GitHub Token"
                : "Push Direct Surgical Commit via GitHub Token"}
            </button>
          </div>

          <div className="rounded-xl border border-emerald-200 bg-emerald-50/60 px-3.5 py-2 text-[11px] text-emerald-900 flex items-center gap-2">
            <Lock className="h-3.5 w-3.5 shrink-0 text-emerald-700" />
            <span>
              <strong>Secret Leak Guard:</strong> Raw <code className="font-mono">.env</code> /{" "}
              <code className="font-mono">.env.local</code> files are strictly excluded from every GitHub push.
            </span>
          </div>
        </form>

        {/* Option B: Download Updated .ZIP, .patch & Audit Certificate */}
        <div className="wiz-card rounded-2xl p-6 lg:col-span-5 flex flex-col justify-between space-y-5">
          <div className="space-y-4">
            <div className="flex items-center gap-3 border-b border-slate-100 pb-3.5">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-600 text-white shadow-sm">
                <FolderArchive className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900">
                  Option B · Export Verified Project Bundle
                </h3>
                <p className="text-xs text-slate-500">
                  Ready-to-deploy .ZIP, unified Git .patch, &amp; Audit Certificate
                </p>
              </div>
            </div>

            <button
              type="button"
              disabled={busyArtifact !== null}
              onClick={() => handleDeliverArtifact("project_zip")}
              className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-emerald-600 px-5 py-3.5 text-sm font-bold text-white shadow-sm hover:bg-emerald-700 disabled:opacity-60 transition cursor-pointer"
            >
              {busyArtifact === "project_zip" ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <FolderArchive className="h-4 w-4" />
              )}{" "}
              Download Updated Project (.zip)
            </button>

            <div className="grid grid-cols-2 gap-2.5">
              <button
                type="button"
                disabled={busyArtifact !== null}
                onClick={() => handleDeliverArtifact("project_patch")}
                className="inline-flex items-center justify-center gap-1.5 rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-xs font-bold text-slate-800 hover:bg-slate-50 disabled:opacity-60 transition cursor-pointer"
              >
                {busyArtifact === "project_patch" ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-indigo-600" />
                ) : (
                  <Download className="h-3.5 w-3.5 text-indigo-600" />
                )}{" "}
                Git .patch File
              </button>

              <button
                type="button"
                disabled={busyArtifact !== null}
                onClick={() => handleDeliverArtifact("project_cert")}
                className="inline-flex items-center justify-center gap-1.5 rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-xs font-bold text-slate-800 hover:bg-slate-50 disabled:opacity-60 transition cursor-pointer"
              >
                {busyArtifact === "project_cert" ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-sky-600" />
                ) : (
                  <FileCheck2 className="h-3.5 w-3.5 text-sky-600" />
                )}{" "}
                Audit Report
              </button>
            </div>

            {/* Exact Manifest of Updated vs Untouched Files */}
            <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-3.5 space-y-2">
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
                Surgically Updated Files ({changedFiles.length})
              </div>
              {changedFiles.length === 0 ? (
                <div className="text-xs text-slate-500">
                  No changes adopted yet. Go to Step 3 to approve surgical fixes.
                </div>
              ) : (
                <div className="space-y-1 max-h-44 overflow-y-auto">
                  {changedFiles.map((fp) => (
                    <div key={fp} className="flex items-center justify-between font-mono text-[11px]">
                      <span className="truncate text-slate-800 font-semibold">{fp}</span>
                      <span className="ml-2 shrink-0 text-emerald-700 font-bold">
                        {fp in before_files ? "PATCHED" : "+ADDED"}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="border-t border-slate-100 pt-3 flex items-center justify-between text-[11px] text-slate-500">
            <span>Untouched Safe Files</span>
            <span className="font-mono font-bold text-slate-800">{untouchedFiles.length} files (0 bytes changed)</span>
          </div>
        </div>
      </div>

      <ArtifactDeliveryModal
        artifact={activeArtifact}
        onClose={() => setActiveArtifact(null)}
      />
    </div>
  );
};
