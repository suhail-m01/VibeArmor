import React, { useMemo } from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Database,
  FileCheck,
  FileWarning,
  KeyRound,
  Lock,
  PackageSearch,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
} from "lucide-react";
import { Finding, ProjectDetailPayload } from "../types";

interface Props {
  detail: ProjectDetailPayload;
  onContinueToSurgicalDiff: () => void;
  onBackToGraph: () => void;
}

export const ThreatAnalysisView: React.FC<Props> = ({
  detail,
  onContinueToSurgicalDiff,
  onBackToGraph,
}) => {
  const { project, report, files } = detail;

  const activeFindings = useMemo(
    () =>
      report.mode === "auto_heal"
        ? report.findings_after
        : report.findings_before,
    [report]
  );

  const actionable = useMemo(
    () => activeFindings.filter((f) => f.reachable && !f.requires_policy_spec),
    [activeFindings]
  );

  const abstentions = useMemo(
    () => activeFindings.filter((f) => f.requires_policy_spec),
    [activeFindings]
  );

  // Compute the 5 exact Pre-Push / Pre-Deploy Threat Categories
  const threatChecks = useMemo(() => {
    const byPred = (pred: (f: Finding) => boolean) => actionable.filter(pred);
    const envF = byPred((f) => f.rule_id === "VA-ENV-001" || f.rule_id === "VA-ENV-002");
    const rlsF = byPred((f) => f.pillar === "rls_dpdp");
    const keyF = byPred(
      (f) => f.pillar === "secret_boundary" && f.rule_id !== "VA-ENV-001" && f.rule_id !== "VA-ENV-002"
    );
    const injF = byPred((f) => f.pillar === "taint_payment");
    const pkgF = byPred((f) => f.pillar === "supply_chain");

    return [
      {
        id: "dotenv",
        title: "1. .env Variables & Git Push Hygiene",
        desc: "Unignored .env secret files & NEXT_PUBLIC_/VITE_ private key leaks",
        count: envF.length,
        icon: Lock,
      },
      {
        id: "rls",
        title: "2. Supabase Tables & Access Rules",
        desc: "Tables missing RLS or using vacuous USING (true) policies",
        count: rlsF.length,
        icon: Database,
      },
      {
        id: "keys",
        title: "3. Browser-Exposed Secret Keys",
        desc: "OpenAI, Razorpay, Stripe or service_role keys inside React/TSX",
        count: keyF.length,
        icon: KeyRound,
      },
      {
        id: "injections",
        title: "4. DB Injections & Payment Callbacks",
        desc: "Raw SQL/Command/Eval injections & unsigned Razorpay/Stripe webhooks",
        count: injF.length,
        icon: TerminalSquare,
      },
      {
        id: "packages",
        title: "5. Fake & Vulnerable Packages",
        desc: "AI-hallucinated slopsquat malware & reachable CVEs",
        count: pkgF.length,
        icon: PackageSearch,
      },
    ];
  }, [actionable]);

  const { vulnerableFiles, safeUntouchedFiles } = useMemo(() => {
    const vulnPaths = new Set(actionable.map((f) => f.file_path));
    const allPaths = Object.keys(files).sort();
    return {
      vulnerableFiles: allPaths.filter((p) => vulnPaths.has(p)),
      safeUntouchedFiles: allPaths.filter((p) => !vulnPaths.has(p)),
    };
  }, [files, actionable]);

  return (
    <div className="space-y-6">
      {/* Header Banner + Next Step CTA */}
      <div className="wiz-card rounded-2xl p-6 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="rounded-full bg-indigo-50 px-2.5 py-0.5 font-mono text-[11px] font-bold text-indigo-700 border border-indigo-200">
              STEP 2 OF 4 · DEEP THREAT ANALYSIS
            </span>
            <span
              className={`rounded-full px-3 py-0.5 text-xs font-bold ${
                actionable.length === 0
                  ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                  : "bg-rose-50 text-rose-700 border border-rose-200"
              }`}
            >
              {actionable.length === 0
                ? "✅ Ready for GitHub Push & Deploy"
                : `🛑 Push / Deploy Blocked — ${actionable.length} Open Threat(s)`}
            </span>
          </div>
          <h2 className="mt-2 text-lg font-extrabold text-slate-900">
            Pre-Push &amp; Deployment Vulnerability Audit — {project.name}
          </h2>
          <p className="mt-1 text-xs text-slate-600 max-w-3xl">
            Completed deterministic AST + PostgreSQL RLS + Supply-Chain analysis in{" "}
            <strong className="font-mono text-slate-900">{report.scan_latency_ms} ms</strong>. Only the{" "}
            <strong className="text-rose-700">{vulnerableFiles.length} vulnerable file(s)</strong> will be targeted;{" "}
            <strong className="text-emerald-700">{safeUntouchedFiles.length} clean file(s)</strong> are locked against modification.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={onBackToGraph}
            className="rounded-xl border border-slate-300 bg-white px-3.5 py-2.5 text-xs font-semibold text-slate-700 hover:bg-slate-50"
          >
            &larr; Code Structure Graph
          </button>
          <button
            type="button"
            onClick={onContinueToSurgicalDiff}
            className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-5 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-indigo-700 transition"
          >
            Differentiate Vulnerable vs. Correct Code <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* 5-Check Pre-Push & Deploy Readiness Cards */}
      <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 lg:grid-cols-5">
        {threatChecks.map((chk) => {
          const Icon = chk.icon;
          const passed = chk.count === 0;
          return (
            <div
              key={chk.id}
              className={`wiz-card rounded-2xl p-4 border-t-4 ${
                passed ? "border-t-emerald-500" : "border-t-rose-500"
              }`}
            >
              <div className="flex items-center justify-between">
                <div
                  className={`flex h-8 w-8 items-center justify-center rounded-lg ${
                    passed ? "bg-emerald-50 text-emerald-700" : "bg-rose-50 text-rose-700"
                  }`}
                >
                  <Icon className="h-4 w-4" />
                </div>
                <span
                  className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[11px] font-bold ${
                    passed ? "bg-emerald-100 text-emerald-800" : "bg-rose-100 text-rose-800"
                  }`}
                >
                  {passed ? <ShieldCheck className="h-3 w-3" /> : <ShieldAlert className="h-3 w-3" />}
                  {passed ? "SAFE" : `${chk.count} RISK${chk.count > 1 ? "S" : ""}`}
                </span>
              </div>
              <div className="mt-2.5 text-xs font-bold text-slate-900 leading-snug">{chk.title}</div>
              <p className="mt-1 text-[11px] text-slate-500 leading-relaxed">{chk.desc}</p>
            </div>
          );
        })}
      </div>

      {/* Two-Column Separation: Vulnerable / Open-to-Threat Code vs. Clean Untouched Files */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left 8 Cols: Detailed Vulnerable Findings */}
        <div className="wiz-card rounded-2xl p-5 lg:col-span-8 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-200 pb-3">
            <div className="flex items-center gap-2">
              <FileWarning className="h-4 w-4 text-rose-600" />
              <h3 className="text-sm font-bold text-slate-900">
                Detected Vulnerabilities &amp; Open-to-Threat Code ({actionable.length})
              </h3>
            </div>
            <span className="text-xs text-slate-500">Strict Scope: Only these exact locations are eligible for repair</span>
          </div>

          {actionable.length === 0 ? (
            <div className="rounded-xl border border-emerald-200 bg-emerald-50/60 p-8 text-center">
              <CheckCircle2 className="h-8 w-8 text-emerald-600 mx-auto mb-2" />
              <div className="text-sm font-bold text-emerald-900">0 Open Actionable Vulnerabilities</div>
              <p className="text-xs text-emerald-700 mt-1">
                This repository passes all 5 Pre-Push &amp; Deployment security checks!
              </p>
            </div>
          ) : (
            <div className="space-y-3 max-h-[540px] overflow-y-auto pr-1">
              {actionable.map((f) => (
                <div
                  key={f.id}
                  className="rounded-xl border border-rose-200/90 bg-rose-50/35 p-4 space-y-2"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-rose-100 px-2 py-0.5 font-mono text-[10.5px] font-bold text-rose-800">
                        {f.severity}
                      </span>
                      <span className="font-mono text-xs font-bold text-slate-800">
                        {f.rule_id} · {f.cwe}
                      </span>
                    </div>
                    <span className="rounded-md bg-white border border-slate-200 px-2 py-0.5 font-mono text-[11px] font-semibold text-slate-700">
                      {f.file_path}:L{f.line_start}
                    </span>
                  </div>

                  <div className="text-xs font-bold text-slate-900">{f.title}</div>
                  <p className="text-xs text-slate-600 leading-relaxed">{f.description}</p>

                  {f.snippet && (
                    <pre className="rounded-lg bg-[#0F172A] px-3 py-2 font-mono text-[11px] text-rose-200 overflow-x-auto">
                      {f.snippet}
                    </pre>
                  )}

                  {f.dpdp_pii_columns.length > 0 && (
                    <div className="inline-block rounded-lg border border-rose-200 bg-white px-2.5 py-1 font-mono text-[10.5px] font-semibold text-rose-700">
                      Exposed User PII Columns: {f.dpdp_pii_columns.join(", ")}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {abstentions.length > 0 && (
            <div className="pt-2 space-y-2">
              <div className="text-xs font-bold uppercase tracking-wider text-amber-800">
                Policy Boundary Items (Left Untouched for Human Business Logic — {abstentions.length})
              </div>
              {abstentions.map((ab) => (
                <div
                  key={ab.id}
                  className="rounded-xl border border-amber-200 bg-amber-50/70 p-3.5 text-xs text-amber-950 flex items-start gap-2.5"
                >
                  <AlertTriangle className="h-4 w-4 text-amber-600 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold">
                      [{ab.rule_id} · {ab.file_path}:L{ab.line_start}] {ab.title}:{" "}
                    </span>
                    {ab.abstention_reason}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right 4 Cols: Clean / Safe Files Inventory (Strict Untouched Guarantee) */}
        <div className="wiz-card rounded-2xl p-5 lg:col-span-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 border-b border-slate-200 pb-3 mb-3">
              <FileCheck className="h-4 w-4 text-emerald-600" />
              <h3 className="text-sm font-bold text-slate-900">
                Strict Non-Modification Scope
              </h3>
            </div>

            <div className="rounded-xl border border-emerald-200 bg-emerald-50/60 p-3.5 mb-4">
              <div className="text-xs font-bold text-emerald-900">
                🔒 Zero Unnecessary Code Changes
              </div>
              <p className="mt-1 text-[11px] text-emerald-800 leading-relaxed">
                VibeArmor never reformats, rewrites, or touches safe files or non-vulnerable functions. Every clean file listed below is locked with <strong>0 bytes modified</strong>.
              </p>
            </div>

            <div className="mb-2 text-[11px] font-bold uppercase tracking-wider text-slate-400">
              Clean / Untouched Files ({safeUntouchedFiles.length})
            </div>
            <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
              {safeUntouchedFiles.map((fp) => (
                <div
                  key={fp}
                  className="flex items-center justify-between rounded-lg border border-slate-200/80 bg-slate-50/70 px-3 py-2"
                >
                  <span className="truncate font-mono text-[11px] text-slate-700">{fp}</span>
                  <span className="shrink-0 ml-2 rounded bg-emerald-100 px-1.5 py-0.5 font-mono text-[9.5px] font-bold text-emerald-800">
                    🔒 SAFE
                  </span>
                </div>
              ))}
            </div>

            <div className="mt-4 mb-2 text-[11px] font-bold uppercase tracking-wider text-rose-500">
              Targeted Vulnerable Files ({vulnerableFiles.length})
            </div>
            <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
              {vulnerableFiles.map((fp) => (
                <div
                  key={fp}
                  className="flex items-center justify-between rounded-lg border border-rose-200 bg-rose-50/50 px-3 py-2"
                >
                  <span className="truncate font-mono text-[11px] text-slate-900 font-semibold">{fp}</span>
                  <span className="shrink-0 ml-2 rounded bg-rose-100 px-1.5 py-0.5 font-mono text-[9.5px] font-bold text-rose-800">
                    SURGICAL TARGET
                  </span>
                </div>
              ))}
            </div>
          </div>

          <button
            type="button"
            onClick={onContinueToSurgicalDiff}
            className="mt-5 w-full inline-flex items-center justify-center gap-2 rounded-xl bg-slate-900 px-4 py-3 text-xs font-bold text-white hover:bg-indigo-600 transition"
          >
            Preview Surgical Fixes &amp; Compare Code <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
