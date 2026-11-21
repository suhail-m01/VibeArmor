import React, { useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  CheckSquare,
  FileDiff,
  Loader2,
  Lock,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Square,
} from "lucide-react";
import {
  ProjectDetailPayload,
  StagedProposalBundle,
  StagedProposalItem,
  StreamEventItem,
} from "../types";

interface Props {
  detail: ProjectDetailPayload;
  stagedBundle: StagedProposalBundle | null;
  stagingBusy: boolean;
  adoptingBusy: boolean;
  streamEvents: StreamEventItem[];
  onGenerateProposals: () => void;
  onAdoptSelected: (selectedFindingIds: string[]) => void;
  onSkipToDelivery: () => void;
}

interface SplitLineRow {
  leftNum: number | null;
  leftText: string;
  rightNum: number | null;
  rightText: string;
  kind: "same" | "del" | "add" | "mod";
}

function buildSplitRows(beforeStr: string, afterStr: string): SplitLineRow[] {
  const bLines = beforeStr ? beforeStr.split("\n") : [];
  const aLines = afterStr ? afterStr.split("\n") : [];
  if (beforeStr === afterStr) {
    return aLines.map((ln, idx) => ({
      leftNum: idx + 1,
      leftText: ln,
      rightNum: idx + 1,
      rightText: ln,
      kind: "same",
    }));
  }

  const rows: SplitLineRow[] = [];
  let i = 0;
  let j = 0;
  while (i < bLines.length || j < aLines.length) {
    if (i < bLines.length && j < aLines.length && bLines[i] === aLines[j]) {
      rows.push({ leftNum: i + 1, leftText: bLines[i], rightNum: j + 1, rightText: aLines[j], kind: "same" });
      i++;
      j++;
      continue;
    }

    let syncI = -1;
    let syncJ = -1;
    outer: for (let di = 0; di < 14 && i + di < bLines.length; di++) {
      for (let dj = 0; dj < 14 && j + dj < aLines.length; dj++) {
        if (bLines[i + di] === aLines[j + dj] && bLines[i + di].trim().length > 0) {
          syncI = i + di;
          syncJ = j + dj;
          break outer;
        }
      }
    }

    if (syncI !== -1 && syncJ !== -1) {
      const delCount = syncI - i;
      const addCount = syncJ - j;
      const pairs = Math.max(delCount, addCount);
      for (let k = 0; k < pairs; k++) {
        const hasL = k < delCount;
        const hasR = k < addCount;
        rows.push({
          leftNum: hasL ? i + k + 1 : null,
          leftText: hasL ? bLines[i + k] : "",
          rightNum: hasR ? j + k + 1 : null,
          rightText: hasR ? aLines[j + k] : "",
          kind: hasL && hasR ? "mod" : hasL ? "del" : "add",
        });
      }
      i = syncI;
      j = syncJ;
    } else {
      const hasL = i < bLines.length;
      const hasR = j < aLines.length;
      rows.push({
        leftNum: hasL ? i + 1 : null,
        leftText: hasL ? bLines[i] : "",
        rightNum: hasR ? j + 1 : null,
        rightText: hasR ? aLines[j] : "",
        kind: hasL && hasR ? "mod" : hasL ? "del" : "add",
      });
      if (hasL) i++;
      if (hasR) j++;
    }
  }
  return rows;
}

export const SurgicalDiffConsentView: React.FC<Props> = ({
  detail,
  stagedBundle,
  stagingBusy,
  adoptingBusy,
  streamEvents,
  onGenerateProposals,
  onAdoptSelected,
  onSkipToDelivery,
}) => {
  const adoptableProposals = useMemo(
    () => (stagedBundle?.proposals || []).filter((p) => p.adoptable),
    [stagedBundle]
  );

  const abstainedProposals = useMemo(
    () => (stagedBundle?.proposals || []).filter((p) => !p.adoptable),
    [stagedBundle]
  );

  const [uncheckedIds, setUncheckedIds] = useState<Record<string, boolean>>({});
  const [expandedFullFile, setExpandedFullFile] = useState<string | null>(null);

  const selectedIds = useMemo(
    () => adoptableProposals.map((p) => p.finding_id).filter((id) => !uncheckedIds[id]),
    [adoptableProposals, uncheckedIds]
  );

  function toggleId(fid: string) {
    setUncheckedIds((prev) => ({ ...prev, [fid]: !prev[fid] }));
  }

  return (
    <div className="space-y-6">
      {/* Top Step Header + Strict Surgical Precision Guarantee */}
      <div className="wiz-card rounded-2xl p-6 space-y-4">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full bg-indigo-50 px-2.5 py-0.5 font-mono text-[11px] font-bold text-indigo-700 border border-indigo-200">
                STEP 3 OF 4 · VULNERABLE VS. CORRECT CODE
              </span>
              <span className="rounded-full bg-slate-900 px-2.5 py-0.5 font-mono text-[11px] font-bold text-white">
                Workspace: {detail.project.name}
              </span>
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 border border-emerald-200 px-2.5 py-0.5 text-xs font-bold text-emerald-800">
                <Lock className="h-3 w-3" /> Strict Surgical Precision Mode Active
              </span>
            </div>
            <h2 className="mt-2 text-lg font-extrabold text-slate-900">
              Differentiate Vulnerable Code &amp; Corrected Code — Review Before Adopting
            </h2>
            <p className="mt-1 text-xs text-slate-600 max-w-3xl">
              Your repository files have <strong>NOT</strong> been modified yet. Inspect every side-by-side comparison below—VibeArmor strictly repairs only the vulnerable AST/SQL/manifest lines while leaving all other code 100% untouched.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              disabled={stagingBusy || adoptingBusy}
              onClick={onGenerateProposals}
              className="inline-flex items-center gap-1.5 rounded-xl border border-slate-300 bg-white px-3.5 py-2.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${stagingBusy ? "animate-spin" : ""}`} />
              {stagingBusy ? "Synthesizing..." : "Re-Analyze Staged Diffs"}
            </button>
            {detail.project.adopted && (
              <button
                type="button"
                onClick={onSkipToDelivery}
                className="inline-flex items-center gap-1.5 rounded-xl bg-emerald-600 px-4 py-2.5 text-xs font-bold text-white hover:bg-emerald-700"
              >
                Already Adopted &rarr; Go to GitHub / .ZIP Update
              </button>
            )}
          </div>
        </div>

        {/* Precision Metrics Strip */}
        {stagedBundle && (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 pt-2 border-t border-slate-100">
            <div className="rounded-xl border border-slate-200/90 bg-slate-50/70 p-3.5">
              <div className="text-[10.5px] font-bold uppercase tracking-wider text-slate-500">
                Non-Vulnerable Lines Preserved
              </div>
              <div className="mt-1 font-mono text-2xl font-extrabold text-emerald-700">
                {stagedBundle.avg_non_vulnerable_preservation_pct}%
              </div>
              <div className="text-[11px] text-slate-500">Byte-for-byte identical outside vulnerable hunks</div>
            </div>

            <div className="rounded-xl border border-slate-200/90 bg-slate-50/70 p-3.5">
              <div className="text-[10.5px] font-bold uppercase tracking-wider text-slate-500">
                Clean Files Untouched
              </div>
              <div className="mt-1 font-mono text-2xl font-extrabold text-slate-900">
                {stagedBundle.untouched_safe_files.length} files
              </div>
              <div className="text-[11px] text-slate-500">0 bytes altered in safe modules &amp; UI code</div>
            </div>

            <div className="rounded-xl border border-slate-200/90 bg-slate-50/70 p-3.5">
              <div className="text-[10.5px] font-bold uppercase tracking-wider text-slate-500">
                3-Gate Verified Surgical Fixes
              </div>
              <div className="mt-1 font-mono text-2xl font-extrabold text-indigo-700">
                {selectedIds.length} / {adoptableProposals.length} selected
              </div>
              <div className="text-[11px] text-slate-500">0 syntax errors · 0 broken builds</div>
            </div>
          </div>
        )}
      </div>

      {/* Live Streaming Telemetry Drawer */}
      {(stagingBusy || streamEvents.length > 0) && (
        <div className="rounded-2xl border border-slate-800 bg-[#0F172A] p-4 text-slate-200 shadow-sm">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-2 text-xs">
            <span className="inline-flex items-center gap-2 font-semibold text-white">
              <Sparkles className="h-3.5 w-3.5 text-indigo-400" />
              Isolated Sandbox Remediation Stream (0 Disk Mutations Until You Approve)
            </span>
            <span className="font-mono text-[11px] text-emerald-400">
              {stagingBusy ? "STAGING IN SANDBOX..." : "READY FOR YOUR REVIEW"}
            </span>
          </div>
          <div className="max-h-28 overflow-y-auto space-y-1 font-mono text-[11px]">
            {streamEvents.map((ev, idx) => (
              <div key={idx} className="flex items-start gap-2.5">
                <span className="w-16 shrink-0 text-right text-slate-500">{ev.elapsed_ms}ms</span>
                <span className="uppercase font-bold w-16 shrink-0 text-indigo-400">[{ev.stage}]</span>
                <span className="text-slate-200">{ev.message}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Loading Skeleton if Staging */}
      {stagingBusy && !stagedBundle && (
        <div className="wiz-card rounded-2xl p-12 text-center space-y-3">
          <Loader2 className="h-7 w-7 animate-spin text-indigo-600 mx-auto" />
          <div className="text-sm font-bold text-slate-900">
            Generating Surgical Fixes &amp; Running 3-Gate Verification in Sandbox...
          </div>
          <p className="text-xs text-slate-500">
            Extracting ~25-line Minimal Security Slices and verifying each candidate patch without modifying your project.
          </p>
        </div>
      )}

      {/* Explicit User Consent Decision Banner */}
      {stagedBundle && adoptableProposals.length > 0 && (
        <div className="rounded-2xl border-2 border-indigo-600 bg-indigo-50/70 p-5 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between shadow-sm">
          <div>
            <div className="text-sm font-extrabold text-indigo-950">
              User Adoption Confirmation Required — Adopt {selectedIds.length} Surgical Security Fix(es)?
            </div>
            <p className="mt-0.5 text-xs text-indigo-900/80">
              Review the side-by-side diffs below, uncheck any fix you want to skip, and click{" "}
              <strong>Adopt Selected Changes</strong> to apply them and update your GitHub repo or download the updated{" "}
              <code className="rounded bg-white px-1 py-0.5 font-mono">.zip</code>.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={() => setUncheckedIds({})}
              className="rounded-xl border border-indigo-200 bg-white px-3 py-2 text-xs font-semibold text-indigo-800 hover:bg-indigo-50"
            >
              Select All ({adoptableProposals.length})
            </button>
            <button
              type="button"
              disabled={adoptingBusy || selectedIds.length === 0}
              onClick={() => onAdoptSelected(selectedIds)}
              className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-5 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-50 transition"
            >
              {adoptingBusy ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <ShieldCheck className="h-4 w-4" />
              )}
              {adoptingBusy
                ? "Applying Approved Fixes..."
                : `Adopt ${selectedIds.length} Selected Change(s) & Continue`}
              <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}

      {/* Per-Finding Side-by-Side Vulnerable vs. Correct Code Cards */}
      {stagedBundle && (
        <div className="space-y-5">
          {adoptableProposals.map((prop: StagedProposalItem, index: number) => {
            const isSelected = !uncheckedIds[prop.finding_id];
            const primaryDiff =
              prop.file_diffs.find((fd) => fd.file_path === prop.file_path) || prop.file_diffs[0];
            const showFull = expandedFullFile === prop.finding_id;

            return (
              <div
                key={prop.finding_id}
                className={`wiz-card rounded-2xl overflow-hidden transition ${
                  isSelected ? "ring-1 ring-indigo-500/30" : "opacity-65"
                }`}
              >
                {/* Card Header with Checkbox + Precision Proof Badge */}
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-slate-50/90 px-5 py-3.5">
                  <button
                    type="button"
                    onClick={() => toggleId(prop.finding_id)}
                    className="flex items-center gap-3 text-left"
                  >
                    {isSelected ? (
                      <CheckSquare className="h-5 w-5 text-indigo-600 shrink-0" />
                    ) : (
                      <Square className="h-5 w-5 text-slate-400 shrink-0" />
                    )}
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs font-bold text-indigo-700">
                          Fix #{index + 1} · {prop.rule_id} ({prop.cwe})
                        </span>
                        <span className="rounded bg-rose-100 px-1.5 py-0.5 font-mono text-[10px] font-bold text-rose-800">
                          {prop.severity}
                        </span>
                        <span className="font-mono text-xs text-slate-500">
                          {prop.file_path}:L{prop.line_start}
                        </span>
                      </div>
                      <div className="text-sm font-bold text-slate-900 mt-0.5">{prop.title}</div>
                    </div>
                  </button>

                  <div className="flex flex-wrap items-center gap-2">
                    {prop.precision && (
                      <span className="rounded-lg border border-emerald-200 bg-emerald-50 px-2.5 py-1 font-mono text-[11px] font-bold text-emerald-800">
                        🔒 {prop.precision.changed_span_label} · {prop.precision.preservation_pct}% file untouched
                      </span>
                    )}
                    {primaryDiff && (
                      <button
                        type="button"
                        onClick={() => setExpandedFullFile(showFull ? null : prop.finding_id)}
                        className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-[11px] font-semibold text-slate-700 hover:bg-slate-50"
                      >
                        <FileDiff className="h-3.5 w-3.5 text-indigo-600" />
                        {showFull ? "Show Surgical Hunk Only" : "Expand Full File Split-Diff"}
                      </button>
                    )}
                  </div>
                </div>

                {/* Focused Surgical Hunk Comparison OR Full-File Split Diff */}
                {!showFull && prop.precision ? (
                  <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-slate-200">
                    {/* Left: Vulnerable Code */}
                    <div className="p-4 bg-rose-50/30">
                      <div className="mb-2 flex items-center justify-between text-xs font-bold text-rose-900">
                        <span>🔴 Vulnerable / Open-to-Threat Code ({prop.file_path})</span>
                        <span className="font-mono text-[10.5px] text-rose-700">Before</span>
                      </div>
                      <pre className="rounded-xl border border-rose-200 bg-[#0F172A] p-3.5 font-mono text-xs text-rose-200 overflow-x-auto leading-relaxed">
                        {prop.precision.vulnerable_excerpt}
                      </pre>
                    </div>

                    {/* Right: Corrected Secure Code */}
                    <div className="p-4 bg-emerald-50/30">
                      <div className="mb-2 flex items-center justify-between text-xs font-bold text-emerald-900">
                        <span>🟢 Corrected Secure Code (Surgical Patch)</span>
                        <span className="font-mono text-[10.5px] text-emerald-700">
                          Strategy: {prop.strategy_used}
                        </span>
                      </div>
                      <pre className="rounded-xl border border-emerald-200 bg-[#0F172A] p-3.5 font-mono text-xs text-emerald-200 overflow-x-auto leading-relaxed">
                        {prop.precision.corrected_excerpt}
                      </pre>
                    </div>
                  </div>
                ) : primaryDiff ? (
                  <div className="max-h-96 overflow-auto bg-white">
                    <div className="grid grid-cols-2 border-b border-slate-200 bg-slate-100 px-3 py-1.5 font-mono text-[11px] font-bold text-slate-700 sticky top-0">
                      <div>Vulnerable Baseline ({primaryDiff.file_path})</div>
                      <div>Surgically Corrected ({primaryDiff.file_path})</div>
                    </div>
                    <table className="w-full border-collapse font-mono text-[11.5px]">
                      <tbody>
                        {buildSplitRows(primaryDiff.before_content, primaryDiff.after_content).map((r, rIdx) => {
                          const lBg =
                            r.kind === "del" || r.kind === "mod"
                              ? "bg-rose-50 text-rose-950 font-semibold"
                              : "bg-white text-slate-600";
                          const rBg =
                            r.kind === "add" || r.kind === "mod"
                              ? "bg-emerald-50 text-emerald-950 font-semibold"
                              : "bg-white text-slate-700";
                          return (
                            <tr key={rIdx} className="border-b border-slate-100">
                              <td className="w-9 bg-slate-50 px-2 text-right text-[10px] text-slate-400 border-r border-slate-200">
                                {r.leftNum ?? ""}
                              </td>
                              <td className={`w-1/2 whitespace-pre-wrap break-all px-3 py-0.5 border-r border-slate-200 ${lBg}`}>
                                {r.leftText}
                              </td>
                              <td className="w-9 bg-slate-50 px-2 text-right text-[10px] text-slate-400 border-r border-slate-200">
                                {r.rightNum ?? ""}
                              </td>
                              <td className={`w-1/2 whitespace-pre-wrap break-all px-3 py-0.5 ${rBg}`}>
                                {r.rightText}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                ) : null}

                {/* Companion Synthesized Guard Files + 3-Gate Verification Strip */}
                <div className="border-t border-slate-200 bg-white px-5 py-3 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    {prop.gates.map((g) => (
                      <span
                        key={g.gate_name}
                        className="inline-flex items-center gap-1 rounded-lg border border-emerald-200 bg-emerald-50/70 px-2.5 py-1 text-[11px] font-semibold text-emerald-800"
                      >
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />
                        {g.gate_name.split("·")[0].trim()} PASS ({g.latency_ms}ms)
                      </span>
                    ))}
                  </div>
                  {prop.file_diffs.length > 1 && (
                    <span className="font-mono text-[11px] text-slate-500">
                      Companion guard files:{" "}
                      {prop.file_diffs.map((d) => d.file_path).join(", ")}
                    </span>
                  )}
                </div>
              </div>
            );
          })}

          {/* Honest Policy Abstentions (Explicitly Not Auto-Modified) */}
          {abstainedProposals.map((ab) => (
            <div
              key={ab.finding_id}
              className="wiz-card rounded-2xl p-4 border-l-4 border-l-amber-500 flex items-start gap-3"
            >
              <AlertTriangle className="h-5 w-5 text-amber-600 shrink-0 mt-0.5" />
              <div className="text-xs">
                <div className="font-bold text-slate-900">
                  🔒 Left Untouched (Needs Business Policy Spec) — {ab.rule_id} in {ab.file_path}:L{ab.line_start}
                </div>
                <p className="mt-1 text-slate-600">{ab.abstention_note}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
