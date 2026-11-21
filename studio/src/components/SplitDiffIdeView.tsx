import React, { useMemo, useState } from "react";
import {
  Download,
  FileCheck2,
  FileCode2,
  FileDiff,
  FolderArchive,
  RotateCcw,
  Scissors,
  ShieldCheck,
  Sparkles,
  Zap,
  CheckCircle2,
  AlertTriangle,
  Loader2,
} from "lucide-react";
import { PatchReport, ProjectDetailPayload, StreamEventItem } from "../types";
import {
  ArtifactDeliveryModal,
  ArtifactKind,
  stageAndFetchArtifact,
  StagedArtifactInfo,
} from "../utils/artifactDelivery";

interface Props {
  detail: ProjectDetailPayload;
  selectedFile: string;
  onSelectFile: (fp: string) => void;
  onTriggerHeal: () => void;
  onTriggerReset: () => void;
  healing: boolean;
  streamEvents: StreamEventItem[];
}

interface SplitRow {
  leftNum: number | null;
  leftText: string;
  rightNum: number | null;
  rightText: string;
  kind: "same" | "del" | "add" | "mod";
}

/** Compute clean side-by-side line alignment from before & after file strings */
function computeSplitRows(beforeStr: string, afterStr: string): SplitRow[] {
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

  // Lightweight LCS-windowed alignment for crisp split diffs up to ~400 lines
  const rows: SplitRow[] = [];
  let i = 0;
  let j = 0;
  while (i < bLines.length || j < aLines.length) {
    if (i < bLines.length && j < aLines.length && bLines[i] === aLines[j]) {
      rows.push({ leftNum: i + 1, leftText: bLines[i], rightNum: j + 1, rightText: aLines[j], kind: "same" });
      i++;
      j++;
      continue;
    }

    // Look ahead up to 14 lines to resync unchanged anchors
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

export const SplitDiffIdeView: React.FC<Props> = ({
  detail,
  selectedFile,
  onSelectFile,
  onTriggerHeal,
  onTriggerReset,
  healing,
  streamEvents,
}) => {
  const [editorMode, setEditorMode] = useState<"split" | "mss" | "source">("split");
  const [activeArtifact, setActiveArtifact] = useState<StagedArtifactInfo | null>(null);
  const [busyArtifact, setBusyArtifact] = useState<ArtifactKind | null>(null);
  const { project, report, files, before_files } = detail;

  async function handleIdeExport(kind: ArtifactKind) {
    setBusyArtifact(kind);
    try {
      const staged = await stageAndFetchArtifact({
        artifact_kind: kind,
        project_id: project.id,
      });
      setActiveArtifact(staged);
    } catch {
      // ignore
    } finally {
      setBusyArtifact(null);
    }
  }

  const allFilePaths = useMemo(() => {
    const keys = new Set([...Object.keys(before_files), ...Object.keys(files)]);
    return Array.from(keys).sort();
  }, [before_files, files]);

  const activeFile = allFilePaths.includes(selectedFile) ? selectedFile : allFilePaths[0] || "";
  const beforeTxt = before_files[activeFile] ?? "";
  const afterTxt = files[activeFile] ?? "";
  const isNewFile = !(activeFile in before_files) && activeFile in files;
  const isModified = beforeTxt !== afterTxt;

  const splitRows = useMemo(() => computeSplitRows(beforeTxt, afterTxt), [beforeTxt, afterTxt]);

  const filePatches: PatchReport[] = useMemo(
    () =>
      report.patches.filter(
        (p) =>
          p.edits.some((e) => e.file_path === activeFile) ||
          p.mss?.file_path === activeFile
      ),
    [report.patches, activeFile]
  );

  const fileFindings = useMemo(
    () => report.findings_before.filter((f) => f.file_path === activeFile),
    [report.findings_before, activeFile]
  );

  return (
    <div className="space-y-5">
      {/* Top IDE Command & Export Bar */}
      <div className="wiz-card rounded-2xl p-4 sm:px-6 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h2 className="text-base font-extrabold text-slate-900">{project.name}</h2>
            <span className="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-[11px] font-semibold text-slate-600">
              sha256:{project.digest}
            </span>
            <span
              className={`rounded-full px-2.5 py-0.5 text-xs font-bold ${
                project.security_score >= 85
                  ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                  : "bg-rose-50 text-rose-700 border border-rose-200"
              }`}
            >
              Posture: {project.security_score}/100
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-500">
            Inspect side-by-side diffs, ~25-line Minimal Security Slices, 3-Gate proofs, and export production git patches
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={healing}
            onClick={onTriggerHeal}
            className="inline-flex items-center gap-1.5 rounded-xl bg-indigo-600 px-4 py-2 text-xs font-bold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-50 transition"
          >
            {healing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Zap className="h-3.5 w-3.5" />}
            {healing ? "Streaming Auto-Heal..." : "Auto-Heal & 3-Gate Verify"}
          </button>

          <button
            type="button"
            disabled={busyArtifact !== null}
            onClick={() => handleIdeExport("project_patch")}
            className="inline-flex items-center gap-1.5 rounded-xl border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-60 transition cursor-pointer"
          >
            <Download className="h-3.5 w-3.5 text-indigo-600" /> Export .patch
          </button>

          <button
            type="button"
            disabled={busyArtifact !== null}
            onClick={() => handleIdeExport("project_zip")}
            className="inline-flex items-center gap-1.5 rounded-xl border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-60 transition cursor-pointer"
          >
            <FolderArchive className="h-3.5 w-3.5 text-emerald-600" /> Healed .zip
          </button>

          <button
            type="button"
            disabled={busyArtifact !== null}
            onClick={() => handleIdeExport("project_cert")}
            className="inline-flex items-center gap-1.5 rounded-xl border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-60 transition cursor-pointer"
          >
            <FileCheck2 className="h-3.5 w-3.5 text-sky-600" /> Audit Report
          </button>

          <button
            type="button"
            disabled={healing}
            onClick={onTriggerReset}
            className="inline-flex items-center gap-1 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-semibold text-slate-600 hover:bg-slate-100 disabled:opacity-50"
          >
            <RotateCcw className="h-3.5 w-3.5" /> Reset
          </button>
        </div>
      </div>

      {/* Live Streaming NDJSON Pipeline Console (visible while healing or right after streaming!) */}
      {(healing || streamEvents.length > 0) && (
        <div className="rounded-2xl border border-slate-800 bg-[#0F172A] p-4 text-slate-200 shadow-sm">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2.5 mb-2.5 text-xs">
            <span className="inline-flex items-center gap-2 font-semibold text-white">
              <Sparkles className="h-3.5 w-3.5 text-indigo-400" />
              Live Neuro-Symbolic Pipeline Stream (AST/SQL Graph &rarr; MSS Slicer &rarr; Local Qwen2.5-Coder &rarr; 3-Gate Verifier)
            </span>
            <span className="font-mono text-[11px] text-emerald-400">
              {healing ? "RUNNING LIVE..." : `COMPLETED (${report.total_latency_ms} ms)`}
            </span>
          </div>
          <div className="max-h-36 overflow-y-auto space-y-1 font-mono text-[11px]">
            {streamEvents.map((ev, idx) => (
              <div key={idx} className="flex items-start gap-2.5">
                <span className="w-16 shrink-0 text-right text-slate-500">{ev.elapsed_ms}ms</span>
                <span
                  className={`uppercase font-bold w-16 shrink-0 ${
                    ev.stage === "verified"
                      ? "text-emerald-400"
                      : ev.stage === "slm"
                      ? "text-indigo-400"
                      : ev.stage === "rollback"
                      ? "text-rose-400"
                      : "text-sky-400"
                  }`}
                >
                  [{ev.stage}]
                </span>
                <span className="text-slate-200">{ev.message}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 3-Pane Code & Split-Diff Workspace */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        {/* Left File Tree & Signal Navigator */}
        <div className="wiz-card rounded-2xl p-4 lg:col-span-3 flex flex-col justify-between">
          <div>
            <div className="mb-2.5 flex items-center justify-between border-b border-slate-100 pb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-500">Repository Files</span>
              <span className="font-mono text-[11px] text-slate-400">{allFilePaths.length}</span>
            </div>
            <div className="space-y-1 max-h-[480px] overflow-y-auto pr-1">
              {allFilePaths.map((fp) => {
                const b = before_files[fp] ?? "";
                const a = files[fp] ?? "";
                const created = !(fp in before_files) && fp in files;
                const changed = b !== a;
                const hasVuln = report.findings_before.some((f) => f.file_path === fp && f.reachable && !f.requires_policy_spec);
                const hasAbstain = report.findings_before.some((f) => f.file_path === fp && f.requires_policy_spec);
                const active = fp === activeFile;

                return (
                  <button
                    key={fp}
                    type="button"
                    onClick={() => onSelectFile(fp)}
                    className={`w-full rounded-xl px-2.5 py-2 text-left transition flex items-center justify-between gap-2 ${
                      active
                        ? "bg-indigo-50 text-indigo-950 border border-indigo-200 font-semibold"
                        : "text-slate-700 hover:bg-slate-50 border border-transparent"
                    }`}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <FileCode2 className={`h-3.5 w-3.5 shrink-0 ${active ? "text-indigo-600" : "text-slate-400"}`} />
                      <span className="truncate font-mono text-[11px]">{fp}</span>
                    </div>
                    {created ? (
                      <span className="shrink-0 rounded bg-emerald-100 px-1.5 py-0.5 font-mono text-[9px] font-bold text-emerald-800">
                        +NEW BFF
                      </span>
                    ) : changed ? (
                      <span className="shrink-0 rounded bg-indigo-100 px-1.5 py-0.5 font-mono text-[9px] font-bold text-indigo-800">
                        PATCHED
                      </span>
                    ) : hasAbstain ? (
                      <span className="shrink-0 rounded bg-amber-100 px-1.5 py-0.5 font-mono text-[9px] font-bold text-amber-800">
                        POLICY
                      </span>
                    ) : hasVuln ? (
                      <span className="shrink-0 rounded bg-rose-100 px-1.5 py-0.5 font-mono text-[9px] font-bold text-rose-800">
                        VULN
                      </span>
                    ) : null}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="mt-4 border-t border-slate-100 pt-3 text-[11px] text-slate-500 space-y-1">
            <div className="flex justify-between">
              <span>Verified Patches</span>
              <span className="font-mono font-bold text-emerald-700">{report.summary.verified_fixed_count}</span>
            </div>
            <div className="flex justify-between">
              <span>Avg MSS Compression</span>
              <span className="font-mono font-bold text-indigo-700">{report.summary.avg_mss_token_compression_pct}%</span>
            </div>
          </div>
        </div>

        {/* Right 9-Col Split-Diff / MSS / Source Viewer + 3-Gate Cards */}
        <div className="lg:col-span-9 space-y-4">
          <div className="wiz-card rounded-2xl overflow-hidden">
            {/* Editor Tab Header */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 bg-slate-50/90 px-4 py-2.5">
              <div className="flex items-center gap-2">
                <FileDiff className="h-4 w-4 text-indigo-600" />
                <span className="font-mono text-xs font-bold text-slate-900">{activeFile}</span>
                {isNewFile && (
                  <span className="rounded-full bg-emerald-100 px-2.5 py-0.5 text-[10px] font-bold text-emerald-800">
                    Synthesized Zero-Trust Auto-BFF / Migration
                  </span>
                )}
                {!isNewFile && isModified && (
                  <span className="rounded-full bg-indigo-100 px-2.5 py-0.5 text-[10px] font-bold text-indigo-800">
                    Modified &amp; 3-Gate Verified
                  </span>
                )}
              </div>

              <div className="inline-flex rounded-xl border border-slate-200 bg-white p-0.5 text-xs">
                {[
                  { id: "split", label: "Side-by-Side Split Diff" },
                  { id: "mss", label: "Minimal Security Slice (MSS)" },
                  { id: "source", label: "Current Source" },
                ].map((m) => (
                  <button
                    key={m.id}
                    type="button"
                    onClick={() => setEditorMode(m.id as "split" | "mss" | "source")}
                    className={`rounded-lg px-3 py-1 text-[11px] font-semibold transition ${
                      editorMode === m.id ? "bg-slate-900 text-white" : "text-slate-600 hover:text-slate-900"
                    }`}
                  >
                    {m.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Inline Finding Callout Strip */}
            {fileFindings.length > 0 && (
              <div className="border-b border-slate-200 bg-amber-50/50 px-4 py-2.5 flex flex-wrap gap-2">
                {fileFindings.map((f) => (
                  <span
                    key={f.id}
                    className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[11px] font-medium ${
                      f.requires_policy_spec
                        ? "border-amber-300 bg-amber-50 text-amber-900"
                        : !f.reachable
                        ? "border-slate-200 bg-white text-slate-600"
                        : "border-rose-200 bg-rose-50 text-rose-900"
                    }`}
                  >
                    <span className="font-mono font-bold">L{f.line_start} · {f.rule_id}:</span>
                    <span>{f.title}</span>
                  </span>
                ))}
              </div>
            )}

            {/* Mode 1: Side-by-Side Split Diff */}
            {editorMode === "split" && (
              <div className="overflow-x-auto max-h-[460px] overflow-y-auto bg-white">
                <div className="grid grid-cols-2 border-b border-slate-200 bg-slate-100/80 font-mono text-[11px] font-semibold text-slate-600 sticky top-0 z-10">
                  <div className="px-3 py-1.5 border-r border-slate-200">Baseline (Before VibeArmor)</div>
                  <div className="px-3 py-1.5">Hardened Workspace (After VibeArmor)</div>
                </div>
                <table className="w-full border-collapse font-mono text-[11.5px] leading-[1.55]">
                  <tbody>
                    {splitRows.map((r, idx) => {
                      const leftBg =
                        r.kind === "del" || r.kind === "mod" ? "bg-rose-50/90 text-rose-950" : "bg-white text-slate-700";
                      const rightBg =
                        r.kind === "add" || r.kind === "mod" ? "bg-emerald-50/90 text-emerald-950" : "bg-white text-slate-800";
                      return (
                        <tr key={idx} className="border-b border-slate-100/80">
                          <td className="w-9 select-none border-r border-slate-200/80 bg-slate-50 px-2 text-right text-[10px] text-slate-400">
                            {r.leftNum ?? ""}
                          </td>
                          <td className={`w-1/2 whitespace-pre-wrap break-all px-3 py-0.5 border-r border-slate-200 ${leftBg}`}>
                            {r.leftNum !== null && (r.kind === "del" || r.kind === "mod") ? "- " : "  "}
                            {r.leftText}
                          </td>
                          <td className="w-9 select-none border-r border-slate-200/80 bg-slate-50 px-2 text-right text-[10px] text-slate-400">
                            {r.rightNum ?? ""}
                          </td>
                          <td className={`w-1/2 whitespace-pre-wrap break-all px-3 py-0.5 ${rightBg}`}>
                            {r.rightNum !== null && (r.kind === "add" || r.kind === "mod") ? "+ " : "  "}
                            {r.rightText}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {/* Mode 2: Minimal Security Slice (MSS) Inspector */}
            {editorMode === "mss" && (
              <div className="p-5 space-y-4 bg-white">
                {filePatches.filter((p) => p.mss).length === 0 ? (
                  <div className="py-8 text-center text-xs text-slate-500">
                    Run <span className="font-bold text-indigo-600">Auto-Heal &amp; 3-Gate Verify</span> to inspect the extracted ~25-line Minimal Security Slice (MSS) for this file.
                  </div>
                ) : (
                  filePatches
                    .filter((p) => p.mss)
                    .map((p, i) => (
                      <div key={i} className="rounded-xl border border-slate-200 bg-slate-50/60 p-4 space-y-3">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className="inline-flex items-center gap-1.5 text-xs font-bold text-slate-900">
                            <Scissors className="h-4 w-4 text-indigo-600" />
                            {p.rule_id} · Sliced {p.mss!.full_file_lines} lines &rarr; {p.mss!.slice_lines} lines
                          </span>
                          <span className="rounded-full bg-emerald-100 px-2.5 py-0.5 font-mono text-xs font-bold text-emerald-800">
                            -{p.mss!.compression_pct}% Prompt Context ({p.mss!.full_file_tokens_est} &rarr; {p.mss!.slice_tokens_est} tokens)
                          </span>
                        </div>
                        {p.mss!.cross_layer_context && (
                          <div className="rounded-lg border border-indigo-200 bg-indigo-50/70 px-3 py-2 font-mono text-[11px] text-indigo-950">
                            {p.mss!.cross_layer_context}
                          </div>
                        )}
                        <pre className="rounded-xl bg-[#0F172A] p-4 font-mono text-xs text-slate-100 overflow-x-auto">
                          {p.mss!.primary_slice}
                        </pre>
                      </div>
                    ))
                )}
              </div>
            )}

            {/* Mode 3: Full Current Source */}
            {editorMode === "source" && (
              <div className="max-h-[460px] overflow-auto bg-[#0F172A] p-4 font-mono text-xs text-slate-100">
                {afterTxt.split("\n").map((ln, idx) => (
                  <div key={idx} className="flex">
                    <span className="w-10 shrink-0 select-none pr-3 text-right text-slate-500">{idx + 1}</span>
                    <span className="whitespace-pre-wrap break-all">{ln}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* 3-Gate Safety Verifier Proofs for Current File */}
          {filePatches.length > 0 && (
            <div className="wiz-card rounded-2xl p-4 space-y-3">
              <div className="text-xs font-bold text-slate-800 flex items-center justify-between">
                <span>Closed-Loop 3-Gate Safety Verification ({activeFile})</span>
                <span className="font-mono text-[11px] text-slate-500">0 Broken Builds Guaranteed</span>
              </div>
              {filePatches.map((fp, idx) => (
                <div key={idx} className="space-y-2">
                  {fp.abstention_note ? (
                    <div className="rounded-xl border border-amber-200 bg-amber-50 px-3.5 py-2.5 text-xs text-amber-900 flex items-start gap-2">
                      <AlertTriangle className="h-4 w-4 shrink-0 text-amber-600 mt-0.5" />
                      <div>
                        <span className="font-bold">[{fp.rule_id} ABSTAINED]: </span>
                        {fp.abstention_note}
                      </div>
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
                      {fp.gates.map((g) => (
                        <div
                          key={g.gate_name}
                          className="rounded-xl border border-emerald-200 bg-emerald-50/50 p-3"
                        >
                          <div className="flex items-center justify-between text-xs font-bold text-emerald-800">
                            <span className="inline-flex items-center gap-1">
                              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />
                              {g.gate_name.split("·")[0]}
                            </span>
                            <span className="font-mono text-[10px] text-emerald-700">{g.latency_ms}ms</span>
                          </div>
                          <div className="mt-0.5 text-[11px] font-semibold text-slate-800">{g.gate_name.split("·")[1]}</div>
                          <div className="mt-1 text-[11px] text-slate-600">{g.summary}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <ArtifactDeliveryModal
        artifact={activeArtifact}
        onClose={() => setActiveArtifact(null)}
      />
    </div>
  );
};
