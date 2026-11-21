import React from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  AreaChart,
  Area,
} from "recharts";
import { AlertTriangle, FlaskConical, Terminal } from "lucide-react";
import { EvalResults } from "../types";

interface Props {
  data: EvalResults | null;
}

export const ResearchBenchmarkView: React.FC<Props> = ({ data }) => {
  if (!data) {
    return (
      <div className="wiz-card rounded-2xl p-10 text-center text-sm text-slate-500">
        Loading empirical Track 03 benchmark suites (<code className="font-mono">SecurityEval-30</code> +{" "}
        <code className="font-mono">VibeStack-28</code> + <code className="font-mono">FailureModes-6</code>)...
      </div>
    );
  }

  const barData = data.comparison_table.map((r) => ({
    name: r.system
      .replace("Bandit + npm/pip Audit (SAST)", "Bandit + Audit")
      .replace("Zero-Shot Local Qwen (Full-File)", "Zero-Shot Full Qwen")
      .replace("VibeArmor Symbolic-Only (No SLM)", "VA Symbolic-Only")
      .replace("VibeArmor Neuro-Symbolic (Full)", "VibeArmor Full"),
    "SecurityEval-30 Recall %": r.securityeval_recall_pct,
    "Verified Auto-Fix %": r.overall_verified_autofix_pct,
    "Broken Builds %": r.broken_builds_pct,
  }));

  const ablationChartData = data.context_scaling_ablation.map((a) => ({
    lines: `${a.file_lines} lines`,
    "Full-File Prompt Tokens": a.full_file_tokens,
    "VibeArmor MSS Tokens": a.mss_slice_tokens,
    reduction: a.token_reduction_pct,
  }));

  return (
    <div className="space-y-6">
      {/* Falsifiable Research Hypothesis Card */}
      <div className="wiz-card rounded-2xl p-6 border-l-4 border-l-indigo-600">
        <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-indigo-700">
          <FlaskConical className="h-4 w-4" />
          Track 03 · Falsifiable Research Hypothesis ({data.datasets.total_evaluated_cases} Total Non-Circular Cases)
        </div>
        <p className="mt-2 text-sm leading-relaxed text-slate-800 font-medium">{data.hypothesis}</p>
      </div>

      {/* Two Publication-Grade Recharts Figures */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Figure 1: Grouped BarChart */}
        <div className="wiz-card rounded-2xl p-5">
          <h3 className="text-sm font-bold text-slate-900">
            Fig 1 · 4-System Empirical Evaluation (Recall, Auto-Fix &amp; Regressions)
          </h3>
          <p className="text-xs text-slate-500 mb-4">
            External peer-reviewed <code className="rounded bg-slate-100 px-1">s2e-lab/SecurityEval-30</code> +{" "}
            <code className="rounded bg-slate-100 px-1">VibeStack-28</code>
          </p>
          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData} margin={{ top: 10, right: 12, left: -12, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: "#334155" }} />
                <YAxis unit="%" tick={{ fontSize: 11, fill: "#64748B" }} domain={[0, 100]} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#FFFFFF",
                    borderColor: "#E2E8F0",
                    borderRadius: "12px",
                    fontSize: "12px",
                  }}
                />
                <Legend wrapperStyle={{ fontSize: "11px" }} />
                <Bar dataKey="SecurityEval-30 Recall %" fill="#6366F1" radius={[5, 5, 0, 0]} />
                <Bar dataKey="Verified Auto-Fix %" fill="#10B981" radius={[5, 5, 0, 0]} />
                <Bar dataKey="Broken Builds %" fill="#F43F5E" radius={[5, 5, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Figure 2: Context-Scaling AreaChart */}
        <div className="wiz-card rounded-2xl p-5">
          <h3 className="text-sm font-bold text-slate-900">
            Fig 2 · Minimal Security Slicer (MSS) Prompt Scaling Curve
          </h3>
          <p className="text-xs text-slate-500 mb-4">
            Full-file token explosion (up to 3,749 tok) vs. constant ~56-token AST+SQL slice (-98.5% at 500 lines)
          </p>
          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={ablationChartData} margin={{ top: 10, right: 16, left: 0, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
                <XAxis dataKey="lines" tick={{ fontSize: 11, fill: "#334155" }} />
                <YAxis tick={{ fontSize: 11, fill: "#64748B" }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#FFFFFF",
                    borderColor: "#E2E8F0",
                    borderRadius: "12px",
                    fontSize: "12px",
                  }}
                />
                <Legend wrapperStyle={{ fontSize: "11px" }} />
                <Area
                  type="monotone"
                  dataKey="Full-File Prompt Tokens"
                  stroke="#E11D48"
                  fill="#FFE4E6"
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="VibeArmor MSS Tokens"
                  stroke="#059669"
                  fill="#D1FAE5"
                  strokeWidth={2.5}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Quantitative Matrix */}
      <div className="wiz-card rounded-2xl overflow-hidden">
        <div className="border-b border-slate-200 px-6 py-4">
          <h3 className="text-sm font-bold text-slate-900">Quantitative Benchmark Matrix (Reproducible via `python eval/run_eval.py`)</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-500 uppercase text-[11px] border-b border-slate-200">
              <tr>
                <th className="px-5 py-3">System / Baseline</th>
                <th className="px-5 py-3">SecurityEval-30 Recall</th>
                <th className="px-5 py-3">VibeStack-20 Recall</th>
                <th className="px-5 py-3">Verified Auto-Fix %</th>
                <th className="px-5 py-3">Hard-Neg False Positives</th>
                <th className="px-5 py-3">Broken Builds</th>
                <th className="px-5 py-3">Median Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200/80">
              {data.comparison_table.map((r) => {
                const isBest = r.system.includes("Neuro-Symbolic");
                return (
                  <tr key={r.system} className={isBest ? "bg-emerald-50/50 font-bold text-slate-900" : "text-slate-700"}>
                    <td className="px-5 py-3.5">{r.system}</td>
                    <td className="px-5 py-3.5 font-mono">{r.securityeval_recall_pct}%</td>
                    <td className="px-5 py-3.5 font-mono">{r.vibestack_recall_pct}%</td>
                    <td className="px-5 py-3.5 font-mono text-emerald-700">{r.overall_verified_autofix_pct}%</td>
                    <td className="px-5 py-3.5 font-mono">{r.false_positive_rate_pct}%</td>
                    <td className={`px-5 py-3.5 font-mono ${r.broken_builds_pct > 0 ? "text-rose-600 font-bold" : "text-emerald-700"}`}>
                      {r.broken_builds_pct}%
                    </td>
                    <td className="px-5 py-3.5 font-mono">{r.median_latency_ms} ms</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Honest Failure-Mode Abstentions + CLI/MCP Setup */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="wiz-card rounded-2xl p-5 lg:col-span-7">
          <div className="flex items-center justify-between gap-2 mb-3">
            <div>
              <h3 className="text-sm font-bold text-slate-900">
                Failure-Mode Boundaries: Where Naive AI Makes Security Worse
              </h3>
              <p className="text-xs text-slate-500">
                100% safe abstention ({data.failure_modes_6.safe_abstentions}/{data.failure_modes_6.total_boundary_cases}) on custom org-role matrices, runtime reflection, and TOCTOU state races
              </p>
            </div>
          </div>
          <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
            {data.failure_modes_6.cases.map((c) => (
              <div key={c.id} className="rounded-xl border border-amber-200 bg-amber-50/50 p-3">
                <div className="flex items-center justify-between gap-1">
                  <span className="font-mono text-[11px] font-bold text-slate-900">{c.id}</span>
                  <span className="inline-flex items-center gap-1 rounded bg-amber-100 px-1.5 py-0.5 font-mono text-[9.5px] font-bold text-amber-900">
                    <AlertTriangle className="h-3 w-3" /> {c.expected}
                  </span>
                </div>
                <div className="mt-1 text-xs font-semibold text-slate-800">{c.boundary_type}</div>
                <p className="mt-0.5 text-[11px] text-slate-600 line-clamp-2">{c.reason}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="wiz-card rounded-2xl p-5 lg:col-span-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-sm font-bold text-slate-900 mb-1">
              <Terminal className="h-4 w-4 text-indigo-600" /> Developer CLI, Pre-Commit Guard &amp; Cursor MCP
            </div>
            <p className="text-xs text-slate-500 mb-3">
              Zero file-race collisions: runs as a &lt;180ms Git pre-commit fast-path or post-turn IDE MCP tool
            </p>
            <pre className="rounded-xl bg-[#0F172A] p-4 font-mono text-[11.5px] text-slate-100 leading-relaxed overflow-x-auto">{`# Install Git pre-commit + .cursor/mcp.json
$ vibearmor init .

# <35ms Cross-Layer Scan (0 LLM calls)
$ vibearmor scan .

# Closed-Loop Auto-Heal + 3-Gate Verify
$ vibearmor fix .

# Debounced 800ms background file watcher
$ vibearmor watch . --debounce 800`}</pre>
          </div>
          <div className="mt-3 pt-3 border-t border-slate-100 text-[11px] text-slate-500 flex justify-between">
            <span>Team NeXGen Coder&apos;s</span>
            <span>Syed Suhail · Alam Nawaz Sha · Vivek Gowda</span>
          </div>
        </div>
      </div>
    </div>
  );
};
