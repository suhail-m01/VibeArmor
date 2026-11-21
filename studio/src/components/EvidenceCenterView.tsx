import React, { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BookOpen,
  CheckCircle2,
  Cpu,
  GitBranch,
  Layers,
  Loader2,
  Lock,
  Play,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  XCircle,
} from "lucide-react";

interface RagHit {
  doc_id: string;
  cwe: string;
  owasp_category: string;
  capec_id: string;
  capec_attack_pattern: string;
  title: string;
  similarity_score: number;
  guidance_summary: string;
  recommended_pattern: string;
  verified_example: string;
}

interface EvidenceNode {
  id: string;
  kind: string;
  label: string;
  status: string;
}

interface EvidenceEdge {
  source: string;
  target: string;
  relation: string;
}

interface EvidenceItem {
  finding_id: string;
  rule_id: string;
  title: string;
  severity: string;
  pillar: string;
  cwe: string;
  file_path: string;
  line_start: number;
  final_status: string;
  test_status: string;
  rescan_status: string;
  exploit_status: string;
  evidence_package: {
    finding_id: string;
    rule_id: string;
    vulnerability: string;
    severity: string;
    cwe: string;
    owasp_category: string;
    capec_id: string;
    attack_pattern: string;
    source_location: string;
    code_context_masked: string;
    ast_evidence: Record<string, unknown>;
    data_flow_slice: string[];
    retrieved_security_evidence: RagHit[];
    recommended_pattern: string;
    remediation_constraints: string[];
    rag_backend: string;
    retrieval_latency_ms: number;
  };
  evidence_graph: {
    nodes: EvidenceNode[];
    edges: EvidenceEdge[];
    why_vulnerable: {
      headline: string;
      data_flow_steps: string[];
      blast_radius: string;
      ast_summary: string;
    };
    why_verified: Array<{ check: string; status: string; detail: string }>;
  };
  agent_steps: Array<{ agent: string; role: string; status: string; detail: string }>;
}

interface PolicyConfig {
  block_critical: boolean;
  block_high: boolean;
  block_medium: boolean;
  require_verification: boolean;
  require_tests: boolean;
  allow_unverified_ai_patch: boolean;
  secrets_block_commit: boolean;
}

interface EvidenceBundleResponse {
  project_id: string;
  project_name: string;
  orchestrator: string;
  rag_backend: string;
  rag_corpus_size: number;
  avg_rag_latency_ms: number;
  bundle_latency_ms: number;
  control_center: {
    severity_open: Record<string, number>;
    verified_fixes: number;
    rejected_fixes: number;
    abstained_policy: number;
    open_vulnerabilities: number;
    scan_latency_ms: number;
    avg_mss_compression_pct: number;
  };
  policy_evaluation: {
    verdict: "PASS" | "BLOCK";
    passed: boolean;
    policy: PolicyConfig;
    violations: string[];
    counts: Record<string, number>;
  };
  ab_comparison: {
    methodology: string;
    baseline_raw_llm: {
      label: string;
      patch_accepted_without_proof_pct: number;
      syntax_or_test_breakage_pct: number;
      residual_vulnerability_remained_pct: number;
      secret_or_full_file_collateral_pct: number;
      independent_verification_gates: number;
    };
    vibearmor_evidence_agentic: {
      label: string;
      active_workspace_actionable: number;
      active_workspace_verified: number;
      active_workspace_rejected: number;
      syntax_or_test_breakage_committed_pct: number;
      avg_mss_token_reduction_pct: number;
      independent_verification_gates: number;
    };
  };
  items: EvidenceItem[];
}

interface Props {
  projectId: string;
  onGoToDiffStep?: () => void;
}

export const EvidenceCenterView: React.FC<Props> = ({ projectId, onGoToDiffStep }) => {
  const [bundle, setBundle] = useState<EvidenceBundleResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [policyBusy, setPolicyBusy] = useState<boolean>(false);

  const [agenticRunning, setAgenticRunning] = useState<boolean>(false);
  const [agenticLiveResult, setAgenticLiveResult] = useState<{
    orchestrator: string;
    findings_processed: number;
    verified_count: number;
    total_latency_ms: number;
  } | null>(null);

  const [ragQuery, setRagQuery] = useState<string>("");
  const [ragSearching, setRagSearching] = useState<boolean>(false);
  const [ragCustomHits, setRagCustomHits] = useState<RagHit[] | null>(null);

  async function fetchEvidence(pid: string) {
    setLoading(true);
    try {
      const res = await fetch(`/api/projects/${encodeURIComponent(pid)}/evidence`);
      if (res.ok) {
        const data: EvidenceBundleResponse = await res.json();
        setBundle(data);
        if (data.items.length > 0 && (!selectedId || !data.items.some((x) => x.finding_id === selectedId))) {
          setSelectedId(data.items[0].finding_id);
        }
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    setAgenticLiveResult(null);
    fetchEvidence(projectId);
  }, [projectId]);

  async function handleTogglePolicy(field: keyof PolicyConfig) {
    if (!bundle) return;
    setPolicyBusy(true);
    try {
      const currentPol = bundle.policy_evaluation.policy;
      const updated: PolicyConfig = {
        ...currentPol,
        [field]: !currentPol[field],
        allow_unverified_ai_patch: false,
      };
      await fetch("/api/policy", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(updated),
      });
      await fetchEvidence(projectId);
    } finally {
      setPolicyBusy(false);
    }
  }

  async function handleRunLiveLangGraph() {
    setAgenticRunning(true);
    try {
      const res = await fetch(`/api/projects/${encodeURIComponent(projectId)}/agentic-run`, {
        method: "POST",
      });
      if (res.ok) {
        const d = await res.json();
        setAgenticLiveResult(d);
      }
    } finally {
      setAgenticRunning(false);
    }
  }

  async function handleSearchRag(e: React.FormEvent) {
    e.preventDefault();
    if (!ragQuery.trim()) {
      setRagCustomHits(null);
      return;
    }
    setRagSearching(true);
    try {
      const res = await fetch("/api/rag/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: ragQuery.trim(), top_k: 3 }),
      });
      if (res.ok) {
        const d = await res.json();
        setRagCustomHits(d.results || []);
      }
    } finally {
      setRagSearching(false);
    }
  }

  if (loading && !bundle) {
    return (
      <div className="wiz-card rounded-2xl p-12 flex items-center justify-center gap-2.5 text-sm font-semibold text-slate-600">
        <Loader2 className="h-5 w-5 animate-spin text-indigo-600" />
        Building FAISS Security RAG Evidence Packages &amp; 12-Node Evidence Graphs...
      </div>
    );
  }

  if (!bundle) return null;

  const cc = bundle.control_center;
  const pol = bundle.policy_evaluation;
  const selectedItem = bundle.items.find((x) => x.finding_id === selectedId) || bundle.items[0] || null;

  function statusBadge(st: string) {
    if (st === "VERIFIED" || st === "PASS") {
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-emerald-100 px-2.5 py-0.5 text-[10.5px] font-extrabold text-emerald-800">
          <CheckCircle2 className="h-3 w-3" /> {st}
        </span>
      );
    }
    if (st === "REJECTED" || st === "FAIL" || st === "BLOCK") {
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-rose-100 px-2.5 py-0.5 text-[10.5px] font-extrabold text-rose-800">
          <XCircle className="h-3 w-3" /> {st}
        </span>
      );
    }
    if (st.startsWith("ABSTAINED")) {
      return (
        <span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2.5 py-0.5 text-[10.5px] font-extrabold text-amber-900">
          <AlertTriangle className="h-3 w-3" /> ABSTAINED
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-slate-200 px-2.5 py-0.5 text-[10.5px] font-bold text-slate-700">
        {st}
      </span>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Control Center & Core Architectural Principle */}
      <div className="wiz-card rounded-2xl p-6 space-y-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between border-b border-slate-100 pb-4">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full bg-indigo-600 px-3 py-0.5 font-mono text-[11px] font-extrabold text-white">
                VIBEARMOR 3.5 · EVIDENCE-DRIVEN AGENTIC SECURITY
              </span>
              <span className="rounded-full bg-slate-900 px-2.5 py-0.5 font-mono text-[11px] font-bold text-emerald-300">
                {bundle.rag_backend} ({bundle.rag_corpus_size} docs) · {bundle.orchestrator}
              </span>
            </div>
            <h2 className="mt-2 text-lg font-extrabold text-slate-900">
              &ldquo;The AI proposes the fix. VibeArmor decides whether the fix is safe.&rdquo;
            </h2>
            <p className="mt-0.5 text-xs text-slate-600">
              Workspace: <strong>{bundle.project_name}</strong> &middot; AI proposals remain unverified until deterministic AST rescan, compile/test &amp; exploit checks pass.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={handleRunLiveLangGraph}
              disabled={agenticRunning}
              className="inline-flex items-center gap-1.5 rounded-xl bg-indigo-600 px-4 py-2.5 text-xs font-extrabold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-60 cursor-pointer"
            >
              {agenticRunning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              Execute Live 4-Agent LangGraph Run
            </button>
            {onGoToDiffStep && (
              <button
                type="button"
                onClick={onGoToDiffStep}
                className="inline-flex items-center gap-1.5 rounded-xl border border-slate-300 bg-white px-3.5 py-2.5 text-xs font-bold text-slate-800 hover:bg-slate-50 cursor-pointer"
              >
                Open Surgical Diffs &rarr;
              </button>
            )}
          </div>
        </div>

        {agenticLiveResult && (
          <div className="rounded-xl border border-emerald-300 bg-emerald-50/80 px-4 py-3 flex flex-wrap items-center justify-between gap-2 text-xs text-emerald-950">
            <div className="flex items-center gap-2 font-bold">
              <CheckCircle2 className="h-4 w-4 text-emerald-600 shrink-0" />
              <span>
                Live <code className="font-mono">{agenticLiveResult.orchestrator}</code> completed across{" "}
                <strong>{agenticLiveResult.findings_processed}</strong> finding(s) &rarr;{" "}
                <strong>{agenticLiveResult.verified_count}</strong> deterministically <code className="font-mono">VERIFIED</code> in{" "}
                <strong>{agenticLiveResult.total_latency_ms} ms</strong>!
              </span>
            </div>
          </div>
        )}

        {/* 6 Metric KPI Tiles */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          <div className="rounded-xl border border-rose-200 bg-rose-50/60 p-3">
            <div className="text-[10.5px] font-bold uppercase text-rose-700">Open Critical / High</div>
            <div className="mt-1 text-xl font-extrabold text-rose-900">
              {(cc.severity_open.CRITICAL || 0) + (cc.severity_open.HIGH || 0)}
              <span className="ml-1.5 text-xs font-semibold text-rose-600">
                ({cc.open_vulnerabilities} open)
              </span>
            </div>
          </div>

          <div className="rounded-xl border border-emerald-200 bg-emerald-50/60 p-3">
            <div className="text-[10.5px] font-bold uppercase text-emerald-700">Verified Safe Fixes</div>
            <div className="mt-1 text-xl font-extrabold text-emerald-900">
              {cc.verified_fixes} <span className="text-xs font-semibold text-emerald-700">/ {bundle.items.length}</span>
            </div>
          </div>

          <div className="rounded-xl border border-amber-200 bg-amber-50/60 p-3">
            <div className="text-[10.5px] font-bold uppercase text-amber-800">Rejected / Abstained</div>
            <div className="mt-1 text-xl font-extrabold text-amber-950">
              {cc.rejected_fixes} <span className="text-xs font-normal text-amber-800">rej</span> &middot;{" "}
              {cc.abstained_policy} <span className="text-xs font-normal text-amber-800">abst</span>
            </div>
          </div>

          <div className="rounded-xl border border-indigo-200 bg-indigo-50/60 p-3">
            <div className="text-[10.5px] font-bold uppercase text-indigo-700">FAISS RAG Latency</div>
            <div className="mt-1 text-xl font-extrabold text-indigo-950">{bundle.avg_rag_latency_ms} ms</div>
          </div>

          <div className="rounded-xl border border-sky-200 bg-sky-50/60 p-3">
            <div className="text-[10.5px] font-bold uppercase text-sky-700">MSS Token Slicing</div>
            <div className="mt-1 text-xl font-extrabold text-sky-950">-{cc.avg_mss_compression_pct}%</div>
          </div>

          <div
            className={`rounded-xl border p-3 ${
              pol.passed ? "border-emerald-300 bg-emerald-50" : "border-rose-300 bg-rose-50"
            }`}
          >
            <div className="text-[10.5px] font-bold uppercase text-slate-700">Policy Gate Verdict</div>
            <div className="mt-1 flex items-center gap-1.5 text-lg font-extrabold">
              {pol.passed ? (
                <span className="text-emerald-800 flex items-center gap-1">
                  <ShieldCheck className="h-4 w-4" /> PASS
                </span>
              ) : (
                <span className="text-rose-800 flex items-center gap-1">
                  <ShieldAlert className="h-4 w-4" /> BLOCK
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Main Split View */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* LEFT COLUMN */}
        <div className="lg:col-span-4 space-y-5">
          {/* Findings Selector */}
          <div className="wiz-card rounded-2xl p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
              <span className="text-xs font-extrabold uppercase tracking-wider text-slate-700">
                Evidence Packages ({bundle.items.length})
              </span>
              <span className="text-[11px] text-slate-500">Select to inspect graph</span>
            </div>

            {bundle.items.length === 0 ? (
              <div className="rounded-xl bg-emerald-50 p-4 text-xs font-semibold text-emerald-900">
                Zero vulnerabilities detected in this workspace!
              </div>
            ) : (
              <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                {bundle.items.map((it) => {
                  const active = selectedItem?.finding_id === it.finding_id;
                  return (
                    <button
                      key={it.finding_id}
                      type="button"
                      onClick={() => setSelectedId(it.finding_id)}
                      className={`w-full text-left rounded-xl border p-3 transition cursor-pointer ${
                        active
                          ? "border-indigo-500 bg-indigo-50/70 shadow-xs"
                          : "border-slate-200 bg-white hover:bg-slate-50"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-[11px] font-extrabold text-indigo-700">
                          {it.rule_id} &middot; {it.cwe}
                        </span>
                        {statusBadge(it.final_status)}
                      </div>
                      <div className="mt-1 text-xs font-bold text-slate-900 line-clamp-1">{it.title}</div>
                      <div className="mt-0.5 font-mono text-[10.5px] text-slate-500 truncate">
                        {it.file_path}:{it.line_start}
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Deterministic Security Policy Engine (`security_policy.yaml`) */}
          <div className="wiz-card rounded-2xl p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
              <div className="flex items-center gap-1.5 text-xs font-extrabold text-slate-900">
                <Lock className="h-3.5 w-3.5 text-indigo-600" />
                Policy Engine (<code className="font-mono text-[11px]">security_policy.yaml</code>)
              </div>
              {statusBadge(pol.verdict)}
            </div>

            <div className="space-y-2">
              {(
                [
                  ["block_critical", "Block Critical Vulnerabilities"],
                  ["block_high", "Block High Vulnerabilities"],
                  ["require_verification", "Require 3-Gate Patch Verification"],
                  ["require_tests", "Require Syntax & Test Gate Pass"],
                  ["secrets_block_commit", "Hard-Block Exposed Secrets"],
                ] as Array<[keyof PolicyConfig, string]>
              ).map(([key, label]) => (
                <label
                  key={key}
                  className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50/60 px-3 py-2 text-xs font-semibold text-slate-800 cursor-pointer"
                >
                  <span>{label}</span>
                  <input
                    type="checkbox"
                    disabled={policyBusy}
                    checked={Boolean(pol.policy[key])}
                    onChange={() => handleTogglePolicy(key)}
                    className="h-4 w-4 accent-indigo-600 cursor-pointer"
                  />
                </label>
              ))}
            </div>

            {pol.violations.length > 0 && (
              <div className="rounded-xl border border-rose-200 bg-rose-50 p-3 space-y-1">
                <div className="text-[11px] font-extrabold text-rose-900">Active Policy Block Reasons:</div>
                {pol.violations.map((vr, i) => (
                  <div key={i} className="text-[11px] text-rose-800">
                    &bull; {vr}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Interactive FAISS Security RAG Explorer */}
          <div className="wiz-card rounded-2xl p-4 space-y-3">
            <div className="flex items-center gap-1.5 text-xs font-extrabold text-slate-900 border-b border-slate-100 pb-2.5">
              <BookOpen className="h-3.5 w-3.5 text-indigo-600" />
              Query FAISS Security RAG Knowledge Base
            </div>
            <form onSubmit={handleSearchRag} className="flex gap-1.5">
              <input
                type="text"
                value={ragQuery}
                onChange={(e) => setRagQuery(e.target.value)}
                placeholder="e.g. SQL injection parameterized, Supabase RLS..."
                className="flex-1 rounded-xl border border-slate-300 bg-white px-3 py-2 text-xs text-slate-900 focus:border-indigo-600 focus:outline-none"
              />
              <button
                type="submit"
                disabled={ragSearching}
                className="rounded-xl bg-slate-900 px-3 py-2 text-xs font-bold text-white hover:bg-indigo-700 cursor-pointer"
              >
                {ragSearching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
              </button>
            </form>
            {ragCustomHits && (
              <div className="space-y-2 max-h-56 overflow-y-auto">
                {ragCustomHits.map((h) => (
                  <div key={h.doc_id} className="rounded-xl border border-indigo-200 bg-indigo-50/50 p-2.5 space-y-1">
                    <div className="flex items-center justify-between text-[10.5px] font-mono font-bold text-indigo-800">
                      <span>
                        {h.cwe} &middot; {h.capec_id}
                      </span>
                      <span>sim={h.similarity_score.toFixed(3)}</span>
                    </div>
                    <div className="text-xs font-bold text-slate-900">{h.title}</div>
                    <div className="font-mono text-[10.5px] text-emerald-900 bg-white rounded px-2 py-1 border border-indigo-100">
                      {h.recommended_pattern}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* RIGHT COLUMN */}
        <div className="lg:col-span-8 space-y-5">
          {selectedItem ? (
            <>
              {/* 1. WHY IS THIS VULNERABLE? + DATA-FLOW / AST EVIDENCE */}
              <div className="wiz-card rounded-2xl p-5 space-y-4">
                <div className="flex flex-wrap items-start justify-between gap-2 border-b border-slate-100 pb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-rose-100 px-2 py-0.5 font-mono text-[11px] font-extrabold text-rose-800">
                        {selectedItem.severity} &middot; {selectedItem.cwe}
                      </span>
                      <span className="font-mono text-xs font-bold text-slate-600">
                        {selectedItem.evidence_package.source_location}
                      </span>
                    </div>
                    <h3 className="mt-1.5 text-base font-extrabold text-slate-900">
                      1. Why Is This Vulnerable? &mdash; {selectedItem.evidence_graph.why_vulnerable.headline}
                    </h3>
                  </div>
                  {statusBadge(selectedItem.final_status)}
                </div>

                <div className="rounded-xl bg-slate-50 border border-slate-200 p-3.5 space-y-1.5 text-xs text-slate-700">
                  <div className="font-semibold text-slate-900">
                    {selectedItem.evidence_graph.why_vulnerable.ast_summary}
                  </div>
                  {selectedItem.evidence_graph.why_vulnerable.data_flow_steps.map((step, idx) => (
                    <div key={idx} className="font-mono text-[11px] text-indigo-950">
                      {idx + 1}. {step}
                    </div>
                  ))}
                  <div className="text-[11px] text-rose-800 pt-1">
                    <strong>Blast Radius:</strong> {selectedItem.evidence_graph.why_vulnerable.blast_radius}
                  </div>
                </div>

                {/* Visual 12-Node Evidence Graph */}
                <div className="space-y-2">
                  <div className="text-[11px] font-extrabold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                    <GitBranch className="h-3.5 w-3.5 text-indigo-600" />
                    Interactive 12-Node Security Evidence Graph
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
                    {selectedItem.evidence_graph.nodes.map((nd) => (
                      <div
                        key={nd.id}
                        className={`rounded-xl border p-2.5 space-y-0.5 ${
                          nd.status === "VERIFIED" || nd.status === "PASS"
                            ? "border-emerald-300 bg-emerald-50/60"
                            : nd.status === "DETECTED" || nd.status === "FAIL" || nd.status === "REJECTED"
                            ? "border-rose-300 bg-rose-50/60"
                            : nd.status === "GROUNDED"
                            ? "border-indigo-200 bg-indigo-50/60"
                            : "border-slate-200 bg-white"
                        }`}
                      >
                        <div className="flex items-center justify-between text-[10px] font-mono uppercase font-bold text-slate-500">
                          <span>{nd.kind.replace(/_/g, " ")}</span>
                          <span className="text-slate-800">{nd.status}</span>
                        </div>
                        <div className="text-xs font-extrabold text-slate-900 line-clamp-2">{nd.label}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Masked AST Minimal Security Slice */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-[11px] font-bold text-slate-700">
                    <span className="flex items-center gap-1.5">
                      <Layers className="h-3.5 w-3.5 text-indigo-600" />
                      Tree-sitter / AST Minimal Security Slice (Secrets Auto-Masked)
                    </span>
                  </div>
                  <pre className="max-h-44 overflow-y-auto rounded-xl bg-[#0F172A] p-3.5 font-mono text-[11px] text-slate-100 leading-relaxed">
                    {selectedItem.evidence_package.code_context_masked}
                  </pre>
                </div>
              </div>

              {/* 2. SECURITY EVIDENCE PACKAGE (FAISS RAG GROUNDING) */}
              <div className="wiz-card rounded-2xl p-5 space-y-3.5">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-2.5">
                  <h3 className="text-sm font-extrabold text-slate-900 flex items-center gap-2">
                    <Sparkles className="h-4 w-4 text-indigo-600" />
                    2. Grounded Security Evidence Package ({selectedItem.evidence_package.rag_backend})
                  </h3>
                  <span className="font-mono text-[11px] text-indigo-700 font-bold">
                    Retrieved in {selectedItem.evidence_package.retrieval_latency_ms} ms
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-xs">
                  <div className="rounded-xl bg-slate-50 border border-slate-200 p-2.5">
                    <div className="text-[10px] font-bold uppercase text-slate-500">OWASP Classification</div>
                    <div className="font-bold text-slate-900 mt-0.5">
                      {selectedItem.evidence_package.owasp_category}
                    </div>
                  </div>
                  <div className="rounded-xl bg-slate-50 border border-slate-200 p-2.5">
                    <div className="text-[10px] font-bold uppercase text-slate-500">CAPEC Attack Pattern</div>
                    <div className="font-bold text-slate-900 mt-0.5">
                      {selectedItem.evidence_package.capec_id}: {selectedItem.evidence_package.attack_pattern}
                    </div>
                  </div>
                  <div className="rounded-xl bg-emerald-50 border border-emerald-200 p-2.5">
                    <div className="text-[10px] font-bold uppercase text-emerald-700">Verified Minimal Pattern</div>
                    <div className="font-mono text-[11px] font-bold text-emerald-950 mt-0.5">
                      {selectedItem.evidence_package.recommended_pattern}
                    </div>
                  </div>
                </div>

                <div className="rounded-xl border border-indigo-200 bg-indigo-50/50 p-3 space-y-1">
                  <div className="text-[11px] font-extrabold text-indigo-950">
                    Strict Remediation Constraints Passed to Remediation Agent:
                  </div>
                  {selectedItem.evidence_package.remediation_constraints.map((c, idx) => (
                    <div key={idx} className="text-[11px] text-indigo-900">
                      &bull; {c}
                    </div>
                  ))}
                </div>
              </div>

              {/* 3. WHY IS THIS FIX VERIFIED? (4-AGENT LANGGRAPH TRACE + 3 DETERMINISTIC GATES) */}
              <div className="wiz-card rounded-2xl p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-2.5">
                  <h3 className="text-sm font-extrabold text-slate-900 flex items-center gap-2">
                    <Cpu className="h-4 w-4 text-emerald-600" />
                    3. Why Is This Fix Verified? &mdash; 4-Agent LangGraph &amp; Deterministic Decision Engine
                  </h3>
                  {statusBadge(selectedItem.final_status)}
                </div>

                <div className="divide-y divide-slate-200/80 rounded-xl border border-slate-200 bg-slate-50/60 px-3.5 py-1">
                  {selectedItem.evidence_graph.why_verified.map((chk, idx) => (
                    <div key={idx} className="flex flex-wrap items-center justify-between gap-2 py-2 text-xs">
                      <span className="font-bold text-slate-800">{chk.check}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] text-slate-600">{chk.detail}</span>
                        {statusBadge(chk.status)}
                      </div>
                    </div>
                  ))}
                </div>

                {/* 4-Agent Pipeline Stepper */}
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-2">
                  {selectedItem.agent_steps.map((ag, idx) => (
                    <div key={ag.agent} className="rounded-xl border border-slate-200 bg-white p-2.5 space-y-1">
                      <div className="flex items-center justify-between text-[10px] font-mono font-extrabold text-indigo-700">
                        <span>
                          STEP {idx + 1} {idx < 3 ? <ArrowRight className="inline h-3 w-3" /> : null}
                        </span>
                        <span>{ag.status}</span>
                      </div>
                      <div className="text-xs font-extrabold text-slate-900">{ag.agent}</div>
                      <div className="text-[10.5px] text-slate-600 leading-snug">{ag.detail}</div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : null}

          {/* 4. A/B BENCHMARK */}
          <div className="wiz-card rounded-2xl p-5 space-y-3">
            <div className="flex items-center gap-2 border-b border-slate-100 pb-2.5">
              <Activity className="h-4 w-4 text-indigo-600" />
              <h3 className="text-sm font-extrabold text-slate-900">
                Research Evaluation · Baseline Direct LLM Patch vs. VibeArmor Evidence-Driven Loop
              </h3>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div className="rounded-xl border border-rose-200 bg-rose-50/50 p-3.5 space-y-1.5">
                <div className="font-extrabold text-rose-900">{bundle.ab_comparison.baseline_raw_llm.label}</div>
                <div className="text-[11px] text-rose-800">
                  &bull; Unverified Patches Accepted:{" "}
                  <strong>{bundle.ab_comparison.baseline_raw_llm.patch_accepted_without_proof_pct}%</strong>
                </div>
                <div className="text-[11px] text-rose-800">
                  &bull; Residual Flaw Rate:{" "}
                  <strong>{bundle.ab_comparison.baseline_raw_llm.residual_vulnerability_remained_pct}%</strong> &middot;
                  Syntax Breakage: <strong>{bundle.ab_comparison.baseline_raw_llm.syntax_or_test_breakage_pct}%</strong>
                </div>
                <div className="text-[11px] text-rose-800">
                  &bull; Independent Verification Gates:{" "}
                  <strong>{bundle.ab_comparison.baseline_raw_llm.independent_verification_gates}</strong>
                </div>
              </div>

              <div className="rounded-xl border border-emerald-300 bg-emerald-50/60 p-3.5 space-y-1.5">
                <div className="font-extrabold text-emerald-950">
                  {bundle.ab_comparison.vibearmor_evidence_agentic.label}
                </div>
                <div className="text-[11px] text-emerald-900">
                  &bull; Active Workspace Verified:{" "}
                  <strong>
                    {bundle.ab_comparison.vibearmor_evidence_agentic.active_workspace_verified} /{" "}
                    {bundle.ab_comparison.vibearmor_evidence_agentic.active_workspace_actionable}
                  </strong>
                </div>
                <div className="text-[11px] text-emerald-900">
                  &bull; Syntax/Test Breakage Committed:{" "}
                  <strong>{bundle.ab_comparison.vibearmor_evidence_agentic.syntax_or_test_breakage_committed_pct}%</strong>
                </div>
                <div className="text-[11px] text-emerald-900">
                  &bull; Avg MSS Token Reduction:{" "}
                  <strong>-{bundle.ab_comparison.vibearmor_evidence_agentic.avg_mss_token_reduction_pct}%</strong> &middot;
                  Gates: <strong>{bundle.ab_comparison.vibearmor_evidence_agentic.independent_verification_gates}</strong>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
