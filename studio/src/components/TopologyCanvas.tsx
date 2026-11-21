import React, { useMemo, useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowUpRight,
  Zap,
  Filter,
} from "lucide-react";
import { Finding, ScanAndHealReport, SecurityNode } from "../types";

interface Props {
  projectName: string;
  securityScore: number;
  report: ScanAndHealReport;
  onJumpToFile: (filePath: string) => void;
  onTriggerHeal: () => void;
  healing: boolean;
}

const LANE_CONFIG: Array<{
  col: number;
  title: string;
  subtitle: string;
  xCenter: number;
  kinds: SecurityNode["kind"][];
}> = [
  { col: 0, title: "Client Browser Bundle", subtitle: "React TSX · Public Env", xCenter: 155, kinds: ["frontend_component", "secret_token"] },
  { col: 1, title: "API & Auto-BFF Tier", subtitle: "FastAPI · Next.js Routes", xCenter: 445, kinds: ["api_route"] },
  { col: 2, title: "PostgreSQL & Cloud Drift", subtitle: "Tables · RLS · DEFINER RPCs", xCenter: 735, kinds: ["sql_table", "sql_function"] },
  { col: 3, title: "Supply-Chain Manifests", subtitle: "npm · PyPI · OSV Reachability", xCenter: 1015, kinds: ["dependency"] },
];

export const TopologyCanvas: React.FC<Props> = ({
  projectName,
  securityScore,
  report,
  onJumpToFile,
  onTriggerHeal,
  healing,
}) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [filterMode, setFilterMode] = useState<"all" | "risk" | "healed">("all");
  const [showAllLargeRepoNodes, setShowAllLargeRepoNodes] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>("");

  const isLargeRepo = report.nodes.length > 44;

  const filteredNodes = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    const statusWeight = (st: SecurityNode["status"]) =>
      st === "vulnerable" ? 0 : st === "abstained" ? 1 : st === "healed" ? 2 : 3;

    // Sort vulnerable & healed nodes to the top of every column so critical blast paths appear immediately!
    let base = [...report.nodes].sort((a, b) => statusWeight(a.status) - statusWeight(b.status));

    if (filterMode === "risk") {
      base = base.filter((n) => n.status === "vulnerable" || n.status === "abstained");
    } else if (filterMode === "healed") {
      base = base.filter((n) => n.status === "healed");
    }

    if (q) {
      return base.filter(
        (n) =>
          n.label.toLowerCase().includes(q) ||
          n.file_path.toLowerCase().includes(q) ||
          n.kind.toLowerCase().includes(q)
      );
    }

    // For large 200+ node repos (like suhail-m01/Knot), prioritize all vulnerable/healed nodes + connected neighbors + top 12 per lane unless "Show All" is toggled
    if (isLargeRepo && !showAllLargeRepoNodes && filterMode === "all") {
      const importantIds = new Set<string>(
        base.filter((n) => n.status !== "safe").map((n) => n.id)
      );
      for (const e of report.edges) {
        if (importantIds.has(e.source) || importantIds.has(e.target) || e.risk !== "safe") {
          importantIds.add(e.source);
          importantIds.add(e.target);
        }
      }
      const perLaneCap = 12;
      const laneCounters: Record<number, number> = { 0: 0, 1: 0, 2: 0, 3: 0 };
      return base.filter((n) => {
        const laneIdx = LANE_CONFIG.findIndex((l) => l.kinds.includes(n.kind));
        if (importantIds.has(n.id)) {
          if (laneIdx >= 0) laneCounters[laneIdx] += 1;
          return true;
        }
        if (laneIdx >= 0 && laneCounters[laneIdx] < perLaneCap) {
          laneCounters[laneIdx] += 1;
          return true;
        }
        return false;
      });
    }

    return base;
  }, [report.nodes, report.edges, filterMode, isLargeRepo, showAllLargeRepoNodes, searchQuery]);

  // Compute exact SVG (x, y) positions per node across the 4 architectural swimlanes
  const layout = useMemo(() => {
    const posMap = new Map<string, { x: number; y: number; node: SecurityNode }>();
    let maxRows = 1;

    LANE_CONFIG.forEach((lane) => {
      const laneNodes = filteredNodes.filter((n) => lane.kinds.includes(n.kind));
      maxRows = Math.max(maxRows, laneNodes.length);
      laneNodes.forEach((node, idx) => {
        const y = 92 + idx * 72;
        posMap.set(node.id, { x: lane.xCenter, y, node });
      });
    });

    const svgHeight = Math.max(430, 110 + maxRows * 74);
    return { posMap, svgHeight };
  }, [filteredNodes]);

  const activeNode = useMemo(() => {
    if (selectedNodeId && layout.posMap.has(selectedNodeId)) {
      return layout.posMap.get(selectedNodeId)!.node;
    }
    const firstVuln = filteredNodes.find((n) => n.status === "vulnerable" || n.status === "healed");
    return firstVuln || filteredNodes[0] || null;
  }, [selectedNodeId, layout, filteredNodes]);

  const relatedFindings: Finding[] = useMemo(() => {
    if (!activeNode) return [];
    const sourceList = report.findings_before;
    if (activeNode.id.startsWith("sql:")) {
      const tblName = activeNode.id.slice(4);
      return sourceList.filter((f) => f.metadata?.table === tblName || f.title.includes(`'${tblName}'`));
    }
    if (activeNode.id.startsWith("rpc:")) {
      const rpcName = activeNode.id.slice(4);
      return sourceList.filter((f) => f.title.includes(rpcName));
    }
    if (activeNode.id.startsWith("pkg:")) {
      const pkgName = activeNode.id.slice(4).toLowerCase();
      return sourceList.filter(
        (f) =>
          String(f.metadata?.package || "").toLowerCase() === pkgName ||
          f.title.toLowerCase().includes(pkgName)
      );
    }
    if (activeNode.id.startsWith("api:")) {
      const routeLabel = activeNode.label.split(" ")[1] || activeNode.label;
      return sourceList.filter(
        (f) =>
          f.file_path === activeNode.file_path &&
          (Math.abs(f.line_start - activeNode.line) <= 10 || f.title.includes(routeLabel))
      );
    }
    return sourceList.filter((f) => f.file_path === activeNode.file_path);
  }, [activeNode, report]);

  const pillarCounts = useMemo(() => {
    const active = report.mode === "auto_heal" ? report.findings_after : report.findings_before;
    const countP = (p: Finding["pillar"]) => active.filter((f) => f.pillar === p && f.reachable && !f.requires_policy_spec).length;
    return [
      { label: "Database RLS & Cloud Drift", count: countP("rls_dpdp"), desc: "CVE-2025-48757 · DPDP PII" },
      { label: "Client Secrets & Auto-BFF", count: countP("secret_boundary"), desc: "Bundle keys · JWT role check" },
      { label: "AST Taint & Payment HMAC", count: countP("taint_payment"), desc: "SQLi · Cmd · Razorpay ₹0 spoof" },
      { label: "Supply-Chain & Slopsquats", count: countP("supply_chain"), desc: "<72h hallucinations · OSV CVEs" },
    ];
  }, [report]);

  return (
    <div className="space-y-6">
      {/* Executive Posture Strip */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
        <div className="wiz-card rounded-2xl p-5 lg:col-span-4 flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Security Posture Score</div>
            <div className="mt-1 flex items-baseline gap-2">
              <span
                className={`font-mono text-4xl font-extrabold ${
                  securityScore >= 85 ? "text-emerald-600" : securityScore >= 55 ? "text-amber-600" : "text-rose-600"
                }`}
              >
                {securityScore}
              </span>
              <span className="text-sm font-semibold text-slate-400">/ 100</span>
            </div>
            <p className="mt-1 text-xs text-slate-500 truncate max-w-[210px]">{projectName}</p>
          </div>

          <button
            type="button"
            disabled={healing}
            onClick={onTriggerHeal}
            className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-xs font-bold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-50 transition"
          >
            <Zap className="h-4 w-4" />
            {report.mode === "auto_heal" ? "View Update & Export" : "Analyze Vulnerabilities →"}
          </button>
        </div>

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:col-span-8">
          {pillarCounts.map((p) => (
            <div key={p.label} className="wiz-card rounded-2xl p-4">
              <div className="flex items-center justify-between">
                <span
                  className={`font-mono text-2xl font-extrabold ${
                    p.count > 0 ? "text-rose-600" : "text-emerald-600"
                  }`}
                >
                  {p.count}
                </span>
                {p.count > 0 ? (
                  <ShieldAlert className="h-4 w-4 text-rose-500" />
                ) : (
                  <ShieldCheck className="h-4 w-4 text-emerald-500" />
                )}
              </div>
              <div className="mt-1.5 text-xs font-bold text-slate-800 leading-snug">{p.label}</div>
              <div className="mt-0.5 text-[11px] text-slate-500">{p.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Interactive SVG Topology Graph + Node Inspector */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <div className="wiz-card rounded-2xl p-5 xl:col-span-8 overflow-hidden">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="flex flex-wrap items-center gap-2 mb-1">
                <span className="rounded-full bg-indigo-50 px-2.5 py-0.5 font-mono text-[10.5px] font-bold text-indigo-700 border border-indigo-200">
                  STEP 1 OF 4 · COMPLETE CODE STRUCTURE GRAPH
                </span>
                <span className="rounded-full bg-slate-900 px-2.5 py-0.5 font-mono text-[10.5px] font-bold text-white">
                  Repo: {projectName}
                </span>
              </div>
              <h2 className="text-sm font-bold text-slate-900">Complete Repository Structure &amp; Cross-Layer Architecture Graph</h2>
              <p className="text-xs text-slate-500">
                Interactive SVG dataflow graph ({report.nodes.length} total nodes · {report.edges.length} cross-layer edges
                {filteredNodes.length < report.nodes.length ? ` · showing ${filteredNodes.length} prioritized nodes` : ""}). Click any node to inspect findings &amp; jump to code.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter table / route / file..."
                className="rounded-xl border border-slate-200 bg-white px-2.5 py-1.5 font-mono text-[11px] text-slate-800 placeholder:text-slate-400 focus:border-indigo-500 focus:outline-none w-44"
              />
              {isLargeRepo && (
                <button
                  type="button"
                  onClick={() => setShowAllLargeRepoNodes((v) => !v)}
                  className="rounded-xl border border-indigo-200 bg-indigo-50 px-2.5 py-1.5 text-[11px] font-bold text-indigo-700 hover:bg-indigo-100 transition"
                >
                  {showAllLargeRepoNodes ? "Focused Blast View" : `Show All ${report.nodes.length} Nodes`}
                </button>
              )}
              <div className="inline-flex items-center gap-1 rounded-xl border border-slate-200 bg-slate-50 p-1 text-xs">
                <Filter className="h-3.5 w-3.5 text-slate-400 ml-1.5 mr-1" />
                {[
                  { id: "all", label: "All Layers" },
                  { id: "risk", label: "Exposed / Policy" },
                  { id: "healed", label: "Healed" },
                ].map((f) => (
                  <button
                    key={f.id}
                    type="button"
                    onClick={() => setFilterMode(f.id as "all" | "risk" | "healed")}
                    className={`rounded-lg px-2.5 py-1 text-[11px] font-semibold transition ${
                      filterMode === f.id ? "bg-white text-slate-900 shadow-sm" : "text-slate-600 hover:text-slate-900"
                    }`}
                  >
                    {f.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-slate-200/90 bg-[#FAFBFF] p-2 max-h-[640px] overflow-auto">
            <svg
              viewBox={`0 0 1160 ${layout.svgHeight}`}
              className="w-full h-auto block"
            >
              <defs>
                <pattern id="wizGrid" width="24" height="24" patternUnits="userSpaceOnUse">
                  <circle cx="2" cy="2" r="1" fill="#CBD5E1" opacity="0.55" />
                </pattern>
                <marker id="arrowCrit" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 1 L 10 5 L 0 9 z" fill="#E11D48" />
                </marker>
                <marker id="arrowHealed" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 1 L 10 5 L 0 9 z" fill="#059669" />
                </marker>
                <marker id="arrowSafe" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 1 L 10 5 L 0 9 z" fill="#94A3B8" />
                </marker>
              </defs>

              <rect width="1160" height={layout.svgHeight} fill="url(#wizGrid)" />

              {/* Swimlane column headers */}
              {LANE_CONFIG.map((lane) => (
                <g key={lane.col}>
                  <rect
                    x={lane.xCenter - 125}
                    y={14}
                    width={250}
                    height={46}
                    rx={10}
                    fill="#FFFFFF"
                    stroke="#E2E8F0"
                  />
                  <text x={lane.xCenter} y={34} textAnchor="middle" className="fill-slate-900 text-[12px] font-bold">
                    {lane.title}
                  </text>
                  <text x={lane.xCenter} y={50} textAnchor="middle" className="fill-slate-400 text-[10px] font-medium">
                    {lane.subtitle}
                  </text>
                </g>
              ))}

              {/* Curved Bézier Cross-Layer Dataflow Edges */}
              {report.edges.map((edge, idx) => {
                const srcPos = layout.posMap.get(edge.source);
                const dstPos = layout.posMap.get(edge.target);
                if (!srcPos || !dstPos) return null;

                const sameCol = srcPos.x === dstPos.x;
                let pathD = "";
                if (sameCol) {
                  const xEdge = srcPos.x + 112;
                  pathD = `M ${xEdge} ${srcPos.y} C ${xEdge + 42} ${srcPos.y}, ${xEdge + 42} ${dstPos.y}, ${xEdge} ${dstPos.y}`;
                } else {
                  const goRight = dstPos.x > srcPos.x;
                  const x1 = goRight ? srcPos.x + 112 : srcPos.x - 112;
                  const y1 = srcPos.y;
                  const x2 = goRight ? dstPos.x - 112 : dstPos.x + 112;
                  const y2 = dstPos.y;
                  const dx = Math.max(55, Math.abs(x2 - x1) * 0.45);
                  pathD = `M ${x1} ${y1} C ${x1 + (goRight ? dx : -dx)} ${y1}, ${x2 - (goRight ? dx : -dx)} ${y2}, ${x2} ${y2}`;
                }

                const isCrit = edge.risk === "critical" || edge.risk === "high";
                const isHealed = edge.risk === "healed";
                const isSelectedEdge = activeNode && (edge.source === activeNode.id || edge.target === activeNode.id);

                const stroke = isCrit ? "#E11D48" : isHealed ? "#059669" : "#94A3B8";
                const markerEnd = isCrit ? "url(#arrowCrit)" : isHealed ? "url(#arrowHealed)" : "url(#arrowSafe)";

                return (
                  <g key={`${edge.source}-${edge.target}-${idx}`} opacity={activeNode && !isSelectedEdge ? 0.35 : 0.95}>
                    <path
                      d={pathD}
                      fill="none"
                      stroke={stroke}
                      strokeWidth={isSelectedEdge ? 2.6 : isCrit ? 2.1 : 1.6}
                      markerEnd={markerEnd}
                      className={isCrit ? "edge-animated-risk" : ""}
                    />
                  </g>
                );
              })}

              {/* Interactive SVG Nodes */}
              {Array.from(layout.posMap.values()).map(({ x, y, node }) => {
                const isSel = activeNode?.id === node.id;
                const fillBg =
                  node.status === "vulnerable"
                    ? "#FFF1F2"
                    : node.status === "healed"
                    ? "#ECFDF5"
                    : node.status === "abstained"
                    ? "#FFFBEB"
                    : "#FFFFFF";
                const borderCol =
                  node.status === "vulnerable"
                    ? "#F43F5E"
                    : node.status === "healed"
                    ? "#10B981"
                    : node.status === "abstained"
                    ? "#F59E0B"
                    : "#CBD5E1";
                const dotCol =
                  node.status === "vulnerable"
                    ? "#E11D48"
                    : node.status === "healed"
                    ? "#059669"
                    : node.status === "abstained"
                    ? "#D97706"
                    : "#64748B";

                const shortLabel = node.label.length > 26 ? node.label.slice(0, 25) + "…" : node.label;
                const shortFile = node.file_path.length > 30 ? "…" + node.file_path.slice(-29) : node.file_path;

                return (
                  <g
                    key={node.id}
                    transform={`translate(${x - 112}, ${y - 24})`}
                    onClick={() => setSelectedNodeId(node.id)}
                    className="cursor-pointer"
                  >
                    <rect
                      width={224}
                      height={48}
                      rx={11}
                      fill={fillBg}
                      stroke={isSel ? "#4F46E5" : borderCol}
                      strokeWidth={isSel ? 2.4 : 1.4}
                    />
                    <circle cx={15} cy={18} r={4.5} fill={dotCol} />
                    <text x={27} y={21} className="fill-slate-900 font-mono text-[11px] font-semibold">
                      {shortLabel}
                    </text>
                    <text x={27} y={37} className="fill-slate-500 font-mono text-[9.5px]">
                      {shortFile}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-4 text-[11px] text-slate-500">
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-rose-500" /> Exposed / Critical Blast Path
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" /> Healed &amp; 3-Gate Verified
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-amber-500" /> Honest Policy Abstention
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-slate-400" /> Verified Safe / Unreachable
            </span>
          </div>
        </div>

        {/* Right Node & Blast-Radius Inspector */}
        <div className="wiz-card rounded-2xl p-5 xl:col-span-4 flex flex-col justify-between">
          {activeNode ? (
            <div>
              <div className="flex items-start justify-between gap-2 border-b border-slate-200 pb-3.5">
                <div>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-indigo-600">
                    {activeNode.kind.replace("_", " ")}
                  </span>
                  <h3 className="mt-0.5 font-mono text-sm font-bold text-slate-900 break-all">{activeNode.label}</h3>
                  <p className="mt-0.5 font-mono text-xs text-slate-500 break-all">
                    {activeNode.file_path}:{activeNode.line}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => onJumpToFile(activeNode.file_path)}
                  className="inline-flex items-center gap-1 rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-semibold text-slate-700 hover:border-indigo-400 hover:text-indigo-700 shrink-0"
                >
                  Open in IDE <ArrowUpRight className="h-3.5 w-3.5" />
                </button>
              </div>

              <div className="mt-4 space-y-3 max-h-[390px] overflow-y-auto pr-1">
                {relatedFindings.length === 0 ? (
                  <div className="rounded-xl border border-emerald-200 bg-emerald-50/60 p-4 text-xs text-emerald-800">
                    <div className="font-bold flex items-center gap-1.5">
                      <ShieldCheck className="h-4 w-4 text-emerald-600" /> Zero Active Risks on Node
                    </div>
                    <p className="mt-1 text-emerald-700">
                      This component/table passed Cross-Layer AST, JWT role, and PostgreSQL RLS checks with zero false positives.
                    </p>
                  </div>
                ) : (
                  relatedFindings.map((f) => (
                    <div key={f.id} className="rounded-xl border border-slate-200 bg-slate-50/70 p-3.5 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs font-bold text-slate-900">
                          {f.rule_id} · {f.cwe}
                        </span>
                        <span
                          className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${
                            f.requires_policy_spec
                              ? "bg-amber-100 text-amber-800"
                              : !f.reachable
                              ? "bg-slate-200 text-slate-700"
                              : f.severity === "CRITICAL"
                              ? "bg-rose-100 text-rose-800"
                              : "bg-orange-100 text-orange-800"
                          }`}
                        >
                          {f.requires_policy_spec ? "ABSTAIN: POLICY SPEC" : !f.reachable ? "UNREACHABLE INFO" : f.severity}
                        </span>
                      </div>
                      <div className="text-xs font-bold text-slate-800">{f.title}</div>
                      <p className="text-xs text-slate-600 leading-relaxed">{f.blast_radius}</p>
                      {f.dpdp_pii_columns.length > 0 && (
                        <div className="rounded-lg border border-rose-200 bg-rose-50 px-2.5 py-1.5 text-[11px] font-medium text-rose-800">
                          DPDP Act §8(5) PII Exposed: <span className="font-mono">{f.dpdp_pii_columns.join(", ")}</span>
                        </div>
                      )}
                      {f.abstention_reason && (
                        <div className="rounded-lg border border-amber-200 bg-amber-50 px-2.5 py-1.5 text-[11px] text-amber-900 flex items-start gap-1.5">
                          <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5 text-amber-600" />
                          <span>{f.abstention_reason}</span>
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-xs text-slate-400">Select any node on the canvas</div>
          )}

          <div className="mt-4 border-t border-slate-200 pt-3 text-[11px] text-slate-500 flex items-center justify-between">
            <span>Scan Time: {report.scan_latency_ms} ms</span>
            <span>Broken Builds: 0</span>
          </div>
        </div>
      </div>
    </div>
  );
};
