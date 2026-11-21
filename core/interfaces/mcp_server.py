"""Model Context Protocol (MCP) Controlled Security Tool Server for Cursor, Windsurf, and Claude Code.

Exposes deterministic, bounded security tools so AI agents cannot self-certify security verdicts.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

try:
    from mcp.server.mcpserver import MCPServer as _MCPServerCls  # mcp >= 2.0
except ImportError:
    from mcp.server.fastmcp import FastMCP as _MCPServerCls  # mcp 1.x

from core.agents.langgraph_workflow import build_workspace_evidence_bundle
from core.engine import scan_and_heal
from core.graph.cross_layer_graph import build_workspace_context
from core.models import Pillar
from core.rag.security_rag import search_security_knowledge_base
from core.security_masking import mask_secrets
from core.slicer.mss_slicer import extract_mss

mcp = _MCPServerCls("VibeArmor")


@mcp.tool()
def vibearmor_scan(workspace_dir: str) -> str:
    """Run <180ms cross-layer AST/SQL/Secret/Supply-Chain security scan on a workspace directory."""
    report = scan_and_heal(workspace_dir, auto_heal=False)
    return json.dumps(
        {
            "clean_fast_path": report.clean_fast_path,
            "scan_latency_ms": report.scan_latency_ms,
            "summary": report.summary,
            "findings": [
                {**f.model_dump(), "snippet": mask_secrets(f.snippet)}
                for f in report.findings_before
            ],
        },
        indent=2,
    )


@mcp.tool()
def vibearmor_heal(workspace_dir: str) -> str:
    """Auto-remediate vulnerabilities using Minimal Security Slicing + 3-Gate Verification."""
    report = scan_and_heal(workspace_dir, auto_heal=True)
    return json.dumps(
        {
            "total_latency_ms": report.total_latency_ms,
            "summary": report.summary,
            "patches": [
                {
                    "rule_id": p.rule_id,
                    "status": p.status.value,
                    "strategy_used": p.strategy_used,
                    "files_modified": [e.file_path for e in p.edits],
                    "gates_passed": [g.passed for g in p.gates],
                    "abstention_note": p.abstention_note,
                }
                for p in report.patches
            ],
        },
        indent=2,
    )


@mcp.tool()
def vibearmor_heal_snippet(filename: str, content: str) -> str:
    """Scan, retrieve Security RAG evidence, remediate, and 3-Gate verify an in-memory code/SQL snippet."""
    with tempfile.TemporaryDirectory(prefix="vibearmor_mcp_") as tmp:
        root = Path(tmp)
        fpath = root / filename
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")
        report = scan_and_heal(root, auto_heal=True)
        healed_text = fpath.read_text(encoding="utf-8") if fpath.exists() else content
        return json.dumps(
            {
                "filename": filename,
                "summary": report.summary,
                "healed_content": healed_text,
                "abstentions": [a.abstention_reason for a in report.abstentions],
            },
            indent=2,
        )


@mcp.tool()
def search_security_knowledge(query: str, cwe_hint: str = "", rule_id_hint: str = "") -> str:
    """Query VibeArmor's FAISS Security RAG Knowledge Base (CWE, OWASP, CAPEC, Verified Patterns)."""
    res = search_security_knowledge_base(query=query, cwe_hint=cwe_hint, rule_id_hint=rule_id_hint, top_k=3)
    return json.dumps(res, indent=2)


@mcp.tool()
def get_ast(workspace_dir: str) -> str:
    """Extract Cross-Layer Tree-sitter & sqlglot AST Knowledge Graph nodes and edges."""
    ctx = build_workspace_context(Path(workspace_dir).resolve())
    return json.dumps(
        {
            "node_count": len(ctx.nodes),
            "edge_count": len(ctx.edges),
            "nodes": [n.model_dump() for n in ctx.nodes[:60]],
            "edges": [e.model_dump() for e in ctx.edges[:80]],
        },
        indent=2,
    )


@mcp.tool()
def get_security_slice(workspace_dir: str) -> str:
    """Extract Minimal Security Slices (MSS) for detected vulnerabilities in a workspace."""
    root = Path(workspace_dir).resolve()
    ctx = build_workspace_context(root)
    report = scan_and_heal(root, auto_heal=False)
    slices = [extract_mss(f, ctx).model_dump() for f in report.findings_before[:15]]
    for s in slices:
        s["primary_slice"] = mask_secrets(s.get("primary_slice", ""))
    return json.dumps({"slice_count": len(slices), "slices": slices}, indent=2)


@mcp.tool()
def inspect_dependencies(workspace_dir: str) -> str:
    """Inspect package.json and requirements.txt for slopsquatting and AST-reachable CVEs."""
    report = scan_and_heal(workspace_dir, auto_heal=False)
    dep_findings = [
        f.model_dump() for f in report.findings_before if f.pillar == Pillar.SUPPLY_CHAIN
    ]
    return json.dumps({"supply_chain_findings": dep_findings, "count": len(dep_findings)}, indent=2)


@mcp.tool()
def get_evidence(workspace_dir: str) -> str:
    """Build complete Security Evidence Packages and Evidence Graphs for a workspace."""
    root = Path(workspace_dir).resolve()
    report = scan_and_heal(root, auto_heal=False)
    bundle = build_workspace_evidence_bundle("mcp-workspace", root.name, root, report)
    return json.dumps(bundle, indent=2)


def run_mcp_server() -> None:
    mcp.run()
