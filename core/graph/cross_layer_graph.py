"""Unified Cross-Layer Graph builder connecting Frontend, API Routes, SQL Schema/Cloud Drift, and Dependencies."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from core.graph.pg_live_drift import CloudDriftRecord, inspect_cloud_drift
from core.graph.py_parser import PyFileAnalysis, parse_py_file
from core.graph.sql_rls_parser import SqlSchemaAnalysis, parse_sql_files
from core.graph.ts_parser import TsFileAnalysis, parse_ts_file
from core.models import NodeKind, SecurityEdge, SecurityNode

IGNORED_DIRS = {
    "node_modules",
    ".git",
    ".next",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    ".vibearmor",
    "workspaces_store",
}


@dataclass
class WorkspaceContext:
    root: Path
    ts_files: Dict[str, TsFileAnalysis] = field(default_factory=dict)
    py_files: Dict[str, PyFileAnalysis] = field(default_factory=dict)
    sql_files_raw: List[Tuple[str, str]] = field(default_factory=list)
    sql_analysis: SqlSchemaAnalysis = field(default_factory=SqlSchemaAnalysis)
    cloud_drifts: List[CloudDriftRecord] = field(default_factory=list)
    npm_deps: Dict[str, Tuple[str, str, int]] = field(default_factory=dict)  # pkg -> (version, rel_file, line)
    npm_dev_deps: Dict[str, Tuple[str, str, int]] = field(default_factory=dict)
    pypi_deps: Dict[str, Tuple[str, str, int]] = field(default_factory=dict)  # pkg -> (version, rel_file, line)
    all_imported_pkgs: Set[str] = field(default_factory=set)
    env_files: Dict[str, str] = field(default_factory=dict)
    file_contents: Dict[str, str] = field(default_factory=dict)
    nodes: List[SecurityNode] = field(default_factory=list)
    edges: List[SecurityEdge] = field(default_factory=list)


def _find_line(text: str, needle: str) -> int:
    idx = text.find(needle)
    if idx < 0:
        return 1
    return text[:idx].count("\n") + 1


def build_workspace_context(root_dir: str | Path) -> WorkspaceContext:
    root = Path(root_dir).resolve()
    ctx = WorkspaceContext(root=root)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in sorted(dirnames) if d not in IGNORED_DIRS]
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            rel = str(fpath.relative_to(root)).replace("\\", "/")

            if fname == ".gitignore":
                txt = fpath.read_text(encoding="utf-8", errors="replace")
                ctx.file_contents[rel] = txt
                continue

            if fname.startswith(".env"):
                txt = fpath.read_text(encoding="utf-8", errors="replace")
                ctx.env_files[rel] = txt
                ctx.file_contents[rel] = txt
                continue

            ext = fpath.suffix.lower()
            if ext in (".ts", ".tsx", ".js", ".jsx"):
                txt = fpath.read_text(encoding="utf-8", errors="replace")
                ctx.file_contents[rel] = txt
                ts_res = parse_ts_file(rel, txt)
                ctx.ts_files[rel] = ts_res
                ctx.all_imported_pkgs.update(p.lower() for p in ts_res.imports)

            elif ext == ".py":
                txt = fpath.read_text(encoding="utf-8", errors="replace")
                ctx.file_contents[rel] = txt
                py_res = parse_py_file(rel, txt)
                ctx.py_files[rel] = py_res
                ctx.all_imported_pkgs.update(p.lower().replace("_", "-") for p in py_res.imports)
                ctx.all_imported_pkgs.update(p.lower() for p in py_res.imports)

            elif ext == ".sql":
                txt = fpath.read_text(encoding="utf-8", errors="replace")
                ctx.file_contents[rel] = txt
                ctx.sql_files_raw.append((rel, txt))

            elif fname == "package.json":
                txt = fpath.read_text(encoding="utf-8", errors="replace")
                ctx.file_contents[rel] = txt
                try:
                    pkg_json = json.loads(txt)
                    for k, v in (pkg_json.get("dependencies") or {}).items():
                        clean_v = re.sub(r"^[\^~>=<]+", "", str(v)).strip()
                        ctx.npm_deps[k] = (clean_v, rel, _find_line(txt, f'"{k}"'))
                    for k, v in (pkg_json.get("devDependencies") or {}).items():
                        clean_v = re.sub(r"^[\^~>=<]+", "", str(v)).strip()
                        ctx.npm_dev_deps[k] = (clean_v, rel, _find_line(txt, f'"{k}"'))
                except Exception:
                    pass

            elif fname == "requirements.txt":
                txt = fpath.read_text(encoding="utf-8", errors="replace")
                ctx.file_contents[rel] = txt
                for ln_idx, raw_line in enumerate(txt.splitlines(), start=1):
                    line = raw_line.split("#")[0].strip()
                    if not line or line.startswith("-"):
                        continue
                    m_req = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=)?\s*([0-9A-Za-z_.\-]*)", line)
                    if m_req:
                        ctx.pypi_deps[m_req.group(1)] = (m_req.group(2) or "latest", rel, ln_idx)

            elif fname == "cloud_drift_catalog.json":
                ctx.file_contents[rel] = fpath.read_text(encoding="utf-8", errors="replace")

    # Parse SQL & Live Cloud Drift
    ctx.sql_analysis = parse_sql_files(ctx.sql_files_raw)
    ctx.cloud_drifts = inspect_cloud_drift(root, ctx.sql_analysis)

    # Populate visual nodes & edges for Studio Cross-Layer Graph
    node_ids: Set[str] = set()

    def _ensure_node(nid: str, kind: NodeKind, label: str, fpath: str, line: int = 1, meta=None):
        if nid not in node_ids:
            node_ids.add(nid)
            ctx.nodes.append(
                SecurityNode(
                    id=nid,
                    kind=kind,
                    label=label,
                    file_path=fpath,
                    line=line,
                    metadata=meta or {},
                )
            )

    for tbl_name, tbl in ctx.sql_analysis.tables.items():
        _ensure_node(
            f"sql:{tbl_name}",
            NodeKind.SQL_TABLE,
            f"Table: {tbl_name}",
            tbl.file_path,
            tbl.line,
            {"rls_enabled": tbl.rls_enabled, "dpdp_pii": tbl.dpdp_pii_columns},
        )

    for fn_name, fn in ctx.sql_analysis.functions.items():
        _ensure_node(
            f"rpc:{fn_name}",
            NodeKind.SQL_FUNCTION,
            f"RPC: {fn_name}()",
            fn.file_path,
            fn.line,
            {"security_definer": fn.security_definer},
        )

    for rel, ts_f in ctx.ts_files.items():
        comp_id = f"ts:{rel}"
        kind = NodeKind.FRONTEND_COMPONENT if ts_f.is_client_bundle else NodeKind.API_ROUTE
        _ensure_node(comp_id, kind, Path(rel).name, rel, 1, {"client": ts_f.is_client_bundle})
        for sb in ts_f.supabase_calls:
            tgt = f"sql:{sb.table_or_rpc}" if sb.call_type == "table" else f"rpc:{sb.table_or_rpc}"
            if sb.call_type == "table" and sb.table_or_rpc not in ctx.sql_analysis.tables:
                _ensure_node(tgt, NodeKind.SQL_TABLE, f"Table: {sb.table_or_rpc}", rel, sb.line)
            ctx.edges.append(
                SecurityEdge(
                    source=comp_id,
                    target=tgt,
                    relation=f"supabase.{sb.operation}",
                    detail=sb.snippet[:80],
                )
            )

    for rel, py_f in ctx.py_files.items():
        if py_f.routes:
            for rt in py_f.routes:
                rid = f"api:{rel}:{rt.func_name}"
                _ensure_node(
                    rid,
                    NodeKind.API_ROUTE,
                    f"{rt.http_method} {rt.route_path}",
                    rel,
                    rt.line_start,
                    {"auth": rt.has_auth_dependency},
                )
        else:
            # Ensure standalone Python modules/services also appear in the Complete Code Structure Graph
            _ensure_node(
                f"py:{rel}",
                NodeKind.API_ROUTE,
                Path(rel).name,
                rel,
                1,
                {"module": True},
            )

    for env_rel in ctx.env_files:
        if not env_rel.endswith((".example", ".sample", ".template")):
            _ensure_node(
                f"env:{env_rel}",
                NodeKind.SECRET_TOKEN,
                f"Env: {env_rel}",
                env_rel,
                1,
                {"env_file": True},
            )

    for pkg, (ver, rel, ln) in list(ctx.npm_deps.items())[:14] + list(ctx.pypi_deps.items())[:14]:
        pid = f"pkg:{pkg}"
        _ensure_node(pid, NodeKind.DEPENDENCY, f"{pkg}@{ver}", rel, ln)

    # Wire SQL Foreign-Key Relational Edges
    for tbl_name, tbl in ctx.sql_analysis.tables.items():
        for fk_col, (ref_tbl, ref_col) in tbl.foreign_keys.items():
            src_id = f"sql:{tbl_name}"
            tgt_id = f"sql:{ref_tbl}"
            if src_id in node_ids and tgt_id in node_ids:
                ctx.edges.append(
                    SecurityEdge(
                        source=src_id,
                        target=tgt_id,
                        relation="foreign_key",
                        detail=f"{tbl_name}.{fk_col} -> {ref_tbl}.{ref_col}",
                    )
                )

    # Wire TS Imports (external packages + internal local module structure edges) & Auto-BFF calls
    for rel, ts_f in ctx.ts_files.items():
        comp_id = f"ts:{rel}"
        raw_ts = ctx.file_contents.get(rel, "")
        for imp in ts_f.imports:
            pkg_id = f"pkg:{imp}"
            if pkg_id in node_ids:
                ctx.edges.append(
                    SecurityEdge(source=comp_id, target=pkg_id, relation="imports_pkg", detail=f"import {imp}")
                )
        # Local relative module imports to show complete code structure graph!
        for m_rel in re.finditer(r"from\s+['\"](\.[^'\"]+)['\"]", raw_ts):
            rel_spec = m_rel.group(1)
            base_dir = Path(rel).parent
            cand_stem = str((base_dir / rel_spec)).replace("\\", "/")
            for other_rel in ctx.ts_files:
                if other_rel == rel:
                    continue
                other_no_ext = re.sub(r"\.(tsx?|jsx?)$", "", other_rel)
                if cand_stem.endswith(other_no_ext) or other_no_ext.endswith(rel_spec.lstrip("./")):
                    if f"ts:{other_rel}" in node_ids:
                        ctx.edges.append(
                            SecurityEdge(
                                source=comp_id,
                                target=f"ts:{other_rel}",
                                relation="imports_module",
                                detail=f"{Path(rel).name} -> {Path(other_rel).name}",
                            )
                        )
                    break
        if "/api/vibearmor/" in raw_ts:
            for other_rel in ctx.ts_files:
                if "api/vibearmor/" in other_rel and f"ts:{other_rel}" in node_ids:
                    ctx.edges.append(
                        SecurityEdge(
                            source=comp_id,
                            target=f"ts:{other_rel}",
                            relation="zero_trust_bff",
                            detail="fetch('/api/vibearmor/...')",
                        )
                    )

    # Wire Python API Routes -> SQL Tables & Imported Packages
    for rel, py_f in ctx.py_files.items():
        py_lines = ctx.file_contents.get(rel, "").splitlines()
        for rt in py_f.routes:
            rid = f"api:{rel}:{rt.func_name}"
            fn_body = "\n".join(py_lines[max(0, rt.line_start - 1) : rt.line_end])
            for tbl_name in ctx.sql_analysis.tables:
                if re.search(rf"\b{re.escape(tbl_name)}\b", fn_body):
                    ctx.edges.append(
                        SecurityEdge(
                            source=rid,
                            target=f"sql:{tbl_name}",
                            relation="sql_query",
                            detail=f"{rt.http_method} {rt.route_path} -> {tbl_name}",
                        )
                    )
            for imp in py_f.imports:
                pkg_id = f"pkg:{imp}"
                if pkg_id in node_ids:
                    ctx.edges.append(
                        SecurityEdge(source=rid, target=pkg_id, relation="imports_pkg", detail=f"import {imp}")
                    )

    return ctx
