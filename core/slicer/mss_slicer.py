"""Minimal Security Slicer (MSS) — cuts full files down to ~25-line cross-layer security slices."""

from __future__ import annotations

import ast
from typing import List

from core.graph.cross_layer_graph import WorkspaceContext
from core.models import Finding, MinimalSecuritySlice, Pillar


def _est_tokens(text: str) -> int:
    return max(1, int(len(text) / 3.8))


def extract_mss(finding: Finding, ctx: WorkspaceContext, force_slm: bool = False) -> MinimalSecuritySlice:
    full_src = ctx.file_contents.get(finding.file_path, "")
    lines = full_src.splitlines()
    total_lines = max(1, len(lines))

    # Determine slice window
    slice_txt = ""
    cross_ctx = ""

    if finding.file_path.endswith(".py") and lines:
        try:
            tree = ast.parse(full_src)
            imports_lines: List[str] = []
            target_fn_src = ""
            for node in tree.body:
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    imports_lines.append(lines[node.lineno - 1])
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    end_ln = getattr(node, "end_lineno", node.lineno + 10)
                    if node.lineno <= finding.line_start <= end_ln:
                        s = max(0, node.lineno - 2)
                        target_fn_src = "\n".join(lines[s:end_ln])
                        break
            if target_fn_src:
                slice_txt = ("\n".join(imports_lines[:6]) + "\n\n" + target_fn_src).strip()
        except Exception:
            pass

    if not slice_txt and lines:
        pad = 10 if finding.pillar != Pillar.SUPPLY_CHAIN else 3
        s = max(0, finding.line_start - 1 - pad)
        e = min(len(lines), finding.line_end + pad)
        slice_txt = "\n".join(lines[s:e])

    if not slice_txt:
        slice_txt = finding.snippet

    # Attach minimal cross-layer SQL / FK / client call context
    if finding.pillar == Pillar.RLS_DPDP:
        tname = finding.metadata.get("table", "")
        tbl = ctx.sql_analysis.tables.get(tname)
        if tbl:
            fk_desc = ", ".join(f"{col}->{rt}({rc})" for col, (rt, rc) in tbl.foreign_keys.items())
            parent_owners = []
            for _, (rt, _) in tbl.foreign_keys.items():
                ptbl = ctx.sql_analysis.tables.get(rt)
                if ptbl and ptbl.owner_column:
                    parent_owners.append(f"{rt}.{ptbl.owner_column}")
            cross_ctx = (
                f"-- Cross-Layer SQL Context: table={tname}, columns={list(tbl.columns.keys())}, "
                f"owner_col={tbl.owner_column}, fks=[{fk_desc}], parent_owners={parent_owners}, "
                f"client_queries={finding.linked_files}"
            )

    slice_line_cnt = max(1, len(slice_txt.splitlines()))
    full_tok = _est_tokens(full_src or slice_txt)
    slice_tok = _est_tokens(slice_txt + ("\n" + cross_ctx if cross_ctx else ""))
    # On real multi-line files, calculate context reduction cleanly
    comp_pct = round(max(0.0, (1.0 - (slice_tok / max(full_tok, slice_tok))) * 100.0), 1)

    # Choose repair strategy
    if finding.requires_policy_spec:
        strategy = "abstain"
    elif not finding.reachable:
        strategy = "skip_info"
    elif force_slm:
        strategy = "slm_mss"
    elif finding.pillar == Pillar.RLS_DPDP and not finding.metadata.get("owner_col") and finding.metadata.get("foreign_keys"):
        # Child FK join RLS without direct owner column -> showcase Tier-2 Local SLM on MSS!
        strategy = "slm_mss"
    else:
        strategy = "deterministic"

    return MinimalSecuritySlice(
        finding_id=finding.id,
        file_path=finding.file_path,
        full_file_lines=total_lines,
        slice_lines=slice_line_cnt,
        full_file_tokens_est=full_tok,
        slice_tokens_est=slice_tok,
        compression_pct=comp_pct,
        primary_slice=slice_txt,
        cross_layer_context=cross_ctx,
        repair_strategy=strategy,
    )
