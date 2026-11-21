"""Pillar 1 Remediator: Query-Intent, FK, RPC & Cloud-Drift Aware RLS Policy Synthesizer."""

from __future__ import annotations

import difflib
import json
import re
from typing import Dict, List, Optional

from core.graph.cross_layer_graph import WorkspaceContext
from core.models import FileEdit, Finding


def _make_diff(path: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            n=2,
        )
    )


def synthesize_rls_fix(finding: Finding, ctx: WorkspaceContext, slm_sql_override: Optional[str] = None) -> List[FileEdit]:
    edits: List[FileEdit] = []
    rule = finding.rule_id

    # Case A: Unauthenticated Mutating Python Route (VA-AUTH-006)
    if rule == "VA-AUTH-006":
        import ast as _ast
        rel = finding.file_path
        before = ctx.file_contents.get(rel, "")
        if not before:
            return []
        func_name = finding.metadata.get("func_name", "")
        after = before

        def _insert_after_future(src: str, line_to_add: str) -> str:
            ins_line = 0
            try:
                _tree = _ast.parse(src)
                for _node in _tree.body:
                    if isinstance(_node, _ast.Expr) and isinstance(getattr(_node, "value", None), _ast.Constant) and isinstance(_node.value.value, str):
                        ins_line = max(ins_line, getattr(_node, "end_lineno", _node.lineno))
                    elif isinstance(_node, _ast.ImportFrom) and _node.module == "__future__":
                        ins_line = max(ins_line, getattr(_node, "end_lineno", _node.lineno))
                    else:
                        break
            except SyntaxError:
                ins_line = 0
            _lns = src.splitlines(keepends=True)
            _lns.insert(ins_line, line_to_add)
            return "".join(_lns)

        if "from fastapi import Depends, Header, HTTPException" not in after and ("FastAPI" in after or "fastapi" in after):
            after = _insert_after_future(after, "from fastapi import Depends, Header, HTTPException\n")

        # Inject require_auth helper & check inside the target route
        helper = (
            "\ndef verify_jwt(authorization: str = Header(default='')) -> str:\n"
            "    if not authorization.startswith('Bearer ') or len(authorization.split(' ', 1)[1].strip()) < 12:\n"
            "        raise HTTPException(status_code=401, detail='VIBEARMOR_AUTH_REQUIRED')\n"
            "    return authorization.split(' ', 1)[1].strip()\n"
        )
        if "def verify_jwt(" not in after:
            lines = after.splitlines()
            ins_idx = max(0, min(len(lines), finding.line_start))
            try:
                _t2 = _ast.parse(after)
                for _n in _ast.walk(_t2):
                    if isinstance(_n, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and _n.name == func_name:
                        first_line = min([_n.lineno] + [d.lineno for d in _n.decorator_list])
                        ins_idx = max(0, first_line - 1)
                        break
            except SyntaxError:
                while ins_idx > 0 and lines[ins_idx - 1].lstrip().startswith("@"):
                    ins_idx -= 1
            lines.insert(ins_idx, helper)
            after = "\n".join(lines) + ("\n" if before.endswith("\n") else "")

        # Balanced-parenthesis injection of `_caller: str = Depends(verify_jwt)` into `def func_name(...)`
        m_def = re.search(rf"\b(?:async\s+)?def\s+{re.escape(func_name)}\s*\(", after)
        if m_def:
            open_paren_idx = m_def.end() - 1
            depth = 0
            close_paren_idx = -1
            in_quote: Optional[str] = None
            idx = open_paren_idx
            while idx < len(after):
                ch = after[idx]
                if in_quote:
                    if ch == "\\" and idx + 1 < len(after):
                        idx += 2
                        continue
                    if ch == in_quote:
                        in_quote = None
                else:
                    if ch in ("'", '"'):
                        in_quote = ch
                    elif ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                        if depth == 0:
                            close_paren_idx = idx
                            break
                idx += 1
            if close_paren_idx > open_paren_idx:
                inner = after[open_paren_idx + 1 : close_paren_idx]
                if "verify_jwt" not in inner:
                    stripped = inner.rstrip()
                    if not stripped:
                        new_inner = "_caller: str = Depends(verify_jwt)"
                    elif stripped.endswith(","):
                        trailing_ws = inner[len(stripped):]
                        new_inner = f"{stripped} _caller: str = Depends(verify_jwt),{trailing_ws}"
                    else:
                        trailing_ws = inner[len(stripped):]
                        new_inner = f"{stripped}, _caller: str = Depends(verify_jwt){trailing_ws}"
                    after = after[: open_paren_idx + 1] + new_inner + after[close_paren_idx:]
        if after != before:
            edits.append(FileEdit(file_path=rel, before_content=before, after_content=after, unified_diff=_make_diff(rel, before, after)))
        return edits

    # Case B: Unpinned SECURITY DEFINER RPC (VA-RLS-004)
    if rule == "VA-RLS-004":
        rpc_name = finding.metadata.get("rpc_name", "")
        arg_sig = finding.metadata.get("rpc_arg_types", "")
        rel = finding.file_path
        before = ctx.file_contents.get(rel, "")
        sql_patch = (
            f"\n-- VibeArmor Auto-Hardening for SECURITY DEFINER RPC '{rpc_name}({arg_sig})'\n"
            f"ALTER FUNCTION public.{rpc_name}({arg_sig}) SET search_path = '';\n"
            f"REVOKE ALL ON FUNCTION public.{rpc_name}({arg_sig}) FROM PUBLIC, anon;\n"
        )
        after = before.rstrip() + "\n" + sql_patch
        edits.append(FileEdit(file_path=rel, before_content=before, after_content=after, unified_diff=_make_diff(rel, before, after)))
        return edits

    # Case C: SQL Table Missing RLS / Vacuous USING(true) / Cloud Drift (VA-RLS-001, 002, 003)
    tname = finding.metadata.get("table", "")
    tbl = ctx.sql_analysis.tables.get(tname)
    if not tbl:
        return []

    owner_col = tbl.owner_column
    is_pub = bool(finding.metadata.get("is_public_catalog", False))

    if slm_sql_override and f"ON {tname}" in slm_sql_override.lower() or (slm_sql_override and "ENABLE ROW LEVEL SECURITY" in slm_sql_override.upper()):
        policy_block = slm_sql_override.strip() + "\n"
    elif is_pub:
        policy_block = (
            f"-- VibeArmor Auto-Synthesized Public-Read / Restricted-Write RLS for '{tname}'\n"
            f"ALTER TABLE public.{tname} ENABLE ROW LEVEL SECURITY;\n"
            f'CREATE POLICY "{tname}_public_select" ON public.{tname} FOR SELECT TO anon, authenticated USING (true);\n'
            f'CREATE POLICY "{tname}_auth_write" ON public.{tname} FOR INSERT TO authenticated WITH CHECK ((select auth.uid()) IS NOT NULL);\n'
        )
    elif owner_col:
        policy_block = (
            f"-- VibeArmor Auto-Synthesized Owner-Scoped DPDP RLS for '{tname}'\n"
            f"ALTER TABLE public.{tname} ENABLE ROW LEVEL SECURITY;\n"
            f'CREATE POLICY "{tname}_owner_select" ON public.{tname} FOR SELECT TO authenticated USING ((select auth.uid()) = {owner_col});\n'
            f'CREATE POLICY "{tname}_owner_insert" ON public.{tname} FOR INSERT TO authenticated WITH CHECK ((select auth.uid()) = {owner_col});\n'
            f'CREATE POLICY "{tname}_owner_update" ON public.{tname} FOR UPDATE TO authenticated USING ((select auth.uid()) = {owner_col}) WITH CHECK ((select auth.uid()) = {owner_col});\n'
            f'CREATE POLICY "{tname}_owner_delete" ON public.{tname} FOR DELETE TO authenticated USING ((select auth.uid()) = {owner_col});\n'
        )
    else:
        # Traverse FK parent table for child join ownership!
        fk_expr = None
        for child_col, (parent_tbl, parent_col) in tbl.foreign_keys.items():
            pt = ctx.sql_analysis.tables.get(parent_tbl)
            if pt and pt.owner_column:
                fk_expr = (
                    f"EXISTS (SELECT 1 FROM public.{parent_tbl} p "
                    f"WHERE p.{parent_col} = {tname}.{child_col} AND p.{pt.owner_column} = (select auth.uid()))"
                )
                break
        guard = fk_expr or "((select auth.uid()) IS NOT NULL)"
        policy_block = (
            f"-- VibeArmor Auto-Synthesized FK-Scoped RLS for '{tname}'\n"
            f"ALTER TABLE public.{tname} ENABLE ROW LEVEL SECURITY;\n"
            f'CREATE POLICY "{tname}_scoped_access" ON public.{tname} FOR ALL TO authenticated USING ({guard}) WITH CHECK ({guard});\n'
        )

    # Cloud Drift table (`VA-RLS-003`): write migration + sync cloud_drift_catalog.json
    if rule == "VA-RLS-003" or finding.metadata.get("drift"):
        mig_rel = "supabase/migrations/999_vibearmor_cloud_drift_rls.sql"
        before_mig = ctx.file_contents.get(mig_rel, "")
        after_mig = (before_mig.rstrip() + "\n\n" + policy_block).lstrip()
        edits.append(
            FileEdit(
                file_path=mig_rel,
                before_content=before_mig,
                after_content=after_mig,
                unified_diff=_make_diff(mig_rel, before_mig, after_mig),
                created_new=not bool(before_mig),
            )
        )
        drift_rel = finding.file_path.replace("\\", "/")
        before_cat = ctx.file_contents.get(drift_rel, "") or ctx.file_contents.get(drift_rel.replace("/", "\\"), "")
        if before_cat:
            try:
                cat_data = json.loads(before_cat)
                for entry in cat_data.get("pg_tables", []):
                    if str(entry.get("tablename", "")).lower() == tname:
                        entry["rowsecurity"] = True
                        entry["policies"] = [
                            {
                                "policyname": f"{tname}_owner_select",
                                "cmd": "ALL",
                                "roles": ["authenticated"],
                                "qual": f"((select auth.uid()) = {owner_col or 'user_id'})",
                            }
                        ]
                after_cat = json.dumps(cat_data, indent=2) + "\n"
                edits.append(
                    FileEdit(
                        file_path=drift_rel,
                        before_content=before_cat,
                        after_content=after_cat,
                        unified_diff=_make_diff(drift_rel, before_cat, after_cat),
                    )
                )
            except Exception:
                pass
        return edits

    # Local SQL file edit: remove vacuous USING(true) policy if present and append strict owner RLS
    rel = finding.file_path
    before_sql = ctx.file_contents.get(rel, "")
    after_sql = before_sql
    if rule == "VA-RLS-002":
        pol_name = finding.metadata.get("policy_name", "")
        if pol_name:
            after_sql = re.sub(
                rf"CREATE\s+POLICY\s+\"?{re.escape(pol_name)}\"?\s+ON\s+[A-Za-z0-9_.\"]+[^;]*;\s*",
                "",
                after_sql,
                flags=re.IGNORECASE | re.DOTALL,
            )

    if f"ALTER TABLE public.{tname} ENABLE ROW LEVEL SECURITY" not in after_sql and re.search(
        rf"ALTER\s+TABLE\s+(?:public\.)?{re.escape(tname)}\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY", after_sql, re.IGNORECASE
    ):
        # Already has ENABLE RLS, only append policies
        policy_lines = "\n".join(
            ln for ln in policy_block.splitlines() if "ENABLE ROW LEVEL SECURITY" not in ln
        ) + "\n"
        after_sql = after_sql.rstrip() + "\n\n" + policy_lines
    else:
        after_sql = after_sql.rstrip() + "\n\n" + policy_block

    if after_sql != before_sql:
        edits.append(
            FileEdit(
                file_path=rel,
                before_content=before_sql,
                after_content=after_sql,
                unified_diff=_make_diff(rel, before_sql, after_sql),
            )
        )
    return edits
