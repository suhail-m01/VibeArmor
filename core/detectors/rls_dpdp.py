"""Pillar 1: Cross-Layer Supabase/Postgres RLS, Cloud Drift, RPC Hardening, API Auth & DPDP PII Detector."""

from __future__ import annotations

import re
from typing import Dict, List, Set

from core.graph.cross_layer_graph import WorkspaceContext
from core.models import Finding, Pillar, Severity

PUBLIC_READONLY_TABLE_NAMES = {
    "products",
    "catalog",
    "categories",
    "public_events",
    "events",
    "articles",
    "posts",
    "announcements",
}


def detect_rls_and_access(ctx: WorkspaceContext) -> List[Finding]:
    findings: List[Finding] = []
    idx = 1

    # Map which tables/RPCs are called from client bundles and with what operations
    client_table_ops: Dict[str, Set[str]] = {}
    client_table_files: Dict[str, List[str]] = {}
    client_rpc_files: Dict[str, List[str]] = {}

    for rel, ts_f in ctx.ts_files.items():
        for sb in ts_f.supabase_calls:
            if sb.call_type == "table":
                t = sb.table_or_rpc.lower()
                client_table_ops.setdefault(t, set()).add(sb.operation.lower())
                client_table_files.setdefault(t, []).append(f"{rel}:{sb.line}")
            elif sb.call_type == "rpc":
                fn = sb.table_or_rpc.lower()
                client_rpc_files.setdefault(fn, []).append(f"{rel}:{sb.line}")

    drift_tables = {d.table_name: d for d in ctx.cloud_drifts}

    # 1. Evaluate every SQL / Cloud table
    for tname, tbl in ctx.sql_analysis.tables.items():
        linked = client_table_files.get(tname, [])
        ops = client_table_ops.get(tname, set())
        is_public_catalog = tname in PUBLIC_READONLY_TABLE_NAMES and not tbl.dpdp_pii_columns and not tbl.owner_column
        pii = tbl.dpdp_pii_columns

        # Check Semantic Multi-Tenant Business Policy Ambiguity FIRST (Honest Abstention Boundary!)
        if tbl.has_complex_tenant_role_columns or tbl.policy_comment_hint:
            if not tbl.rls_enabled or any(p.is_vacuous_true for p in tbl.policies) or not tbl.policies:
                findings.append(
                    Finding(
                        id=f"VA-RLS-ABSTAIN-{idx:03d}",
                        pillar=Pillar.RLS_DPDP,
                        rule_id="VA-RLS-005",
                        cwe="CWE-284",
                        severity=Severity.HIGH,
                        title=f"Multi-Tenant Role/Limit Policy Spec Required on '{tname}'",
                        description=(
                            f"Table '{tname}' contains domain-specific organizational/threshold columns "
                            f"({', '.join(tbl.columns.keys())}). Static syntax cannot safely infer custom business "
                            f"authorization rules ({tbl.policy_comment_hint or 'org role & INR threshold rules'})."
                        ),
                        blast_radius="Guessing a naive owner policy would either break org workflows or over-grant refund/approval access.",
                        file_path=tbl.file_path,
                        line_start=tbl.line,
                        line_end=tbl.line + 5,
                        snippet=f"CREATE TABLE {tname} ({', '.join(list(tbl.columns.keys())[:6])})",
                        linked_files=linked,
                        dpdp_pii_columns=pii,
                        requires_policy_spec=True,
                        abstention_reason="NEEDS_POLICY_SPEC: Custom multi-tenant role & INR approval hierarchy cannot be synthesized purely from AST/DDL without an explicit policy specification.",
                        metadata={"table": tname},
                    )
                )
                idx += 1
                continue

        # Cloud Drift table with RLS disabled
        if tname in drift_tables and not tbl.rls_enabled:
            drift = drift_tables[tname]
            findings.append(
                Finding(
                    id=f"VA-DRIFT-{idx:03d}",
                    pillar=Pillar.RLS_DPDP,
                    rule_id="VA-RLS-003",
                    cwe="CWE-284",
                    severity=Severity.CRITICAL if pii else Severity.HIGH,
                    title=f"Live Supabase Cloud Drift: Table '{tname}' Has RLS Disabled",
                    description=(
                        f"Table '{tname}' exists in live database catalog ({drift.source_file}) with rowsecurity=false "
                        f"and no local hardening migration."
                    ),
                    blast_radius=(
                        f"Anyone with the public Supabase anon_key can dump/modify '{tname}'"
                        + (f" — exposing DPDP Act PII ({', '.join(pii)})." if pii else ".")
                    ),
                    file_path=drift.source_file,
                    line_start=1,
                    line_end=10,
                    snippet=f"pg_tables.{tname}: rowsecurity = false | columns = {list(tbl.columns.keys())}",
                    linked_files=linked,
                    dpdp_pii_columns=pii,
                    metadata={"table": tname, "ops": sorted(ops), "owner_col": tbl.owner_column, "drift": True},
                )
            )
            idx += 1
            continue

        # Missing RLS (`CVE-2025-48757`)
        if not tbl.rls_enabled:
            # Even public catalog tables in Supabase MUST enable RLS so anon cannot INSERT/UPDATE/DELETE!
            sev = Severity.CRITICAL if (pii or tbl.owner_column or linked) else Severity.HIGH
            findings.append(
                Finding(
                    id=f"VA-RLS-{idx:03d}",
                    pillar=Pillar.RLS_DPDP,
                    rule_id="VA-RLS-001",
                    cwe="CWE-284",
                    severity=sev,
                    title=f"Missing Row-Level Security on Table '{tname}' (CVE-2025-48757)",
                    description=(
                        f"Table '{tname}' is created without ENABLE ROW LEVEL SECURITY"
                        + (f" while queried directly from client code ({', '.join(linked)})." if linked else ".")
                    ),
                    blast_radius=(
                        f"Unauthenticated callers using the public anon_key get full SELECT/INSERT/UPDATE/DELETE access to '{tname}'"
                        + (f", leaking Indian DPDP PII: {', '.join(pii)}." if pii else ".")
                    ),
                    file_path=tbl.file_path,
                    line_start=tbl.line,
                    line_end=tbl.line + 6,
                    snippet=f"CREATE TABLE {tname} (...); -- RLS NOT ENABLED",
                    linked_files=linked,
                    dpdp_pii_columns=pii,
                    metadata={
                        "table": tname,
                        "ops": sorted(ops),
                        "owner_col": tbl.owner_column,
                        "foreign_keys": {k: list(v) for k, v in tbl.foreign_keys.items()},
                        "is_public_catalog": is_public_catalog,
                    },
                )
            )
            idx += 1
            continue

        # Vacuous / Fake RLS (`USING (true)` on non-public-readonly or write operations!)
        for pol in tbl.policies:
            if not pol.is_vacuous_true:
                continue
            # Allow `FOR SELECT USING (true)` ONLY on public catalog tables with no PII/owner restriction!
            if pol.command == "SELECT" and is_public_catalog:
                continue
            findings.append(
                Finding(
                    id=f"VA-RLS-{idx:03d}",
                    pillar=Pillar.RLS_DPDP,
                    rule_id="VA-RLS-002",
                    cwe="CWE-732",
                    severity=Severity.CRITICAL if pii else Severity.HIGH,
                    title=f"Vacuous 'Fake RLS' Policy '{pol.name}' on '{tname}' (USING true)",
                    description=(
                        f"Policy '{pol.name}' on '{tname}' enables RLS cosmetically but sets USING/WITH CHECK to 'true' "
                        f"for command '{pol.command}'."
                    ),
                    blast_radius=(
                        f"Bypasses row isolation completely — any caller can read/write every user's rows in '{tname}'"
                        + (f" (DPDP PII exposed: {', '.join(pii)})." if pii else ".")
                    ),
                    file_path=tbl.file_path,
                    line_start=pol.line,
                    line_end=pol.line + 3,
                    snippet=f'CREATE POLICY "{pol.name}" ON {tname} FOR {pol.command} USING ({pol.using_expr or "true"});',
                    linked_files=linked,
                    dpdp_pii_columns=pii,
                    metadata={
                        "table": tname,
                        "policy_name": pol.name,
                        "ops": sorted(ops),
                        "owner_col": tbl.owner_column,
                        "foreign_keys": {k: list(v) for k, v in tbl.foreign_keys.items()},
                        "is_public_catalog": is_public_catalog,
                    },
                )
            )
            idx += 1

    # 2. Check SECURITY DEFINER Postgres RPCs
    for fname, fn in ctx.sql_analysis.functions.items():
        if fn.security_definer and (not fn.has_pinned_search_path or not fn.revoked_public_anon):
            findings.append(
                Finding(
                    id=f"VA-RPC-{idx:03d}",
                    pillar=Pillar.RLS_DPDP,
                    rule_id="VA-RLS-004",
                    cwe="CWE-269",
                    severity=Severity.HIGH,
                    title=f"Unpinned / Publicly Callable SECURITY DEFINER RPC '{fname}()'",
                    description=(
                        f"Function '{fname}()' runs with superuser/owner privileges (SECURITY DEFINER) "
                        + ("without SET search_path = '' " if not fn.has_pinned_search_path else "")
                        + ("and remains executable by anon/public." if not fn.revoked_public_anon else ".")
                    ),
                    blast_radius="Attackers can hijack schema search_path or invoke privileged internal RPCs via PostgREST.",
                    file_path=fn.file_path,
                    line_start=fn.line,
                    line_end=fn.line + 5,
                    snippet=f"CREATE FUNCTION {fname}({fn.arg_types}) ... SECURITY DEFINER;",
                    linked_files=client_rpc_files.get(fname, []),
                    metadata={"rpc_name": fname, "rpc_arg_types": fn.arg_types},
                )
            )
            idx += 1

    # 3. Check Unauthenticated State-Mutating Python API Routes (excluding auth/webhook/public endpoints)
    safe_public_paths = ("login", "register", "signup", "health", "webhook", "public", "search", "products")
    for rel, py_f in ctx.py_files.items():
        src = ctx.file_contents.get(rel, "")
        for rt in py_f.routes:
            if rt.http_method in ("DELETE", "PUT", "PATCH") and not rt.has_auth_dependency:
                if not any(sp in rt.route_path.lower() for sp in safe_public_paths):
                    lines = src.splitlines()
                    snip = "\n".join(lines[max(0, rt.line_start - 1): min(len(lines), rt.line_end)])
                    findings.append(
                        Finding(
                            id=f"VA-AUTH-{idx:03d}",
                            pillar=Pillar.RLS_DPDP,
                            rule_id="VA-AUTH-006",
                            cwe="CWE-306",
                            severity=Severity.HIGH,
                            title=f"Missing Auth Check on {rt.http_method} {rt.route_path}",
                            description=f"Mutating endpoint '{rt.func_name}' ({rt.http_method} {rt.route_path}) modifies data with zero authentication guard.",
                            blast_radius="Any unauthenticated attacker can modify or delete records by guessing IDs (BOLA/IDOR).",
                            file_path=rel,
                            line_start=rt.line_start,
                            line_end=rt.line_end,
                            snippet=snip[:220],
                            metadata={"func_name": rt.func_name, "route_path": rt.route_path, "method": rt.http_method},
                        )
                    )
                    idx += 1

    # Update visual graph node/edge statuses
    vuln_tables = {f.metadata.get("table") for f in findings if f.metadata.get("table")}
    vuln_rpcs = {f.metadata.get("rpc_name") for f in findings if f.metadata.get("rpc_name")}
    for node in ctx.nodes:
        if node.id.startswith("sql:") and node.id.split(":", 1)[1] in vuln_tables:
            node.status = "vulnerable"
        elif node.id.startswith("rpc:") and node.id.split(":", 1)[1] in vuln_rpcs:
            node.status = "vulnerable"
    for edge in ctx.edges:
        if edge.target.startswith("sql:") and edge.target.split(":", 1)[1] in vuln_tables:
            edge.risk = "critical"
        elif edge.target.startswith("rpc:") and edge.target.split(":", 1)[1] in vuln_rpcs:
            edge.risk = "critical"

    return findings
