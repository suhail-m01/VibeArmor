"""Live Supabase / PostgreSQL Cloud-vs-Code Drift Introspector.

Detects tables & policies created directly in Supabase Dashboard (`cloud_drift_catalog.json` or live
`pg_catalog` snapshot) that are missing from or out-of-sync with local `.sql` migrations.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.graph.sql_rls_parser import DPDP_PII_PATTERNS, OWNER_COLUMN_CANDIDATES, SqlPolicyInfo, SqlSchemaAnalysis, SqlTableInfo


@dataclass
class CloudDriftRecord:
    table_name: str
    drift_kind: str  # "untracked_cloud_table_rls_off" | "cloud_rls_disabled_override" | "cloud_vacuous_policy"
    columns: Dict[str, str] = field(default_factory=dict)
    dpdp_pii_columns: List[str] = field(default_factory=list)
    owner_column: Optional[str] = None
    source_file: str = "cloud_drift_catalog.json"


def inspect_cloud_drift(workspace: Path, local_sql: SqlSchemaAnalysis) -> List[CloudDriftRecord]:
    """Compare live `pg_tables`/`pg_policies` catalog snapshot against local migrations."""
    catalog_path = workspace / "cloud_drift_catalog.json"
    if not catalog_path.exists():
        catalog_path = workspace / "supabase" / "cloud_drift_catalog.json"
    if not catalog_path.exists():
        return []

    try:
        raw: Dict[str, Any] = json.loads(catalog_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    drifts: List[CloudDriftRecord] = []
    rel_src = str(catalog_path.relative_to(workspace))

    for tbl in raw.get("pg_tables", []):
        tname = str(tbl.get("tablename", "")).lower().strip()
        if not tname:
            continue
        rowsecurity = bool(tbl.get("rowsecurity", False))
        cols_raw = tbl.get("columns", {})
        if isinstance(cols_raw, list):
            cols: Dict[str, str] = {str(c): "text" for c in cols_raw}
        elif isinstance(cols_raw, dict):
            cols = {str(k): str(v) for k, v in cols_raw.items()}
        else:
            cols = {}
        policies_raw: List[Dict[str, Any]] = tbl.get("policies", [])

        pii_cols = [
            c for c in cols if c.lower() in DPDP_PII_PATTERNS or any(c.lower().endswith(f"_{p}") for p in ("phone", "aadhaar", "pan", "address"))
        ]
        owner_col = next((cand for cand in OWNER_COLUMN_CANDIDATES if cand in cols), None)

        # Merge into local_sql so Cross-Layer Graph sees cloud tables too
        if tname not in local_sql.tables:
            pol_objs = [
                SqlPolicyInfo(
                    name=p.get("policyname", "cloud_policy"),
                    table=tname,
                    command=p.get("cmd", "ALL").upper(),
                    roles=p.get("roles", ["public"]),
                    using_expr=p.get("qual", ""),
                    with_check_expr=p.get("with_check", ""),
                    is_vacuous_true=str(p.get("qual", "")).strip().lower() in ("true", "1=1"),
                )
                for p in policies_raw
            ]
            local_sql.tables[tname] = SqlTableInfo(
                name=tname,
                file_path=rel_src,
                line=1,
                columns=cols,
                owner_column=owner_col,
                dpdp_pii_columns=pii_cols,
                rls_enabled=rowsecurity,
                policies=pol_objs,
            )
            if not rowsecurity:
                drifts.append(
                    CloudDriftRecord(
                        table_name=tname,
                        drift_kind="untracked_cloud_table_rls_off",
                        columns=cols,
                        dpdp_pii_columns=pii_cols,
                        owner_column=owner_col,
                        source_file=rel_src,
                    )
                )
        else:
            # Table exists in local SQL, check if cloud drifted to RLS=false while local wasn't applied!
            if not rowsecurity and not local_sql.tables[tname].rls_enabled:
                drifts.append(
                    CloudDriftRecord(
                        table_name=tname,
                        drift_kind="cloud_rls_disabled_override",
                        columns=cols or local_sql.tables[tname].columns,
                        dpdp_pii_columns=pii_cols or local_sql.tables[tname].dpdp_pii_columns,
                        owner_column=owner_col or local_sql.tables[tname].owner_column,
                        source_file=rel_src,
                    )
                )

    return drifts
