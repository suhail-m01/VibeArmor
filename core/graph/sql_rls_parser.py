"""PostgreSQL / Supabase SQL schema, RLS policy, FK, DPDP PII, and RPC parser powered by sqlglot."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import sqlglot
from sqlglot import exp

logging.getLogger("sqlglot").setLevel(logging.ERROR)

DPDP_PII_PATTERNS = {
    "aadhaar",
    "aadhar",
    "pan",
    "pan_number",
    "gstin",
    "phone",
    "mobile",
    "phone_number",
    "home_address",
    "shipping_address",
    "address",
    "dob",
    "date_of_birth",
    "bank_account",
    "upi_id",
    "passport",
}

OWNER_COLUMN_CANDIDATES = (
    "user_id",
    "owner_id",
    "customer_id",
    "buyer_id",
    "author_id",
    "seller_id",
    "created_by",
    "profile_id",
)


@dataclass
class SqlPolicyInfo:
    name: str
    table: str
    command: str  # "ALL" | "SELECT" | "INSERT" | "UPDATE" | "DELETE"
    roles: List[str]
    using_expr: str
    with_check_expr: str
    is_vacuous_true: bool
    line: int = 1


@dataclass
class SqlTableInfo:
    name: str
    file_path: str
    line: int
    columns: Dict[str, str] = field(default_factory=dict)
    foreign_keys: Dict[str, Tuple[str, str]] = field(default_factory=dict)  # col -> (ref_table, ref_col)
    owner_column: Optional[str] = None
    dpdp_pii_columns: List[str] = field(default_factory=list)
    rls_enabled: bool = False
    policies: List[SqlPolicyInfo] = field(default_factory=list)
    has_complex_tenant_role_columns: bool = False
    policy_comment_hint: str = ""


@dataclass
class SqlRpcFunctionInfo:
    name: str
    file_path: str
    line: int
    security_definer: bool
    has_pinned_search_path: bool
    revoked_public_anon: bool
    arg_types: str = ""


def _extract_pg_arg_types(raw_params: str) -> str:
    """Convert PostgreSQL parameter list e.g. 'p_event text, p_limit int default 10' -> 'text, int'."""
    s = raw_params.strip()
    if not s:
        return ""
    parts: List[str] = []
    depth = 0
    cur: List[str] = []
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur).strip())

    out_types: List[str] = []
    pg_type_starters = {
        "uuid", "text", "varchar", "char", "int", "int2", "int4", "int8", "integer",
        "bigint", "smallint", "boolean", "bool", "json", "jsonb", "numeric", "decimal",
        "real", "float", "float4", "float8", "double", "date", "time", "timetz",
        "timestamp", "timestamptz", "interval", "bytea", "inet", "cidr", "record",
    }
    for p in parts:
        # Strip DEFAULT /= clauses
        p_clean = re.split(r"\bDEFAULT\b|=", p, maxsplit=1, flags=re.IGNORECASE)[0].strip()
        if not p_clean:
            continue
        tokens = p_clean.split()
        if tokens and tokens[0].upper() in ("IN", "INOUT", "VARIADIC"):
            tokens = tokens[1:]
        elif tokens and tokens[0].upper() == "OUT":
            continue
        if not tokens:
            continue
        if len(tokens) == 1 or tokens[0].lower().rstrip("[]") in pg_type_starters:
            out_types.append(" ".join(tokens))
        else:
            out_types.append(" ".join(tokens[1:]))
    return ", ".join(out_types)


@dataclass
class SqlSchemaAnalysis:
    tables: Dict[str, SqlTableInfo] = field(default_factory=dict)
    functions: Dict[str, SqlRpcFunctionInfo] = field(default_factory=dict)
    parse_errors: List[str] = field(default_factory=list)


def _clean_ident(raw: str) -> str:
    s = raw.strip().strip('"').strip("'")
    if "." in s:
        s = s.split(".")[-1].strip('"')
    return s.lower()


def _line_of_offset(source: str, pattern: str) -> int:
    m = re.search(pattern, source, re.IGNORECASE)
    if not m:
        return 1
    return source[: m.start()].count("\n") + 1


def parse_sql_files(sql_files: List[Tuple[str, str]]) -> SqlSchemaAnalysis:
    """Parse a list of (file_path, sql_content) pairs into a unified SQL & RLS catalog."""
    result = SqlSchemaAnalysis()

    for file_path, content in sql_files:
        # 1. Validate SQL syntax via sqlglot + extract CREATE TABLE ASTs
        # Strip PostgreSQL PL/pgSQL DO $$...$$ blocks gently for AST pass while keeping regex checks on full text
        cleaned_for_ast = re.sub(r"CREATE\s+(?:OR\s+REPLACE\s+)?POLICY\b[^;]+;", "-- policy;", content, flags=re.IGNORECASE | re.DOTALL)
        cleaned_for_ast = re.sub(r"ALTER\s+TABLE\b[^;]+ENABLE\s+ROW\s+LEVEL\s+SECURITY\s*;", "-- rls;", cleaned_for_ast, flags=re.IGNORECASE)

        try:
            statements = sqlglot.parse(cleaned_for_ast, read="postgres")
        except Exception as exc:
            result.parse_errors.append(f"{file_path}: {exc}")
            statements = []

        for stmt in statements:
            if isinstance(stmt, exp.Create) and stmt.kind and stmt.kind.upper() == "TABLE":
                schema_node = stmt.this
                tbl_expr = schema_node.this if isinstance(schema_node, exp.Schema) else schema_node
                tbl_name = _clean_ident(tbl_expr.sql())
                ln = _line_of_offset(content, rf"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?\"?{re.escape(tbl_name)}\"?")

                tbl_info = result.tables.get(tbl_name) or SqlTableInfo(name=tbl_name, file_path=file_path, line=ln)

                if isinstance(schema_node, exp.Schema):
                    for expr_item in schema_node.expressions:
                        if isinstance(expr_item, exp.ColumnDef):
                            col_name = _clean_ident(expr_item.this.sql())
                            col_type = expr_item.kind.sql() if expr_item.kind else "TEXT"
                            tbl_info.columns[col_name] = col_type

                            # Inline REFERENCES parent(col)
                            item_sql = expr_item.sql(dialect="postgres")
                            m_fk = re.search(r"REFERENCES\s+(?:public\.)?([A-Za-z0-9_]+)\s*\(\s*([A-Za-z0-9_]+)\s*\)", item_sql, re.IGNORECASE)
                            if m_fk:
                                tbl_info.foreign_keys[col_name] = (_clean_ident(m_fk.group(1)), _clean_ident(m_fk.group(2)))

                        elif isinstance(expr_item, exp.ForeignKey):
                            fk_sql = expr_item.sql(dialect="postgres")
                            m_fk2 = re.search(
                                r"FOREIGN\s+KEY\s*\(\s*([A-Za-z0-9_]+)\s*\)\s*REFERENCES\s+(?:public\.)?([A-Za-z0-9_]+)\s*\(\s*([A-Za-z0-9_]+)\s*\)",
                                fk_sql,
                                re.IGNORECASE,
                            )
                            if m_fk2:
                                tbl_info.foreign_keys[_clean_ident(m_fk2.group(1))] = (
                                    _clean_ident(m_fk2.group(2)),
                                    _clean_ident(m_fk2.group(3)),
                                )

                # Detect owner column, DPDP PII columns, and complex multi-tenant business-policy columns
                for cand in OWNER_COLUMN_CANDIDATES:
                    if cand in tbl_info.columns:
                        tbl_info.owner_column = cand
                        break
                if tbl_name in ("users", "profiles") and "id" in tbl_info.columns and not tbl_info.owner_column:
                    tbl_info.owner_column = "id"

                for col in tbl_info.columns:
                    if col in DPDP_PII_PATTERNS or any(col.endswith(f"_{p}") for p in ("phone", "aadhaar", "pan", "address")):
                        if col not in tbl_info.dpdp_pii_columns:
                            tbl_info.dpdp_pii_columns.append(col)

                col_set = set(tbl_info.columns.keys())
                if ({"org_id", "tenant_id", "department_id"} & col_set) and (
                    {"approval_limit_inr", "required_role", "min_approver_tier", "refund_amount_inr"} & col_set
                ):
                    tbl_info.has_complex_tenant_role_columns = True

                result.tables[tbl_name] = tbl_info

        # Capture domain policy comments immediately preceding a CREATE TABLE
        for m_comment in re.finditer(
            r"--\s*(?:POLICY_SPEC|BUSINESS_RULE):([^\n]+)\n\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_.\"]+)",
            content,
            re.IGNORECASE,
        ):
            hint = m_comment.group(1).strip()
            target_tbl = _clean_ident(m_comment.group(2))
            if target_tbl in result.tables:
                result.tables[target_tbl].policy_comment_hint = hint

        # 2. Parse ALTER TABLE ... ENABLE / DISABLE ROW LEVEL SECURITY
        for m_rls in re.finditer(
            r"ALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?([A-Za-z0-9_.\"]+)\s+(ENABLE|DISABLE)\s+ROW\s+LEVEL\s+SECURITY",
            content,
            re.IGNORECASE,
        ):
            raw_tbl_ref = m_rls.group(1).strip().strip('"').lower()
            if raw_tbl_ref.startswith(("storage.", "realtime.", "auth.", "vault.", "supabase_functions.")):
                continue
            tname = _clean_ident(m_rls.group(1))
            action = m_rls.group(2).upper()
            ln_rls = content[: m_rls.start()].count("\n") + 1
            if tname not in result.tables:
                result.tables[tname] = SqlTableInfo(name=tname, file_path=file_path, line=ln_rls)
            result.tables[tname].rls_enabled = action == "ENABLE"

        # 3. Parse CREATE POLICY statements
        policy_regex = re.compile(
            r"CREATE\s+POLICY\s+(\"[^\"]+\"|[A-Za-z0-9_]+)\s+ON\s+([A-Za-z0-9_.\"]+)"
            r"(?:\s+AS\s+(?:PERMISSIVE|RESTRICTIVE))?"
            r"(?:\s+FOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE))?"
            r"(?:\s+TO\s+([A-Za-z0-9_,\s]+?))?"
            r"(?:\s+USING\s*\((.+?)\))?"
            r"(?:\s+WITH\s+CHECK\s*\((.+?)\))?\s*;",
            re.IGNORECASE | re.DOTALL,
        )
        for mp in policy_regex.finditer(content):
            raw_pol_tbl = mp.group(2).strip().strip('"').lower()
            if raw_pol_tbl.startswith(("storage.", "realtime.", "auth.", "vault.", "supabase_functions.")):
                continue
            pol_name = mp.group(1).strip('"')
            tname = _clean_ident(mp.group(2))
            cmd = (mp.group(3) or "ALL").upper()
            roles_raw = mp.group(4) or "public"
            roles = [r.strip().lower() for r in roles_raw.split(",") if r.strip()]
            using_ex = (mp.group(5) or "").strip()
            check_ex = (mp.group(6) or "").strip()
            ln = content[: mp.start()].count("\n") + 1

            is_vacuous = using_ex.lower() in ("true", "1=1", "1 = 1") or check_ex.lower() in ("true", "1=1", "1 = 1")
            pol = SqlPolicyInfo(
                name=pol_name,
                table=tname,
                command=cmd,
                roles=roles,
                using_expr=using_ex,
                with_check_expr=check_ex,
                is_vacuous_true=is_vacuous,
                line=ln,
            )
            if tname not in result.tables:
                result.tables[tname] = SqlTableInfo(name=tname, file_path=file_path, line=ln)
            result.tables[tname].policies.append(pol)

        # 4. Parse SECURITY DEFINER RPC functions & REVOKE statements
        fn_regex = re.compile(
            r"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([A-Za-z0-9_.\"]+)\s*\(([^)]*)\)(.+?)LANGUAGE\s+\w+",
            re.IGNORECASE | re.DOTALL,
        )
        for mf in fn_regex.finditer(content):
            fname = _clean_ident(mf.group(1))
            raw_params = mf.group(2)
            arg_types = _extract_pg_arg_types(raw_params)
            full_chunk = content[mf.start(): min(len(content), mf.end() + 400)]
            sec_def = bool(re.search(r"SECURITY\s+DEFINER", full_chunk, re.IGNORECASE))
            pinned_sp = bool(re.search(r"SET\s+search_path\s*=\s*(?:''|\"\"|public,\s*pg_temp|public,pg_temp|pg_catalog)", full_chunk, re.IGNORECASE))
            revoked = bool(
                re.search(
                    rf"REVOKE\s+(?:ALL|EXECUTE)\s+ON\s+FUNCTION\s+(?:public\.)?{re.escape(fname)}\b[^;]*FROM\s+[^;]*(?:anon|public)",
                    content,
                    re.IGNORECASE,
                )
            )
            ln = content[: mf.start()].count("\n") + 1
            result.functions[fname] = SqlRpcFunctionInfo(
                name=fname,
                file_path=file_path,
                line=ln,
                security_definer=sec_def,
                has_pinned_search_path=pinned_sp,
                revoked_public_anon=revoked,
                arg_types=arg_types,
            )

        # Also catch ALTER FUNCTION ... SET search_path = '' in later hardening migrations!
        for m_alt_fn in re.finditer(
            r"ALTER\s+FUNCTION\s+([A-Za-z0-9_.\"]+)\s*\([^)]*\)\s+SET\s+search_path\s*=",
            content,
            re.IGNORECASE,
        ):
            fname = _clean_ident(m_alt_fn.group(1))
            if fname in result.functions:
                result.functions[fname].has_pinned_search_path = True

        for m_rev in re.finditer(
            r"REVOKE\s+(?:ALL|EXECUTE)\s+ON\s+FUNCTION\s+([A-Za-z0-9_.\"]+)\s*(?:\([^)]*\))?\s+FROM\s+([^;]+);",
            content,
            re.IGNORECASE,
        ):
            fname = _clean_ident(m_rev.group(1))
            who = m_rev.group(2).lower()
            if fname in result.functions and ("anon" in who or "public" in who):
                result.functions[fname].revoked_public_anon = True

    return result
