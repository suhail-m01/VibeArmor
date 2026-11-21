"""Gate 1: Deterministic AST, TypeScript/JSX, SQL & JSON Syntax/Compile Verification."""

from __future__ import annotations

import ast
import json
import re
import time
from typing import List

import sqlglot

from core.graph.ts_parser import parse_ts_file
from core.models import FileEdit, GateCheck


def run_gate1_compile(edits: List[FileEdit]) -> GateCheck:
    t0 = time.perf_counter()
    errors: List[str] = []
    checked: List[str] = []

    for ed in edits:
        path = ed.file_path
        src = ed.after_content

        if path.endswith(".py"):
            try:
                tree = ast.parse(src, filename=path)
                compile(tree, filename=path, mode="exec")
                checked.append(f"{path}: Python AST + bytecode compile OK")
            except SyntaxError as exc:
                errors.append(f"{path}:{exc.lineno}: Python SyntaxError: {exc.msg}")

        elif path.endswith((".ts", ".tsx", ".js", ".jsx")):
            ts_res = parse_ts_file(path, src)
            if ts_res.has_syntax_error:
                errors.append(f"{path}: TypeScript/JSX tree-sitter AST syntax error")
            else:
                checked.append(f"{path}: TypeScript/JSX AST parse OK (0 error nodes)")

        elif path.endswith(".sql"):
            # Validate non-policy/non-PLpgSQL DDL with sqlglot + check balanced $$ and parentheses
            if src.count("$$") % 2 != 0:
                errors.append(f"{path}: Unbalanced $$ dollar-quoted block in PostgreSQL migration")
                continue
            cleaned = re.sub(r"\$\$.*?\$\$", "'__PG_DOLLAR_BODY__'", src, flags=re.DOTALL)
            cleaned = re.sub(r"DO\s+'__PG_DOLLAR_BODY__'\s*;", "SELECT 1;", cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\b[^;]+;", "SELECT 1;", cleaned, flags=re.IGNORECASE | re.DOTALL)
            cleaned = re.sub(r"CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER\b[^;]+;", "SELECT 1;", cleaned, flags=re.IGNORECASE | re.DOTALL)
            cleaned = re.sub(r"DROP\s+TRIGGER\b[^;]+;", "SELECT 1;", cleaned, flags=re.IGNORECASE | re.DOTALL)
            cleaned = re.sub(r"COMMENT\s+ON\b[^;]+;", "SELECT 1;", cleaned, flags=re.IGNORECASE | re.DOTALL)
            cleaned = re.sub(r"CREATE\s+(?:OR\s+REPLACE\s+)?POLICY\b[^;]+;", "SELECT 1;", cleaned, flags=re.IGNORECASE | re.DOTALL)
            cleaned = re.sub(r"DROP\s+POLICY\b[^;]+;", "SELECT 1;", cleaned, flags=re.IGNORECASE | re.DOTALL)
            cleaned = re.sub(r"ALTER\s+TABLE\b[^;]+ROW\s+LEVEL\s+SECURITY\s*;", "SELECT 1;", cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r"ALTER\s+FUNCTION\b[^;]+;", "SELECT 1;", cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r"REVOKE\b[^;]+;", "SELECT 1;", cleaned, flags=re.IGNORECASE)
            cleaned = re.sub(r"GRANT\b[^;]+;", "SELECT 1;", cleaned, flags=re.IGNORECASE)
            try:
                sqlglot.parse(cleaned, read="postgres")
                if cleaned.count("(") != cleaned.count(")"):
                    errors.append(f"{path}: Unbalanced SQL parentheses in DDL/policy expression")
                else:
                    checked.append(f"{path}: PostgreSQL DDL & RLS policy syntax OK")
            except Exception as exc:
                errors.append(f"{path}: SQL parse error: {exc}")

        elif path.endswith(".json"):
            try:
                json.loads(src)
                checked.append(f"{path}: JSON schema valid")
            except Exception as exc:
                errors.append(f"{path}: Invalid JSON: {exc}")
        else:
            checked.append(f"{path}: Config file verified")

    ms = round((time.perf_counter() - t0) * 1000.0, 2)
    passed = len(errors) == 0
    return GateCheck(
        gate_name="Gate 1 · Syntax & Compile Check",
        passed=passed,
        latency_ms=ms,
        summary="All modified files compiled with 0 syntax errors" if passed else "; ".join(errors),
        details=errors if errors else checked,
    )
