"""Python AST parser for routes, source-to-sink taint flows, payment HMAC guards, and secrets."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class PyRouteInfo:
    func_name: str
    http_method: str
    route_path: str
    has_auth_dependency: bool
    line_start: int
    line_end: int
    params: List[str] = field(default_factory=list)


@dataclass
class PyTaintFinding:
    sink_kind: str
    cwe: str
    func_name: str
    line_start: int
    line_end: int
    snippet: str
    tainted_vars: List[str] = field(default_factory=list)
    dynamic_reflection: bool = False


@dataclass
class PyFileAnalysis:
    file_path: str
    has_syntax_error: bool
    syntax_error_msg: str = ""
    imports: Set[str] = field(default_factory=set)
    imported_symbols: Dict[str, Set[str]] = field(default_factory=dict)
    routes: List[PyRouteInfo] = field(default_factory=list)
    taint_findings: List[PyTaintFinding] = field(default_factory=list)
    string_assignments: List[Tuple[str, str, int]] = field(default_factory=list)


AUTH_KEYWORDS = {
    "get_current_user",
    "require_user",
    "require_auth",
    "verify_token",
    "verify_jwt",
    "jwt_required",
    "login_required",
    "HTTPBearer",
    "OAuth2PasswordBearer",
}


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = []
        cur: ast.AST = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        elif isinstance(cur, ast.Call):
            parts.append(_call_name(cur) or "<call>")
        return ".".join(reversed(parts))
    return ""


def _expr_uses_taint(expr: ast.AST, tainted: Set[str]) -> List[str]:
    """Return tainted variable names referenced inside expr, ignoring UPPER_CASE constants."""
    hits: List[str] = []
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Name):
            if sub.id in tainted and not sub.id.isupper():
                hits.append(sub.id)
        elif isinstance(sub, ast.Call):
            cname = _call_name(sub)
            if any(
                cname.startswith(src)
                for src in (
                    "request.args",
                    "request.form",
                    "request.values",
                    "request.get_json",
                    "request.json",
                    "input",
                )
            ):
                hits.append(cname)
        elif isinstance(sub, ast.Attribute):
            if isinstance(sub.value, ast.Name) and sub.value.id == "request" and sub.attr in (
                "args",
                "form",
                "files",
                "json",
                "data",
                "values",
                "cookies",
                "headers",
                "query_params",
                "GET",
                "POST",
            ):
                hits.append(f"request.{sub.attr}")
    return list(dict.fromkeys(hits))


def _is_formatted_string(expr: ast.AST) -> bool:
    """True if expr constructs a string via f-string, %, .format(), or + concatenation."""
    if isinstance(expr, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in expr.values)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Mod, ast.Add)):
        return True
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
        return True
    return False


def _slice_lines(lines: List[str], start: int, end: int) -> str:
    s = max(0, start - 1)
    e = min(len(lines), end)
    return "\n".join(lines[s:e])


def parse_py_file(file_path: str, content: Optional[str] = None) -> PyFileAnalysis:
    source = content if content is not None else Path(file_path).read_text(encoding="utf-8", errors="replace")
    lines = source.splitlines()

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as exc:
        return PyFileAnalysis(
            file_path=file_path,
            has_syntax_error=True,
            syntax_error_msg=f"Line {exc.lineno}: {exc.msg}",
        )

    analysis = PyFileAnalysis(file_path=file_path, has_syntax_error=False)

    # 1. Top-level & module imports + string assignments
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_pkg = alias.name.split(".")[0]
                analysis.imports.add(root_pkg)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                root_pkg = node.module.split(".")[0]
                analysis.imports.add(root_pkg)
                syms = {a.name for a in node.names}
                analysis.imported_symbols.setdefault(root_pkg, set()).update(syms)
        elif isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                val = node.value.value
                if len(val) >= 8:
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            analysis.string_assignments.append((tgt.id, val, node.lineno))
        elif isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if (
                    isinstance(k, ast.Constant)
                    and isinstance(k.value, str)
                    and isinstance(v, ast.Constant)
                    and isinstance(v.value, str)
                    and len(v.value) >= 10
                ):
                    analysis.string_assignments.append((k.value, v.value, k.lineno))

    # 2. Analyze every function / async function for routes, taint flows, payment HMAC, crypto, deserialization
    func_nodes = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

    for fn in func_nodes:
        fn_start = fn.lineno
        fn_end = getattr(fn, "end_lineno", fn.lineno + 10)
        fn_src = _slice_lines(lines, fn_start, fn_end)
        params = [a.arg for a in fn.args.args if a.arg not in ("self", "cls", "db", "session")]

        # Route decorator check
        route_method = None
        route_path = ""
        has_auth = False
        for dec in fn.decorator_list:
            dec_src = ast.unparse(dec) if hasattr(ast, "unparse") else ""
            if any(k in dec_src for k in AUTH_KEYWORDS):
                has_auth = True
            m_rt = re.search(r"\.(get|post|put|delete|patch|route)\(\s*['\"]([^'\"]+)['\"]", dec_src)
            if m_rt:
                route_method = m_rt.group(1).upper()
                route_path = m_rt.group(2)
                if "methods=" in dec_src and "POST" in dec_src.upper():
                    route_method = "POST"

        # Check parameter defaults for FastAPI Depends(auth)
        for d in fn.args.defaults + [x for x in fn.args.kw_defaults if x is not None]:
            d_src = ast.unparse(d) if hasattr(ast, "unparse") else ""
            if any(k in d_src for k in AUTH_KEYWORDS):
                has_auth = True
        if any(k in fn_src for k in AUTH_KEYWORDS):
            has_auth = True

        if route_method:
            analysis.routes.append(
                PyRouteInfo(
                    func_name=fn.name,
                    http_method=route_method,
                    route_path=route_path,
                    has_auth_dependency=has_auth,
                    line_start=fn_start,
                    line_end=fn_end,
                    params=params,
                )
            )

        # Intraprocedural taint tracking
        tainted: Set[str] = set(params)
        sanitized_paths: Set[str] = set()

        # Pass 1: propagate taint across assignments inside function
        for stmt in ast.walk(fn):
            if isinstance(stmt, ast.Assign):
                val_src = ast.unparse(stmt.value) if hasattr(ast, "unparse") else ""
                # Detect path sanitization (basename / secure_filename / resolve)
                if any(s in val_src for s in ("os.path.basename", "secure_filename", "realpath")):
                    for tgt in stmt.targets:
                        if isinstance(tgt, ast.Name):
                            sanitized_paths.add(tgt.id)
                            tainted.discard(tgt.id)
                    continue

                # Safe SQL '?' placeholder builders (e.g. ",".join("?" for _ in ids)) are NOT user taint
                if ".join(" in val_src and ("'?'" in val_src or '"?"' in val_src):
                    for tgt in stmt.targets:
                        if isinstance(tgt, ast.Name):
                            tainted.discard(tgt.id)
                    continue

                used_taint = _expr_uses_taint(stmt.value, tainted)
                if used_taint:
                    for tgt in stmt.targets:
                        if isinstance(tgt, ast.Name) and not tgt.id.isupper():
                            tainted.add(tgt.id)

        # Pass 2: inspect sinks inside function
        for sub in ast.walk(fn):
            if not isinstance(sub, ast.Call):
                continue
            cname = _call_name(sub)
            ln_s = sub.lineno
            ln_e = getattr(sub, "end_lineno", ln_s)
            snip = _slice_lines(lines, ln_s, ln_e)

            # A. SQL Injection (CWE-089)
            if cname.endswith((".execute", ".executemany", ".raw")) or cname in ("text", "execute_query"):
                if sub.args:
                    q_arg = sub.args[0]
                    has_bound_params = len(sub.args) >= 2
                    t_hits = _expr_uses_taint(q_arg, tainted)
                    # Exclude safe parameterized IN (?, ?, ?) clauses where every f-string slot is a '?' join builder
                    is_safe_placeholder_fstr = False
                    if has_bound_params and isinstance(q_arg, ast.JoinedStr):
                        fvals = [v for v in q_arg.values if isinstance(v, ast.FormattedValue)]
                        if fvals and all(
                            ".join(" in (ast.unparse(fv.value) if hasattr(ast, "unparse") else "")
                            and ("'?'" in (ast.unparse(fv.value) if hasattr(ast, "unparse") else "") or '"?"' in (ast.unparse(fv.value) if hasattr(ast, "unparse") else ""))
                            for fv in fvals
                        ):
                            is_safe_placeholder_fstr = True
                    # Exclude inner helper functions (e.g. `def one(sql: str): con.execute(sql)`) called exclusively with string literals
                    is_constant_sql_helper = False
                    if isinstance(q_arg, ast.Name) and q_arg.id in params and not route_method:
                        helper_calls = [
                            c for c in ast.walk(tree)
                            if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == fn.name and c.args
                        ]
                        if helper_calls and all(isinstance(c.args[0], ast.Constant) and isinstance(c.args[0].value, str) for c in helper_calls):
                            is_constant_sql_helper = True
                    # Check if q_arg was assigned from a formatted string variable
                    q_is_formatted = (
                        not is_safe_placeholder_fstr
                        and not is_constant_sql_helper
                        and (
                            _is_formatted_string(q_arg)
                            or (isinstance(q_arg, ast.Name) and q_arg.id in tainted and not has_bound_params)
                        )
                    )
                    if t_hits and q_is_formatted:
                        analysis.taint_findings.append(
                            PyTaintFinding("sql_injection", "CWE-089", fn.name, ln_s, ln_e, snip, t_hits)
                        )

            # B. OS Command Injection (CWE-078)
            elif cname in ("os.system", "os.popen") or cname.startswith("subprocess."):
                kw_map = {kw.arg: kw.value for kw in sub.keywords if kw.arg}
                shell_true = (
                    cname in ("os.system", "os.popen")
                    or (isinstance(kw_map.get("shell"), ast.Constant) and kw_map["shell"].value is True)
                )
                if sub.args:
                    t_hits = _expr_uses_taint(sub.args[0], tainted)
                    if t_hits and (shell_true or cname in ("os.system", "os.popen")):
                        analysis.taint_findings.append(
                            PyTaintFinding("cmd_injection", "CWE-078", fn.name, ln_s, ln_e, snip, t_hits)
                        )

            # C. Code Injection / Eval / Exec / Dynamic Compile (CWE-094)
            elif cname in ("eval", "exec") or (cname == "compile" and len(sub.args) >= 3):
                t_hits = _expr_uses_taint(sub.args[0], tainted) if sub.args else ["input"]
                if cname != "compile" or t_hits:
                    analysis.taint_findings.append(
                        PyTaintFinding("code_eval", "CWE-094", fn.name, ln_s, ln_e, snip, t_hits or ["untrusted_expr"])
                    )

            # D. Unsafe Deserialization (CWE-502: pickle.loads, yaml.load without SafeLoader)
            elif cname in ("pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads"):
                analysis.taint_findings.append(
                    PyTaintFinding("unsafe_deserialization", "CWE-502", fn.name, ln_s, ln_e, snip, ["serialized_bytes"])
                )
            elif cname == "yaml.load":
                kw_src = ast.unparse(sub) if hasattr(ast, "unparse") else snip
                if "SafeLoader" not in kw_src and "safe_load" not in kw_src:
                    analysis.taint_findings.append(
                        PyTaintFinding("unsafe_yaml_load", "CWE-502", fn.name, ln_s, ln_e, snip, ["yaml_payload"])
                    )

            # E. Path Traversal (CWE-022)
            elif cname in ("open", "send_file", "os.remove", "os.unlink", "shutil.rmtree"):
                if sub.args:
                    p_arg = sub.args[0]
                    t_hits = [v for v in _expr_uses_taint(p_arg, tainted) if v not in sanitized_paths]
                    if t_hits and "secure_filename" not in fn_src and "os.path.basename" not in fn_src and "realpath" not in fn_src:
                        analysis.taint_findings.append(
                            PyTaintFinding("path_traversal", "CWE-022", fn.name, ln_s, ln_e, snip, t_hits)
                        )

            # F. XSS / Server-Side Template Injection (CWE-079)
            elif cname in ("render_template_string", "jinja2.Template", "Template"):
                if sub.args:
                    t_hits = _expr_uses_taint(sub.args[0], tainted)
                    if t_hits:
                        analysis.taint_findings.append(
                            PyTaintFinding("xss_ssti", "CWE-079", fn.name, ln_s, ln_e, snip, t_hits)
                        )
            elif cname in ("make_response", "HTMLResponse") and sub.args:
                if _is_formatted_string(sub.args[0]) and _expr_uses_taint(sub.args[0], tainted) and "escape(" not in fn_src:
                    analysis.taint_findings.append(
                        PyTaintFinding("xss_reflected", "CWE-079", fn.name, ln_s, ln_e, snip, _expr_uses_taint(sub.args[0], tainted))
                    )
            elif cname in ("Environment", "jinja2.Environment"):
                kw_src = ast.unparse(sub) if hasattr(ast, "unparse") else snip
                if "autoescape=True" not in kw_src and "select_autoescape" not in kw_src:
                    analysis.taint_findings.append(
                        PyTaintFinding("xss_ssti", "CWE-079", fn.name, ln_s, ln_e, snip, ["jinja_autoescape_off"])
                    )

            # G. SSRF (CWE-918)
            elif cname in ("requests.get", "requests.post", "urllib.request.urlopen", "httpx.get", "httpx.post"):
                if sub.args:
                    t_hits = _expr_uses_taint(sub.args[0], tainted)
                    if t_hits and "allowlist" not in fn_src.lower() and "allowed_hosts" not in fn_src.lower():
                        analysis.taint_findings.append(
                            PyTaintFinding("ssrf", "CWE-918", fn.name, ln_s, ln_e, snip, t_hits)
                        )

            # H. Weak Crypto / Broken Hash / XML XXE / Unverified SSL (SecurityEval CWEs)
            elif cname in ("hashlib.md5", "hashlib.sha1", "Crypto.Cipher.DES.new", "DES.new"):
                if "usedforsecurity=False" not in snip:
                    analysis.taint_findings.append(
                        PyTaintFinding("weak_crypto", "CWE-327", fn.name, ln_s, ln_e, snip, ["weak_primitive"])
                    )
            elif cname.endswith(("ET.fromstring", "ElementTree.fromstring", "ElementTree.parse", "etree.fromstring", "etree.parse", "xml.sax.make_parser", "etree.XMLParser")):
                if "defusedxml" not in source and "resolve_entities=False" not in snip:
                    analysis.taint_findings.append(
                        PyTaintFinding("xxe_xml", "CWE-611", fn.name, ln_s, ln_e, snip, ["xml_input"])
                    )
            elif cname in ("jwt.decode", "jwt.process_jwt"):
                if cname == "jwt.process_jwt" or "verify_signature\": False" in snip or "verify=False" in snip or "options={\"verify_signature\": False}" in snip:
                    analysis.taint_findings.append(
                        PyTaintFinding("jwt_unverified", "CWE-347", fn.name, ln_s, ln_e, snip, ["jwt_token"])
                    )
            elif cname in ("redirect", "HttpResponseRedirect") and sub.args:
                t_hits = _expr_uses_taint(sub.args[0], tainted)
                if t_hits and "urlparse" not in fn_src:
                    analysis.taint_findings.append(
                        PyTaintFinding("open_redirect", "CWE-601", fn.name, ln_s, ln_e, snip, t_hits)
                    )

            # I. Dynamic Reflection Boundary (getattr dispatch on untrusted input -> Abstention candidate!)
            elif cname == "getattr" and len(sub.args) >= 2:
                t_hits = _expr_uses_taint(sub.args[1], tainted)
                if t_hits:
                    analysis.taint_findings.append(
                        PyTaintFinding(
                            "dynamic_reflection_taint",
                            "CWE-470",
                            fn.name,
                            ln_s,
                            ln_e,
                            snip,
                            t_hits,
                            dynamic_reflection=True,
                        )
                    )

        # J. Razorpay Payment Verification Bypass (India Vibe-Stack Flaw!)
        if ("razorpay_payment_id" in fn_src or "payment_id" in fn_src) and re.search(
            r"['\"]paid['\"]|status\s*=\s*['\"]captured['\"]", fn_src, re.IGNORECASE
        ):
            fn_calls = [_call_name(c) for c in ast.walk(fn) if isinstance(c, ast.Call)]
            has_hmac_guard = any(
                cn.endswith("compare_digest") or cn == "verify_payment_signature" or cn.endswith("verify_payment_signature")
                for cn in fn_calls
            )
            if not has_hmac_guard:
                analysis.taint_findings.append(
                    PyTaintFinding(
                        "razorpay_spoof",
                        "CWE-345",
                        fn.name,
                        fn_start,
                        fn_end,
                        fn_src[:260],
                        ["razorpay_payment_id"],
                    )
                )

    return analysis
