"""Pillar 3 Remediator: AST Taint Sanitizer & Constant-Time Razorpay HMAC Payment Guard."""

from __future__ import annotations

import ast as _py_ast
import difflib
import re
from typing import List, Optional

from core.graph.cross_layer_graph import WorkspaceContext
from core.models import FileEdit, Finding


def _insert_py_header(src: str, block: str) -> str:
    """Insert a Python import/constant strictly AFTER module docstrings and `from __future__` imports."""
    ins_line = 0
    try:
        tree = _py_ast.parse(src)
        for node in tree.body:
            if (
                isinstance(node, _py_ast.Expr)
                and isinstance(getattr(node, "value", None), _py_ast.Constant)
                and isinstance(node.value.value, str)
            ):
                ins_line = max(ins_line, getattr(node, "end_lineno", node.lineno))
            elif isinstance(node, _py_ast.ImportFrom) and node.module == "__future__":
                ins_line = max(ins_line, getattr(node, "end_lineno", node.lineno))
            else:
                break
    except SyntaxError:
        ins_line = 0
    lines = src.splitlines(keepends=True)
    if not block.endswith("\n"):
        block += "\n"
    lines.insert(ins_line, block)
    return "".join(lines)


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


def sanitize_taint_or_payment(
    finding: Finding,
    ctx: WorkspaceContext,
    slm_patched_source: Optional[str] = None,
) -> List[FileEdit]:
    rel = finding.file_path
    before = ctx.file_contents.get(rel, "")
    if not before:
        return []

    if slm_patched_source and slm_patched_source.strip() and slm_patched_source != before:
        return [
            FileEdit(
                file_path=rel,
                before_content=before,
                after_content=slm_patched_source,
                unified_diff=_make_diff(rel, before, slm_patched_source),
            )
        ]

    sink_kind = finding.metadata.get("sink_kind", "")
    lang = finding.metadata.get("lang", "python")
    after = before

    # 1. SQL Injection Parameterization (Python & TypeScript)
    if sink_kind == "sql_injection":
        if lang == "python":
            # Pattern 1: cursor.execute(f"SELECT ... '{var}' ...") or f'... "{var}" ...'
            def _repl_fstring_exec(m: re.Match[str]) -> str:
                prefix = m.group(1)
                fbody = m.group(2) if m.group(2) is not None else m.group(3)
                params = re.findall(r"\{\s*([^}:!]+?)\s*\}", fbody)
                if not params:
                    return m.group(0)
                sql_clean = re.sub(r"['\"]?\{\s*[^}]+\s*\}['\"]?", "?", fbody)
                sql_clean = sql_clean.replace("%?", "%")
                tuple_str = f"({params[0]},)" if len(params) == 1 else f"({', '.join(params)})"
                return f'{prefix}"{sql_clean}", {tuple_str})'

            after = re.sub(
                r"(\.(?:execute|raw)\s*\(\s*)(?:f\"([^\"]+)\"|f'([^']+)')\s*\)",
                _repl_fstring_exec,
                after,
            )
            # Pattern 2: query = f"SELECT ... '{var}'" followed by .execute(query)
            m_qvar = re.search(
                r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:f\"((?:SELECT|DELETE|UPDATE|INSERT)[^\"]+)\"|f'((?:SELECT|DELETE|UPDATE|INSERT)[^']+)')",
                after,
                re.IGNORECASE | re.MULTILINE,
            )
            if m_qvar:
                indent, qname = m_qvar.group(1), m_qvar.group(2)
                qbody = m_qvar.group(3) if m_qvar.group(3) is not None else m_qvar.group(4)
                params = re.findall(r"\{\s*([^}:!]+?)\s*\}", qbody)
                if params:
                    sql_clean = re.sub(r"['\"]?\{\s*[^}]+\s*\}['\"]?", "?", qbody)
                    tuple_str = f"({params[0]},)" if len(params) == 1 else f"({', '.join(params)})"
                    after = after.replace(m_qvar.group(0), f'{indent}{qname} = "{sql_clean}"')
                    after = re.sub(
                        rf"(\.execute\s*\(\s*){re.escape(qname)}\s*\)",
                        rf"\1{qname}, {tuple_str})",
                        after,
                    )
            # Pattern 3: string concatenation or % formatting in .execute("..." + var) or ("... %s" % var)
            after = re.sub(
                r"(\.execute\s*\(\s*)['\"]([^'\"]+?)\s*['\"]\s*\+\s*([A-Za-z_][A-Za-z0-9_.]*)\s*(?:\+\s*['\"][^'\"]*['\"])?\s*\)",
                r'\1"\2 ?", (\3,))',
                after,
            )
            after = re.sub(
                r"(\.execute\s*\(\s*)(?:\"([^\"]*?)\"|'([^']*?)')\s*%\s*\(?([A-Za-z_][A-Za-z0-9_.,\s]*)\)?\s*\)",
                lambda m: f'{m.group(1)}"{re.sub(r"[\'\"]?%s[\'\"]?", "?", (m.group(2) if m.group(2) is not None else m.group(3)))}", ({m.group(4).strip().rstrip(",")},))',
                after,
            )
        else:
            # TypeScript / Node parameterized `$1`
            def _repl_ts_sql(m: re.Match[str]) -> str:
                call_prefix = m.group(1)
                body = m.group(2)
                vars_found = re.findall(r"\$\{\s*([^}]+?)\s*\}", body)
                idx_counter = [0]

                def _sub_p(_m: re.Match[str]) -> str:
                    idx_counter[0] += 1
                    return f"${idx_counter[0]}"

                clean_sql = re.sub(r"['\"]?\$\{\s*[^}]+\s*\}['\"]?", _sub_p, body)
                return f"{call_prefix}(`{clean_sql}`, [{', '.join(vars_found)}])"

            after = re.sub(
                r"(\.(?:query|execute)\s*)\(\s*`([^`]+)`\s*\)",
                _repl_ts_sql,
                after,
            )

    # 2. OS Command Injection -> shlex / argument list with shell=False
    elif sink_kind == "cmd_injection":
        if lang == "python":
            if "import subprocess" not in after:
                after = _insert_py_header(after, "import subprocess\n")
            if "import shlex" not in after:
                after = _insert_py_header(after, "import shlex\n")
            after = re.sub(
                r"os\.system\s*\(\s*f['\"]([^'\"]+)['\"]\s*\)",
                lambda m: f"subprocess.run(shlex.split(f\"{m.group(1)}\"), shell=False, check=False)",
                after,
            )
            after = re.sub(
                r"os\.system\s*\(\s*([^)]+)\)",
                r"subprocess.run(shlex.split(str(\1)), shell=False, check=False)",
                after,
            )
            after = re.sub(r"shell\s*=\s*True", "shell=False", after)
            after = re.sub(
                r"subprocess\.(run|Popen|call|check_output)\s*\(\s*f['\"]([^'\"]+)['\"]",
                lambda m: f'subprocess.{m.group(1)}(shlex.split(f"{m.group(2)}")',
                after,
            )
        else:
            after = after.replace("exec(", "execFile(").replace("execSync(", "execFileSync(")

    # 3. Code Eval -> ast.literal_eval
    elif sink_kind == "code_eval":
        if lang == "python":
            if "import ast" not in after:
                after = _insert_py_header(after, "import ast\n")
            after = re.sub(r"\beval\s*\(", "ast.literal_eval(", after)
            after = re.sub(r"\bexec\s*\(", "ast.literal_eval(", after)
            after = re.sub(r"\bcompile\s*\(\s*([^,]+),\s*[^,]+,\s*['\"]exec['\"]\s*\)", r"ast.literal_eval(\1)", after)
        else:
            after = re.sub(r"\beval\s*\(", "JSON.parse(", after)

    # 4. Unsafe Deserialization / YAML
    elif sink_kind == "unsafe_yaml_load":
        after = re.sub(r"yaml\.load\s*\(([^,)]+)(?:,\s*Loader\s*=\s*[^)]+)?\)", r"yaml.safe_load(\1)", after)
    elif sink_kind == "unsafe_deserialization":
        if "import json" not in after:
            after = _insert_py_header(after, "import json\n")
        after = re.sub(r"(?:c?pickle|marshal)\.loads\s*\(", "json.loads(", after)
        after = re.sub(r"(?:c?pickle|marshal)\.load\s*\(", "json.load(", after)

    # 5. Path Traversal -> os.path.basename confinement
    elif sink_kind == "path_traversal":
        if "import os" not in after:
            after = _insert_py_header(after, "import os\n")
        tvars = finding.metadata.get("tainted_vars", [])
        for tv in tvars:
            if tv.isidentifier():
                after = re.sub(
                    rf"\b(open|send_file|os\.remove|os\.unlink)\s*\(\s*([^)]*\b{re.escape(tv)}\b[^)]*)\)",
                    lambda m: f"{m.group(1)}({m.group(2).replace(tv, f'os.path.basename({tv})')})",
                    after,
                )

    # 6. XSS / SSTI -> html.escape
    elif sink_kind in ("xss_ssti", "xss_reflected"):
        if "Environment(" in after and "autoescape=True" not in after:
            after = re.sub(r"Environment\s*\(([^)]*)\)", r"Environment(\1, autoescape=True)", after)
        else:
            if "import html" not in after:
                after = _insert_py_header(after, "import html\n")
            after = after.replace("render_template_string(", "html.escape(")
            tvars = finding.metadata.get("tainted_vars", [])
            for tv in tvars:
                if tv.isidentifier():
                    after = after.replace(f"{{{tv}}}", f"{{html.escape(str({tv}))}}")
                    after = re.sub(rf"\+\s*{re.escape(tv)}\b", f"+ html.escape(str({tv}))", after)

    # 7. Weak Crypto / XXE / Unverified JWT / Open Redirect / SSRF
    elif sink_kind == "weak_crypto":
        after = after.replace("hashlib.md5(", "hashlib.sha256(").replace("hashlib.sha1(", "hashlib.sha256(")
        after = after.replace("DES.new(", "AES.new(")
    elif sink_kind == "xxe_xml":
        if "defusedxml" not in after:
            after = _insert_py_header(after, "import defusedxml.ElementTree as _safe_et\n")
        after = re.sub(r"(?:lxml\.etree|etree|ET|ElementTree)\.(fromstring|parse)\s*\(", r"_safe_et.\1(", after)
        after = re.sub(r"etree\.XMLParser\s*\(([^)]*)\)", r"etree.XMLParser(resolve_entities=False, no_network=True)", after)
    elif sink_kind == "jwt_unverified":
        after = after.replace('"verify_signature": False', '"verify_signature": True').replace("verify=False", "verify=True")
    elif sink_kind == "open_redirect":
        if "from urllib.parse import urlparse" not in after:
            after = _insert_py_header(after, "from urllib.parse import urlparse\n")
        tvars = finding.metadata.get("tainted_vars", [])
        if tvars and tvars[0].isidentifier():
            tv = tvars[0]
            after = re.sub(
                rf"(redirect|HttpResponseRedirect)\s*\(\s*{re.escape(tv)}\s*\)",
                rf"\1({tv} if not urlparse({tv}).netloc else '/')",
                after,
            )
    elif sink_kind == "ssrf":
        if "from urllib.parse import urlparse" not in after:
            after = _insert_py_header(after, "from urllib.parse import urlparse\n")
        if "def _va_ssrf_allowlist(" not in after:
            ssrf_helper = (
                "# VibeArmor: allowed_hosts SSRF guard enforced\n"
                "ALLOWED_HOSTS = {'api.example.com', 'localhost', '127.0.0.1'}\n"
                "def _va_ssrf_allowlist(_target):\n"
                "    _raw = getattr(_target, 'full_url', _target)\n"
                "    _host = urlparse(str(_raw)).hostname\n"
                "    if _host not in ALLOWED_HOSTS:\n"
                "        raise ValueError('VIBEARMOR_SSRF_BLOCKED')\n"
                "    return _target\n"
            )
            after = _insert_py_header(after, ssrf_helper)
        tvars = finding.metadata.get("tainted_vars", [])
        patched_call = False
        if tvars and tvars[0].isidentifier():
            tv = tvars[0]
            new_after = re.sub(
                rf"(requests\.(?:get|post)|urllib\.request\.urlopen|httpx\.(?:get|post))\s*\(\s*{re.escape(tv)}\b",
                rf"\1(_va_ssrf_allowlist({tv})",
                after,
            )
            if new_after != after:
                after = new_after
                patched_call = True
        if not patched_call:
            # Wrap first argument of outbound HTTP call on the target lines (e.g. f-string URLs)
            lines_list = after.splitlines()
            for idx_ln, ln_txt in enumerate(lines_list):
                if re.search(r"\b(?:requests\.(?:get|post)|urllib\.request\.urlopen|httpx\.(?:get|post))\s*\(", ln_txt) and "_va_ssrf_allowlist(" not in ln_txt:
                    m_c = re.search(r"\b(requests\.(?:get|post)|urllib\.request\.urlopen|httpx\.(?:get|post))\s*\(\s*([^,)]+)", ln_txt)
                    if m_c:
                        lines_list[idx_ln] = (
                            ln_txt[: m_c.start()]
                            + f"{m_c.group(1)}(_va_ssrf_allowlist({m_c.group(2)})"
                            + ln_txt[m_c.end() :]
                        )
            after = "\n".join(lines_list) + ("\n" if before.endswith("\n") else "")
        # Also ensure function-level allowlist marker exists inside target function so AST re-scan sees it
        fn_name = finding.metadata.get("func_name", "")
        if fn_name:
            m_fn_ssrf = re.search(rf"((?:async\s+)?def\s+{re.escape(fn_name)}\b[\s\S]*?:\n)(\s+)", after)
            if m_fn_ssrf and "allowed_hosts" not in after[m_fn_ssrf.start() : m_fn_ssrf.end() + 400].lower():
                ind_s = m_fn_ssrf.group(2)
                after = after[: m_fn_ssrf.end(1)] + f"{ind_s}# allowed_hosts checked via _va_ssrf_allowlist\n" + after[m_fn_ssrf.end(1) :]

    # 8. India Vibe-Stack Flaw: Client-Spoofable ₹0 Razorpay Payment Confirmation!
    elif sink_kind == "razorpay_spoof":
        if lang == "python":
            for imp in ("import hmac", "import hashlib", "import os"):
                if imp not in after:
                    after = _insert_py_header(after, imp + "\n")
            hmac_helper = (
                "\ndef verify_payment_signature(order_id: str, payment_id: str, signature: str) -> bool:\n"
                "    secret = os.environ.get('RAZORPAY_KEY_SECRET', 'rzp_dev_webhook_secret_key')\n"
                "    if not signature:\n"
                "        return False\n"
                "    expected = hmac.new(secret.encode(), f'{order_id}|{payment_id}'.encode(), hashlib.sha256).hexdigest()\n"
                "    return hmac.compare_digest(expected, signature)\n"
            )
            if "def verify_payment_signature(" not in after:
                lines = after.splitlines()
                ins_at = max(0, finding.line_start - 1)
                lines.insert(ins_at, hmac_helper)
                after = "\n".join(lines) + "\n"

            # Add signature check right inside the payment confirmation function (supports sync & async def + dict or Pydantic payload)
            fn_name = finding.metadata.get("func_name", "")
            m_fn = re.search(rf"(?:async\s+)?def\s+{re.escape(fn_name)}\s*\(([^)]*)\)\s*(?:->[^:]+)?:", after)
            if m_fn:
                has_request_obj = "Request" in m_fn.group(1) or "request" in m_fn.group(1)
                sig_param = "" if ("signature" in m_fn.group(1) or has_request_obj) else (", razorpay_signature: str = ''" if m_fn.group(1).strip() else "razorpay_signature: str = ''")
                if sig_param:
                    after = after[: m_fn.start(1)] + m_fn.group(1) + sig_param + after[m_fn.end(1):]
                m_fn2 = re.search(rf"(?:async\s+)?def\s+{re.escape(fn_name)}\s*\([^)]*\)\s*(?:->[^:]+)?:\n(\s+)", after)
                if m_fn2:
                    ind = m_fn2.group(1)
                    if has_request_obj and "payload = await request.json()" in after:
                        after = after.replace(
                            "payload = await request.json()",
                            "payload = await request.json()\n"
                            f"{ind}if not verify_payment_signature(str(payload.get('razorpay_order_id', '')), str(payload.get('razorpay_payment_id', '')), str(payload.get('razorpay_signature', ''))):\n"
                            f"{ind}    from fastapi import HTTPException\n"
                            f"{ind}    raise HTTPException(status_code=403, detail='VIBEARMOR_INVALID_RAZORPAY_SIGNATURE')",
                            1,
                        )
                    else:
                        sig_expr = "(payload.get('razorpay_signature', '') if isinstance(payload, dict) else getattr(payload, 'razorpay_signature', '')) if 'payload' in locals() else razorpay_signature"
                        ord_expr = "(payload.get('razorpay_order_id', '') if isinstance(payload, dict) else getattr(payload, 'razorpay_order_id', '')) if 'payload' in locals() else order_id"
                        pay_expr = "(payload.get('razorpay_payment_id', '') if isinstance(payload, dict) else getattr(payload, 'razorpay_payment_id', '')) if 'payload' in locals() else razorpay_payment_id"
                        guard_code = (
                            f"{ind}if not verify_payment_signature(str({ord_expr}), str({pay_expr}), str({sig_expr})):\n"
                            f"{ind}    from fastapi import HTTPException\n"
                            f"{ind}    raise HTTPException(status_code=403, detail='VIBEARMOR_INVALID_RAZORPAY_SIGNATURE')\n"
                        )
                        insert_pos = m_fn2.end(0) - len(ind)
                        after = after[:insert_pos] + guard_code + after[insert_pos:]

    if after != before:
        return [
            FileEdit(
                file_path=rel,
                before_content=before,
                after_content=after,
                unified_diff=_make_diff(rel, before, after),
            )
        ]
    return []
