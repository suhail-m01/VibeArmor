"""TypeScript / TSX / JavaScript AST parser with tree-sitter & pure-Python fallback."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import tree_sitter
    import tree_sitter_javascript
    import tree_sitter_typescript

    TS_LANG = tree_sitter.Language(tree_sitter_typescript.language_typescript())
    TSX_LANG = tree_sitter.Language(tree_sitter_typescript.language_tsx())
    JS_LANG = tree_sitter.Language(tree_sitter_javascript.language())
    _TREE_SITTER_AVAILABLE = True
except (ImportError, Exception):
    _TREE_SITTER_AVAILABLE = False


@dataclass
class SupabaseCall:
    table_or_rpc: str
    call_type: str  # "table" | "rpc"
    operation: str  # "select" | "insert" | "update" | "delete" | "upsert" | "rpc"
    line: int
    snippet: str


@dataclass
class OutboundCall:
    provider: str  # "openai" | "razorpay" | "stripe" | "msg91" | "generic"
    url_expr: str
    line_start: int
    line_end: int
    start_byte: int
    end_byte: int
    snippet: str
    has_inline_secret_header: bool = False


@dataclass
class TsTaintSink:
    sink_kind: str  # "sql_injection" | "cmd_injection" | "code_eval" | "xss_html" | "razorpay_spoof"
    line_start: int
    line_end: int
    snippet: str
    tainted_vars: List[str] = field(default_factory=list)


@dataclass
class TsFileAnalysis:
    file_path: str
    is_client_bundle: bool
    has_syntax_error: bool
    imports: Set[str] = field(default_factory=set)
    imported_symbols: Dict[str, Set[str]] = field(default_factory=dict)
    supabase_calls: List[SupabaseCall] = field(default_factory=list)
    outbound_calls: List[OutboundCall] = field(default_factory=list)
    string_literals: List[Tuple[str, str, int]] = field(default_factory=list)  # (var_context, value, line)
    taint_sinks: List[TsTaintSink] = field(default_factory=list)
    has_auth_guard: bool = False


def _detect_client_bundle(file_path: str, source: str) -> bool:
    norm = file_path.replace("\\", "/").lower()
    if "'use client'" in source or '"use client"' in source:
        return True
    if "/api/" in norm or norm.endswith("route.ts") or norm.endswith("route.js") or "/server/" in norm:
        return False
    if any(seg in norm for seg in ("/components/", "/pages/", "/views/", "/hooks/", "/client/")):
        return True
    if norm.endswith((".tsx", ".jsx")):
        return True
    return False


def _parse_ts_fallback(file_path: str, source: str) -> TsFileAnalysis:
    is_client = _detect_client_bundle(file_path, source)
    has_auth = bool(
        re.search(r"(getUser|getSession|verifyJwt|requireAuth|auth\.uid|x-vibearmor-session|createServerClient)", source)
    )

    # Balanced bracket syntax verification
    stack = []
    pairs = {')': '(', '}': '{', ']': '['}
    has_syntax_error = False
    in_s_quote = False
    in_d_quote = False
    in_bt_quote = False
    escape = False
    in_line_comment = False
    in_block_comment = False

    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        nxt = source[i+1] if i + 1 < n else ''

        if in_line_comment:
            if ch == '\n':
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == '*' and nxt == '/':
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue

        if escape:
            escape = False
            i += 1
            continue

        if ch == '\\':
            escape = True
            i += 1
            continue

        if in_s_quote:
            if ch == "'":
                in_s_quote = False
            i += 1
            continue
        if in_d_quote:
            if ch == '"':
                in_d_quote = False
            i += 1
            continue
        if in_bt_quote:
            if ch == '`':
                in_bt_quote = False
            i += 1
            continue

        if ch == '/' and nxt == '/':
            in_line_comment = True
            i += 2
            continue
        if ch == '/' and nxt == '*':
            in_block_comment = True
            i += 2
            continue

        if ch == "'":
            in_s_quote = True
            i += 1
            continue
        if ch == '"':
            in_d_quote = True
            i += 1
            continue
        if ch == '`':
            in_bt_quote = True
            i += 1
            continue

        if ch in '({[':
            stack.append(ch)
        elif ch in ')}]':
            if not stack or stack[-1] != pairs[ch]:
                has_syntax_error = True
                break
            stack.pop()
        i += 1

    if stack or in_s_quote or in_d_quote or in_bt_quote:
        has_syntax_error = True

    analysis = TsFileAnalysis(
        file_path=file_path,
        is_client_bundle=is_client,
        has_syntax_error=has_syntax_error,
        has_auth_guard=has_auth,
    )

    # Track tainted names
    tainted_names: Set[str] = set()
    for m in re.finditer(r"(?:searchParams\.get|req\.query\.|req\.body\.|params\.)([A-Za-z_][A-Za-z0-9_]*)", source):
        tainted_names.add(m.group(1))
    for m in re.finditer(r"const\s*\{([^}]+)\}\s*=\s*(?:await\s+req\.json\(\)|req\.body|req\.query)", source):
        for part in m.group(1).split(","):
            clean = part.split(":")[0].strip()
            if clean:
                tainted_names.add(clean)

    # 1. ES Imports & CommonJS require
    for m in re.finditer(r"(?:import\s+(?:(?P<symbols>[\w\s{},*]+)\s+from\s+)?|require\(\s*)['\"](?P<pkg>[^'\"]+)['\"]\s*\)?", source):
        raw_pkg = m.group("pkg")
        if not raw_pkg.startswith(".") and not raw_pkg.startswith("@/"):
            pkg_root = "/".join(raw_pkg.split("/")[:2]) if raw_pkg.startswith("@") else raw_pkg.split("/")[0]
            analysis.imports.add(pkg_root)
            syms_str = m.group("symbols") or ""
            syms = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", syms_str))
            syms.discard("import")
            syms.discard("type")
            analysis.imported_symbols.setdefault(pkg_root, set()).update(syms)

    # 2. Supabase calls
    for m in re.finditer(r"\.from\(\s*['\"]([A-Za-z0-9_]+)['\"]\s*\)\s*\.\s*(select|insert|update|delete|upsert)\b", source):
        line_no = source[:m.start()].count("\n") + 1
        snip = source[max(0, m.start() - 20): min(len(source), m.end() + 80)].strip()
        analysis.supabase_calls.append(
            SupabaseCall(
                table_or_rpc=m.group(1),
                call_type="table",
                operation=m.group(2),
                line=line_no,
                snippet=snip[:220],
            )
        )

    for m in re.finditer(r"\.rpc\(\s*['\"]([A-Za-z0-9_]+)['\"]", source):
        line_no = source[:m.start()].count("\n") + 1
        snip = source[max(0, m.start() - 20): min(len(source), m.end() + 80)].strip()
        analysis.supabase_calls.append(
            SupabaseCall(
                table_or_rpc=m.group(1),
                call_type="rpc",
                operation="rpc",
                line=line_no,
                snippet=snip[:220],
            )
        )

    # 3. Outbound calls
    for m in re.finditer(r"\b(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?)\s*\(\s*([^,\n)]+)", source):
        line_start = source[:m.start()].count("\n") + 1
        end_idx = min(len(source), m.end() + 300)
        call_txt = source[m.start():end_idx]
        line_end = source[:end_idx].count("\n") + 1
        low = call_txt.lower()
        provider = "generic"
        if "api.openai.com" in low:
            provider = "openai"
        elif "api.razorpay.com" in low:
            provider = "razorpay"
        elif "api.stripe.com" in low:
            provider = "stripe"
        elif "msg91.com" in low:
            provider = "msg91"
        has_sec = bool(re.search(r"(authorization|x-api-key|authkey|basic\s+|bearer\s+)", low))
        url_expr = m.group(1).strip()
        analysis.outbound_calls.append(
            OutboundCall(
                provider=provider,
                url_expr=url_expr,
                line_start=line_start,
                line_end=line_end,
                start_byte=m.start(),
                end_byte=end_idx,
                snippet=call_txt[:300],
                has_inline_secret_header=has_sec,
            )
        )

    # 4. Dangerous JS/TS Sinks
    for m in re.finditer(r"\b(?:eval|Function)\s*\(", source):
        line_no = source[:m.start()].count("\n") + 1
        analysis.taint_sinks.append(
            TsTaintSink("code_eval", line_no, line_no, source[m.start():m.start()+100].strip(), list(tainted_names))
        )
    for m in re.finditer(r"\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{", source):
        line_no = source[:m.start()].count("\n") + 1
        analysis.taint_sinks.append(
            TsTaintSink("cmd_injection", line_no, line_no, source[m.start():m.start()+100].strip(), list(tainted_names))
        )
    for m in re.finditer(r"\.(?:query|execute|unsafe|raw)\s*\(\s*`([^`]*SELECT[^`]*)`", source, re.IGNORECASE):
        q_content = m.group(1)
        interp_vars = re.findall(r"\$\{\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\}", q_content)
        non_const = [v for v in interp_vars if not v.isupper()]
        if non_const:
            line_no = source[:m.start()].count("\n") + 1
            analysis.taint_sinks.append(
                TsTaintSink("sql_injection", line_no, line_no, m.group(0)[:220].strip(), non_const)
            )

    # 5. JSX dangerouslySetInnerHTML
    for m in re.finditer(r"dangerouslySetInnerHTML\s*=\s*\{([^}]+)\}", source):
        attr_txt = m.group(0)
        if "DOMPurify" not in attr_txt:
            line_no = source[:m.start()].count("\n") + 1
            analysis.taint_sinks.append(
                TsTaintSink("xss_html", line_no, line_no, attr_txt[:200].strip())
            )

    # 6. String literals >= 12
    for m in re.finditer(r"""(?:(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*|([A-Za-z0-9_$]+)\s*:\s*|([A-Za-z0-9_$]+)\s*=\s*)?(['"`])([^\n\r'"`]{12,})\4""", source):
        ctx_name = m.group(1) or m.group(2) or m.group(3) or ""
        val = m.group(5)
        line_no = source[:m.start()].count("\n") + 1
        analysis.string_literals.append((ctx_name, val, line_no))

    # Deduplicate supabase calls
    seen_sb = set()
    unique_sb = []
    for sb in analysis.supabase_calls:
        key = (sb.table_or_rpc, sb.operation, sb.line)
        if key not in seen_sb:
            seen_sb.add(key)
            unique_sb.append(sb)
    analysis.supabase_calls = unique_sb

    # Razorpay client spoof check
    if not is_client and ("razorpay_payment_id" in source or "payment.captured" in source):
        has_hmac = bool(re.search(r"(createHmac|timingSafeEqual|x-razorpay-signature)", source))
        if not has_hmac and re.search(r"status\s*[:=]\s*['\"]paid['\"]", source, re.IGNORECASE):
            m_line = re.search(r"status\s*[:=]\s*['\"]paid['\"]", source, re.IGNORECASE)
            ln = source[:m_line.start()].count("\n") + 1 if m_line else 1
            analysis.taint_sinks.append(
                TsTaintSink(
                    "razorpay_spoof",
                    ln,
                    ln + 2,
                    "Order marked 'paid' from client payload without HMAC-SHA256 signature verification",
                    ["razorpay_payment_id"],
                )
            )

    return analysis


def _get_parser(file_path: str):
    ext = Path(file_path).suffix.lower()
    if ext == ".tsx":
        return tree_sitter.Parser(TSX_LANG)
    if ext == ".ts":
        return tree_sitter.Parser(TS_LANG)
    if ext == ".jsx":
        return tree_sitter.Parser(TSX_LANG)
    return tree_sitter.Parser(JS_LANG)


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _node_text(source_bytes: bytes, node) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def parse_ts_file(file_path: str, content: Optional[str] = None) -> TsFileAnalysis:
    source = content if content is not None else Path(file_path).read_text(encoding="utf-8", errors="replace")

    if not _TREE_SITTER_AVAILABLE:
        return _parse_ts_fallback(file_path, source)

    source_bytes = source.encode("utf-8")
    parser = _get_parser(file_path)
    tree = parser.parse(source_bytes)

    is_client = _detect_client_bundle(file_path, source)
    has_auth = bool(
        re.search(r"(getUser|getSession|verifyJwt|requireAuth|auth\.uid|x-vibearmor-session|createServerClient)", source)
    )

    analysis = TsFileAnalysis(
        file_path=file_path,
        is_client_bundle=is_client,
        has_syntax_error=tree.root_node.has_error,
        has_auth_guard=has_auth,
    )

    tainted_names: Set[str] = set()
    for m in re.finditer(r"(?:searchParams\.get|req\.query\.|req\.body\.|params\.)([A-Za-z_][A-Za-z0-9_]*)", source):
        tainted_names.add(m.group(1))
    for m in re.finditer(r"const\s*\{([^}]+)\}\s*=\s*(?:await\s+req\.json\(\)|req\.body|req\.query)", source):
        for part in m.group(1).split(","):
            clean = part.split(":")[0].strip()
            if clean:
                tainted_names.add(clean)

    for node in _walk(tree.root_node):
        ntype = node.type

        if ntype == "import_statement":
            stmt_txt = _node_text(source_bytes, node)
            m_pkg = re.search(r"from\s+['\"]([^'\"]+)['\"]", stmt_txt)
            if m_pkg:
                raw_pkg = m_pkg.group(1)
                if not raw_pkg.startswith(".") and not raw_pkg.startswith("@/"):
                    pkg_root = "/".join(raw_pkg.split("/")[:2]) if raw_pkg.startswith("@") else raw_pkg.split("/")[0]
                    analysis.imports.add(pkg_root)
                    syms = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", stmt_txt.split("from")[0]))
                    syms.discard("import")
                    syms.discard("type")
                    analysis.imported_symbols.setdefault(pkg_root, set()).update(syms)

        elif ntype == "call_expression":
            call_txt = _node_text(source_bytes, node)
            line_no = node.start_point[0] + 1
            line_end = node.end_point[0] + 1

            m_req = re.match(r"^require\(\s*['\"]([^'\"]+)['\"]\s*\)$", call_txt.strip())
            if m_req:
                raw_pkg = m_req.group(1)
                if not raw_pkg.startswith("."):
                    pkg_root = "/".join(raw_pkg.split("/")[:2]) if raw_pkg.startswith("@") else raw_pkg.split("/")[0]
                    analysis.imports.add(pkg_root)

            m_sb = re.search(
                r"\.from\(\s*['\"]([A-Za-z0-9_]+)['\"]\s*\)\s*\.\s*(select|insert|update|delete|upsert)\b",
                call_txt,
                re.DOTALL,
            )
            if m_sb and node.parent and ".from(" not in _node_text(source_bytes, node.parent if node.parent.type == "call_expression" else node)[:15]:
                analysis.supabase_calls.append(
                    SupabaseCall(
                        table_or_rpc=m_sb.group(1),
                        call_type="table",
                        operation=m_sb.group(2),
                        line=line_no,
                        snippet=call_txt.strip()[:220],
                    )
                )

            m_rpc = re.search(r"\.rpc\(\s*['\"]([A-Za-z0-9_]+)['\"]", call_txt)
            if m_rpc and (not node.parent or node.parent.type != "member_expression"):
                analysis.supabase_calls.append(
                    SupabaseCall(
                        table_or_rpc=m_rpc.group(1),
                        call_type="rpc",
                        operation="rpc",
                        line=line_no,
                        snippet=call_txt.strip()[:220],
                    )
                )

            if call_txt.lstrip().startswith(("fetch(", "axios.post(", "axios.get(")):
                provider = "generic"
                low = call_txt.lower()
                if "api.openai.com" in low:
                    provider = "openai"
                elif "api.razorpay.com" in low:
                    provider = "razorpay"
                elif "api.stripe.com" in low:
                    provider = "stripe"
                elif "msg91.com" in low:
                    provider = "msg91"
                has_sec = bool(re.search(r"(authorization|x-api-key|authkey|basic\s+|bearer\s+)", low))
                m_url = re.search(r"(?:fetch|axios\.\w+)\(\s*([^,\n)]+)", call_txt)
                analysis.outbound_calls.append(
                    OutboundCall(
                        provider=provider,
                        url_expr=m_url.group(1).strip() if m_url else "",
                        line_start=line_no,
                        line_end=line_end,
                        start_byte=node.start_byte,
                        end_byte=node.end_byte,
                        snippet=call_txt.strip()[:300],
                        has_inline_secret_header=has_sec,
                    )
                )

            if re.match(r"^(?:eval|Function)\s*\(", call_txt.strip()):
                analysis.taint_sinks.append(
                    TsTaintSink("code_eval", line_no, line_end, call_txt.strip()[:200], list(tainted_names))
                )
            elif re.search(r"\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{", call_txt):
                analysis.taint_sinks.append(
                    TsTaintSink("cmd_injection", line_no, line_end, call_txt.strip()[:200], list(tainted_names))
                )
            elif re.search(r"\.(?:query|execute|unsafe|raw)\s*\(\s*`[^`]*SELECT[^`]*\$\{", call_txt, re.IGNORECASE | re.DOTALL):
                interp_vars = re.findall(r"\$\{\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\}", call_txt)
                non_const = [v for v in interp_vars if not v.isupper()]
                if non_const:
                    analysis.taint_sinks.append(
                        TsTaintSink("sql_injection", line_no, line_end, call_txt.strip()[:220], non_const)
                    )

        elif ntype == "jsx_attribute":
            attr_txt = _node_text(source_bytes, node)
            if "dangerouslySetInnerHTML" in attr_txt and "DOMPurify" not in attr_txt:
                analysis.taint_sinks.append(
                    TsTaintSink(
                        "xss_html",
                        node.start_point[0] + 1,
                        node.end_point[0] + 1,
                        attr_txt.strip()[:200],
                    )
                )

        elif ntype in ("string", "template_string"):
            raw_val = _node_text(source_bytes, node).strip("'\"`")
            if len(raw_val) >= 12:
                ctx_name = ""
                cur = node.parent
                steps_up = 0
                while cur is not None and steps_up < 4:
                    if cur.type in ("variable_declarator", "pair", "assignment_expression"):
                        left_node = cur.children[0] if cur.children else None
                        if left_node is not None:
                            ctx_name = _node_text(source_bytes, left_node).strip()
                        break
                    cur = cur.parent
                    steps_up += 1
                analysis.string_literals.append((ctx_name, raw_val, node.start_point[0] + 1))

    seen_sb = set()
    unique_sb = []
    for sb in analysis.supabase_calls:
        key = (sb.table_or_rpc, sb.operation, sb.line)
        if key not in seen_sb:
            seen_sb.add(key)
            unique_sb.append(sb)
    analysis.supabase_calls = unique_sb

    if not is_client and ("razorpay_payment_id" in source or "payment.captured" in source):
        has_hmac = bool(re.search(r"(createHmac|timingSafeEqual|x-razorpay-signature)", source))
        if not has_hmac and re.search(r"status\s*[:=]\s*['\"]paid['\"]", source, re.IGNORECASE):
            m_line = re.search(r"status\s*[:=]\s*['\"]paid['\"]", source, re.IGNORECASE)
            ln = source[: m_line.start()].count("\n") + 1 if m_line else 1
            analysis.taint_sinks.append(
                TsTaintSink(
                    "razorpay_spoof",
                    ln,
                    ln + 2,
                    "Order marked 'paid' from client payload without HMAC-SHA256 signature verification",
                    ["razorpay_payment_id"],
                )
            )

    return analysis
