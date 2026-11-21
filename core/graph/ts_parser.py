"""TypeScript / TSX / JavaScript AST parser powered by tree-sitter."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import tree_sitter
import tree_sitter_javascript
import tree_sitter_typescript

TS_LANG = tree_sitter.Language(tree_sitter_typescript.language_typescript())
TSX_LANG = tree_sitter.Language(tree_sitter_typescript.language_tsx())
JS_LANG = tree_sitter.Language(tree_sitter_javascript.language())


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


def _get_parser(file_path: str) -> tree_sitter.Parser:
    ext = Path(file_path).suffix.lower()
    if ext == ".tsx":
        return tree_sitter.Parser(TSX_LANG)
    if ext == ".ts":
        return tree_sitter.Parser(TS_LANG)
    if ext == ".jsx":
        return tree_sitter.Parser(TSX_LANG)
    return tree_sitter.Parser(JS_LANG)


def _walk(node: tree_sitter.Node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _node_text(source_bytes: bytes, node: tree_sitter.Node) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


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


def parse_ts_file(file_path: str, content: Optional[str] = None) -> TsFileAnalysis:
    source = content if content is not None else Path(file_path).read_text(encoding="utf-8", errors="replace")
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

    # Track tainted parameter / request identifiers inside file
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

        # 1. ES Imports & CommonJS require()
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

            # CommonJS require('pkg')
            m_req = re.match(r"^require\(\s*['\"]([^'\"]+)['\"]\s*\)$", call_txt.strip())
            if m_req:
                raw_pkg = m_req.group(1)
                if not raw_pkg.startswith("."):
                    pkg_root = "/".join(raw_pkg.split("/")[:2]) if raw_pkg.startswith("@") else raw_pkg.split("/")[0]
                    analysis.imports.add(pkg_root)

            # 2. Supabase .from('table').<op>() & .rpc('fn')
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

            # 3. Outbound fetch() / axios calls with inline API URLs or Authorization headers
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

            # 4. Dangerous JS/TS Sinks: eval, exec, SQL template interpolation
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
                # Ignore uppercase constants (hard-negative immunity!)
                non_const = [v for v in interp_vars if not v.isupper()]
                if non_const:
                    analysis.taint_sinks.append(
                        TsTaintSink("sql_injection", line_no, line_end, call_txt.strip()[:220], non_const)
                    )

        # 5. JSX dangerouslySetInnerHTML
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

        # 6. String literals with variable context for secret boundary detector
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

    # Deduplicate nested supabase matches by (table_or_rpc, operation, line)
    seen_sb = set()
    unique_sb = []
    for sb in analysis.supabase_calls:
        key = (sb.table_or_rpc, sb.operation, sb.line)
        if key not in seen_sb:
            seen_sb.add(key)
            unique_sb.append(sb)
    analysis.supabase_calls = unique_sb

    # Check Razorpay client-spoofable payment handler in TS/JS API routes
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
