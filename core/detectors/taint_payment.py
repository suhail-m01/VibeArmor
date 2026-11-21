"""Pillar 3: AST Taint Injection, Payment HMAC Spoofing, and Stateful Logic Detector."""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from core.graph.cross_layer_graph import WorkspaceContext
from core.models import Finding, Pillar, Severity

SINK_META: Dict[str, Tuple[str, str, Severity, str, str]] = {
    "sql_injection": (
        "VA-TNT-001",
        "CWE-089",
        Severity.CRITICAL,
        "SQL Injection via Tainted String Interpolation",
        "Attacker can inject `' OR '1'='1` or `UNION SELECT` to dump tables or bypass authentication.",
    ),
    "cmd_injection": (
        "VA-TNT-002",
        "CWE-078",
        Severity.CRITICAL,
        "OS Command Injection via Tainted Shell Execution",
        "Attacker can append `; curl ... | sh` to achieve arbitrary Remote Code Execution (RCE) on the server.",
    ),
    "code_eval": (
        "VA-TNT-003",
        "CWE-094",
        Severity.CRITICAL,
        "Arbitrary Code Execution via Dynamic eval/exec",
        "Untrusted input reaches Python/JS code interpreter, granting immediate Remote Code Execution.",
    ),
    "unsafe_deserialization": (
        "VA-TNT-004",
        "CWE-502",
        Severity.CRITICAL,
        "Unsafe Binary Deserialization (pickle/marshal)",
        "Crafted pickle payload executes arbitrary OS commands during deserialization.",
    ),
    "unsafe_yaml_load": (
        "VA-TNT-005",
        "CWE-502",
        Severity.HIGH,
        "Unsafe YAML Loader (yaml.load without SafeLoader)",
        "Attacker can instantiate arbitrary Python objects via `!!python/object/apply` tags.",
    ),
    "path_traversal": (
        "VA-TNT-006",
        "CWE-022",
        Severity.HIGH,
        "Path Traversal on Unsanitized File Path",
        "Attacker supplies `../../etc/passwd` or `.env.local` to read or overwrite sensitive server files.",
    ),
    "xss_ssti": (
        "VA-TNT-007",
        "CWE-079",
        Severity.HIGH,
        "Server-Side Template Injection / Reflected XSS",
        "Untrusted input rendered directly as a Jinja/HTML template allows script execution or SSTI RCE.",
    ),
    "xss_reflected": (
        "VA-TNT-007",
        "CWE-079",
        Severity.HIGH,
        "Unescaped HTML Response (Reflected XSS)",
        "User-controlled input interpolated into raw HTML allows session/token theft in victim browsers.",
    ),
    "xss_html": (
        "VA-TNT-007",
        "CWE-079",
        Severity.HIGH,
        "Unsanitized dangerouslySetInnerHTML Sink",
        "Rendering raw HTML without DOMPurify allows stored/reflected Cross-Site Scripting.",
    ),
    "ssrf": (
        "VA-TNT-008",
        "CWE-918",
        Severity.HIGH,
        "Server-Side Request Forgery (SSRF) on User URL",
        "Attacker can force server to fetch cloud metadata (`169.254.169.254`) or internal microservices.",
    ),
    "razorpay_spoof": (
        "VA-PAY-001",
        "CWE-345",
        Severity.CRITICAL,
        "Client-Spoofable ₹0 Razorpay Payment Confirmation",
        "Order marked 'paid' without constant-time HMAC-SHA256 verification of `order_id|payment_id`.",
    ),
    "weak_crypto": (
        "VA-CRY-001",
        "CWE-327",
        Severity.MEDIUM,
        "Broken / Weak Cryptographic Primitive (MD5/SHA1/DES)",
        "Fast collision-prone or deprecated cipher exposes password hashes or encrypted payloads.",
    ),
    "xxe_xml": (
        "VA-XML-001",
        "CWE-611",
        Severity.HIGH,
        "XML External Entity (XXE) Unsafe Parser",
        "Standard XML parser allows external entity expansion to read local server files.",
    ),
    "jwt_unverified": (
        "VA-AUTH-007",
        "CWE-347",
        Severity.CRITICAL,
        "JWT Decoded with Signature Verification Disabled",
        "Attackers can forge arbitrary admin user claims and bypass authentication completely.",
    ),
    "open_redirect": (
        "VA-WEB-001",
        "CWE-601",
        Severity.MEDIUM,
        "Unvalidated Open Redirect on User Parameter",
        "Attackers craft phishing links on your domain that redirect victims to credential-harvesting sites.",
    ),
}


def detect_taint_and_payments(ctx: WorkspaceContext) -> List[Finding]:
    findings: List[Finding] = []
    idx = 1

    # 1. Python AST Taint, Payment & Reflection Findings
    for rel, py_f in ctx.py_files.items():
        src = ctx.file_contents.get(rel, "")
        for tf in py_f.taint_findings:
            if tf.dynamic_reflection:
                findings.append(
                    Finding(
                        id=f"VA-TNT-ABSTAIN-{idx:03d}",
                        pillar=Pillar.TAINT_PAYMENT,
                        rule_id="VA-TNT-099",
                        cwe="CWE-470",
                        severity=Severity.HIGH,
                        title=f"Dynamic Runtime Reflection Dispatch in '{tf.func_name}()'",
                        description=(
                            f"Function '{tf.func_name}' uses `getattr()` with user-controlled input ({', '.join(tf.tainted_vars)}). "
                            "Target method set is unknown statically without an explicit allowlist contract."
                        ),
                        blast_radius="Attacker could invoke unintended internal methods (`__dict__`, admin handlers) at runtime.",
                        file_path=rel,
                        line_start=tf.line_start,
                        line_end=tf.line_end,
                        snippet=tf.snippet,
                        requires_policy_spec=True,
                        abstention_reason="NEEDS_ALLOWLIST_SPEC: Dynamic `getattr` reflection hides target call graph from static AST verification; auto-rewriting risks breaking legitimate plugin/command dispatch.",
                        metadata={"func_name": tf.func_name, "sink_kind": tf.sink_kind},
                    )
                )
                idx += 1
                continue

            rule_id, cwe, sev, title, blast = SINK_META.get(
                tf.sink_kind,
                ("VA-TNT-010", tf.cwe, Severity.HIGH, f"Unsafe Sink ({tf.sink_kind})", "Potential injection flaw."),
            )
            findings.append(
                Finding(
                    id=f"VA-TNT-{idx:03d}",
                    pillar=Pillar.TAINT_PAYMENT,
                    rule_id=rule_id,
                    cwe=cwe,
                    severity=sev,
                    title=title,
                    description=(
                        f"In '{tf.func_name}()' ({rel}:{tf.line_start}), untrusted input ({', '.join(tf.tainted_vars)}) "
                        f"flows directly into sink `{tf.sink_kind}`."
                    ),
                    blast_radius=blast,
                    file_path=rel,
                    line_start=tf.line_start,
                    line_end=tf.line_end,
                    snippet=tf.snippet,
                    metadata={
                        "sink_kind": tf.sink_kind,
                        "func_name": tf.func_name,
                        "tainted_vars": tf.tainted_vars,
                        "lang": "python",
                    },
                )
            )
            idx += 1

        # Detect Stateful Business-Logic Race / Coupon Replay / Negative Quantity Abstention Boundary
        if re.search(r"#\s*STATEFUL_LOGIC_FLOW|coupon_code.*used_count|wallet_balance\s*-=", src, re.IGNORECASE):
            if "SELECT ... FOR UPDATE" not in src and "with_for_update" not in src and "atomic" not in src.lower():
                m_ln = re.search(r"(coupon_code|wallet_balance)", src, re.IGNORECASE)
                ln = src[: m_ln.start()].count("\n") + 1 if m_ln else 1
                findings.append(
                    Finding(
                        id=f"VA-LOGIC-ABSTAIN-{idx:03d}",
                        pillar=Pillar.TAINT_PAYMENT,
                        rule_id="VA-LOG-099",
                        cwe="CWE-841",
                        severity=Severity.HIGH,
                        title="Stateful Business-Logic / Race Invariant Ambiguity",
                        description=(
                            f"'{rel}' performs non-atomic read-modify-write state transitions on financial/coupon state "
                            "without formal idempotency or domain invariant annotations."
                        ),
                        blast_radius="Concurrent requests or negative quantities may replay single-use coupons or overdraw balances.",
                        file_path=rel,
                        line_start=ln,
                        line_end=ln + 5,
                        snippet="\n".join(src.splitlines()[max(0, ln - 1): min(len(src.splitlines()), ln + 5)]),
                        requires_policy_spec=True,
                        abstention_reason="NEEDS_BUSINESS_INVARIANT: Multi-request TOCTOU coupon/wallet semantics depend on application business rules (per-user vs global cap, retry idempotency) uninferable from syntax alone.",
                        metadata={"sink_kind": "stateful_race"},
                    )
                )
                idx += 1

    # 2. TypeScript / JavaScript AST Taint & Payment Findings
    for rel, ts_f in ctx.ts_files.items():
        for sk in ts_f.taint_sinks:
            rule_id, cwe, sev, title, blast = SINK_META.get(
                sk.sink_kind,
                ("VA-TNT-010", "CWE-020", Severity.HIGH, f"Unsafe JS/TS Sink ({sk.sink_kind})", "Potential injection flaw."),
            )
            findings.append(
                Finding(
                    id=f"VA-TNT-{idx:03d}",
                    pillar=Pillar.TAINT_PAYMENT,
                    rule_id=rule_id,
                    cwe=cwe,
                    severity=sev,
                    title=title,
                    description=f"In '{rel}' (line {sk.line_start}), untrusted data reaches `{sk.sink_kind}`.",
                    blast_radius=blast,
                    file_path=rel,
                    line_start=sk.line_start,
                    line_end=sk.line_end,
                    snippet=sk.snippet,
                    metadata={
                        "sink_kind": sk.sink_kind,
                        "tainted_vars": sk.tainted_vars,
                        "lang": "typescript",
                    },
                )
            )
            idx += 1

    # Mark vulnerable API route nodes in graph
    vuln_files = {f.file_path for f in findings}
    for node in ctx.nodes:
        if node.file_path in vuln_files and node.kind.value in ("api_route", "frontend_component"):
            if node.status == "safe":
                node.status = "vulnerable"

    return findings
