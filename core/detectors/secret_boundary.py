"""Pillar 2: Context-Aware Secret Scanner & Bundle-Boundary Detector (Zero-Trust Auto-BFF Ready)."""

from __future__ import annotations

import base64
import json
import math
import re
from typing import Dict, List, Optional, Tuple

from core.graph.cross_layer_graph import WorkspaceContext
from core.models import Finding, NodeKind, Pillar, SecurityEdge, SecurityNode, Severity

PLACEHOLDER_SUBSTRINGS = (
    "your_key_here",
    "your-api-key",
    "changeme",
    "placeholder",
    "example",
    "xxxx",
    "<insert",
    "dummy_safe",
    "test_public_anon_safe",
)

SECRET_PATTERNS: List[Tuple[str, str, re.Pattern[str]]] = [
    ("openai", "OpenAI Private API Key", re.compile(r"^sk-(?:proj-|live-)?[A-Za-z0-9_\-]{18,}$")),
    ("razorpay", "Razorpay Live/Secret Key", re.compile(r"^(?:rzp_live_[A-Za-z0-9]{10,}|rzp_secret_[A-Za-z0-9_\-]{12,})$")),
    ("stripe", "Stripe Secret Key", re.compile(r"^(?:sk_live_|rk_live_)[A-Za-z0-9]{16,}$")),
    ("aws", "AWS Access Key ID", re.compile(r"^AKIA[0-9A-Z]{16}$")),
    ("msg91", "MSG91 / Gupshup OTP Auth Key", re.compile(r"^(?:msg91_live_|gup_live_)[A-Za-z0-9_\-]{14,}$")),
    ("db_uri", "Database Connection URI with Credentials", re.compile(r"^postgres(?:ql)?://[^:\s]+:[^@\s]+@[^\s]+$")),
]

SENSITIVE_VAR_NAMES = re.compile(
    r"(secret(?!ar(?:y|ies|ial))|private_key|api_key|service_role|razorpay_key_secret|openai_key|msg91|db_password|jwt_secret|password|passwd|auth_token)",
    re.IGNORECASE,
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _decode_jwt_role(token: str) -> Optional[str]:
    parts = token.split(".")
    if len(parts) != 3 or not token.startswith("eyJ"):
        return None
    try:
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("ascii")).decode("utf-8", errors="ignore"))
        return str(payload.get("role", "")).lower() or "jwt_generic"
    except Exception:
        return None


def _classify_literal(var_ctx: str, val: str) -> Optional[Tuple[str, str]]:
    low_val = val.lower().strip()
    if any(p in low_val for p in PLACEHOLDER_SUBSTRINGS):
        return None
    if low_val.startswith(("http://", "https://", "/api/", "./", "../")) and "@" not in low_val:
        return None
    if " " in val.strip() and not val.strip().lower().startswith("bearer "):
        return None

    clean_token = val.strip()
    if clean_token.lower().startswith("bearer "):
        clean_token = clean_token[7:].strip()

    for provider, label, pat in SECRET_PATTERNS:
        if pat.match(clean_token):
            return (provider, label)

    jwt_role = _decode_jwt_role(clean_token)
    if jwt_role == "service_role":
        return ("supabase_admin", "Supabase service_role Secret JWT (Bypasses All RLS)")
    if jwt_role == "anon":
        return ("supabase_anon", "Supabase Public anon_key")

    # Variable-context + entropy / credential check (covers SecurityEval CWE-798 hardcoded passwords & keys!)
    if SENSITIVE_VAR_NAMES.search(var_ctx):
        # Ignore env lookups where var_ctx matched but value is merely an env key name like "OPENAI_API_KEY"
        if re.match(r"^[A-Z0-9_]+$", clean_token):
            return None
        if len(clean_token) >= 8 and (_shannon_entropy(clean_token) >= 2.8 or "password" in var_ctx.lower() or "secret" in var_ctx.lower()):
            prov = "razorpay" if "razorpay" in var_ctx.lower() else ("openai" if "openai" in var_ctx.lower() else "generic")
            return (prov, f"Hard-Coded Secret / Credential in '{var_ctx}'")

    return None


def detect_secrets_and_boundaries(ctx: WorkspaceContext, rls_findings: List[Finding]) -> List[Finding]:
    findings: List[Finding] = []
    has_broken_rls = any(f.rule_id in ("VA-RLS-001", "VA-RLS-002", "VA-RLS-003") for f in rls_findings)
    idx = 1
    seen = set()

    # 1. Scan TypeScript / JSX files (Client Bundles & Server Routes)
    for rel, ts_f in ctx.ts_files.items():
        src_lines = ctx.file_contents.get(rel, "").splitlines()
        for var_ctx, val, line_no in ts_f.string_literals:
            classified = _classify_literal(var_ctx, val)
            if not classified:
                continue
            provider, label = classified

            # Smart CVE-2025-48757 Rule: Public anon_key is SAFE if RLS is properly enabled on all tables!
            if provider == "supabase_anon":
                if not has_broken_rls:
                    continue
                # Even when RLS is broken, the fix is enabling RLS (Pillar 1), not hiding anon_key. Skip duplicate noise!
                continue

            dedup_key = (rel, line_no, val[:16])
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            needs_bff = ts_f.is_client_bundle
            snip = src_lines[line_no - 1].strip() if 1 <= line_no <= len(src_lines) else val[:40]
            fid = f"VA-SEC-{idx:03d}"
            idx += 1

            findings.append(
                Finding(
                    id=fid,
                    pillar=Pillar.SECRET_BOUNDARY,
                    rule_id="VA-SEC-001" if needs_bff else "VA-SEC-002",
                    cwe="CWE-798",
                    severity=Severity.CRITICAL if needs_bff else Severity.HIGH,
                    title=f"{label} Exposed in {'Client Browser Bundle' if needs_bff else 'Server Source'}",
                    description=(
                        f"{label} is hardcoded in '{rel}' (line {line_no}). "
                        + (
                            "Because this file compiles into the client JavaScript bundle, any visitor can extract the key in DevTools."
                            if needs_bff
                            else "Hardcoded credentials in server code leak into Git history and commits."
                        )
                    ),
                    blast_radius=(
                        "Attackers can scrape the key from browser JS to drain API credits, impersonate admin service_role, or forge webhooks."
                        if needs_bff
                        else "Anyone with repository read access obtains live production credentials."
                    ),
                    file_path=rel,
                    line_start=line_no,
                    line_end=line_no,
                    snippet=snip[:200],
                    metadata={
                        "provider": provider,
                        "secret_value": val,
                        "var_context": var_ctx,
                        "is_client_bundle": needs_bff,
                        "needs_auto_bff": needs_bff,
                    },
                )
            )

            sec_nid = f"sec:{fid}"
            ctx.nodes.append(
                SecurityNode(
                    id=sec_nid,
                    kind=NodeKind.SECRET_TOKEN,
                    label=f"Secret: {provider.upper()}",
                    file_path=rel,
                    line=line_no,
                    status="vulnerable",
                )
            )
            ctx.edges.append(
                SecurityEdge(
                    source=f"ts:{rel}",
                    target=sec_nid,
                    relation="exposes_in_bundle" if needs_bff else "hardcodes_secret",
                    risk="critical",
                )
            )

    # 2. Scan Python backend files
    for rel, py_f in ctx.py_files.items():
        src_lines = ctx.file_contents.get(rel, "").splitlines()
        for var_ctx, val, line_no in py_f.string_assignments:
            classified = _classify_literal(var_ctx, val)
            if not classified:
                continue
            provider, label = classified
            if provider == "supabase_anon":
                continue

            dedup_key = (rel, line_no, val[:16])
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            snip = src_lines[line_no - 1].strip() if 1 <= line_no <= len(src_lines) else f"{var_ctx} = '***'"
            findings.append(
                Finding(
                    id=f"VA-SEC-{idx:03d}",
                    pillar=Pillar.SECRET_BOUNDARY,
                    rule_id="VA-SEC-002",
                    cwe="CWE-798",
                    severity=Severity.HIGH,
                    title=f"{label} Hard-Coded in Python Module",
                    description=f"{label} is hardcoded in '{rel}' at line {line_no} instead of reading from environment secrets.",
                    blast_radius="Credential leaks permanently into Git commit history and container layers.",
                    file_path=rel,
                    line_start=line_no,
                    line_end=line_no,
                    snippet=snip[:200],
                    metadata={
                        "provider": provider,
                        "secret_value": val,
                        "var_context": var_ctx,
                        "is_client_bundle": False,
                        "needs_auto_bff": False,
                    },
                )
            )
            idx += 1

    # 3. Scan .env* files for Pre-Push Git Leak Risks & Public Client Prefix Misuse (VA-ENV-001 / VA-ENV-002)
    gitignore_txt = ctx.file_contents.get(".gitignore", "")
    ignores_dotenv = bool(
        re.search(r"(?:^|\n)\s*(?:\.env\*?|\.env\.local|\*\.env)\s*(?:\n|$|#)", gitignore_txt)
    )

    for env_rel, env_txt in ctx.env_files.items():
        if env_rel.endswith((".example", ".sample", ".template")):
            continue
        env_secrets_found: List[Tuple[str, int, str]] = []
        for ln_no, raw_ln in enumerate(env_txt.splitlines(), start=1):
            stripped = raw_ln.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            k, v = stripped.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            classified = _classify_literal(k, v)
            if not classified:
                continue
            prov, lbl = classified
            if prov == "supabase_anon":
                continue
            env_secrets_found.append((k, ln_no, lbl))

            # VA-ENV-002: Private key assigned to NEXT_PUBLIC_ / VITE_ / REACT_APP_ inside .env!
            if k.startswith(("NEXT_PUBLIC_", "VITE_", "REACT_APP_")):
                findings.append(
                    Finding(
                        id=f"VA-SEC-{idx:03d}",
                        pillar=Pillar.SECRET_BOUNDARY,
                        rule_id="VA-ENV-002",
                        cwe="CWE-200",
                        severity=Severity.CRITICAL,
                        title=f"Private {lbl} Exposed via Public '{k}' Prefix in {env_rel}",
                        description=(
                            f"'{k}' in '{env_rel}' (line {ln_no}) uses a browser-exposed prefix (NEXT_PUBLIC_/VITE_/REACT_APP_), "
                            "which bundlers inline directly into public client JavaScript during deployment."
                        ),
                        blast_radius="Live private key is shipped to every browser visitor on Vercel/Netlify deployment.",
                        file_path=env_rel,
                        line_start=ln_no,
                        line_end=ln_no,
                        snippet=f"{k}=<redacted>",
                        metadata={
                            "provider": prov,
                            "env_key": k,
                            "secret_value": v,
                            "is_client_bundle": False,
                            "needs_auto_bff": False,
                        },
                    )
                )
                idx += 1

        # VA-ENV-001: Live secrets in .env* file without .gitignore protection (GitHub Push Leak!)
        if env_secrets_found and not ignores_dotenv:
            first_key, first_ln, first_lbl = env_secrets_found[0]
            keys_csv = ", ".join(k for k, _, _ in env_secrets_found[:5])
            findings.append(
                Finding(
                    id=f"VA-SEC-{idx:03d}",
                    pillar=Pillar.SECRET_BOUNDARY,
                    rule_id="VA-ENV-001",
                    cwe="CWE-540",
                    severity=Severity.CRITICAL,
                    title=f"Unignored '{env_rel}' With Live Secrets Ready to Leak on GitHub Push",
                    description=(
                        f"'{env_rel}' contains {len(env_secrets_found)} live credential(s) ({keys_csv}), "
                        "and '.gitignore' does not exclude '.env*' files — pushing to GitHub will expose live secrets publicly."
                    ),
                    blast_radius="Automated GitHub secret-scraping bots compromise leaked keys within seconds of `git push`.",
                    file_path=env_rel,
                    line_start=first_ln,
                    line_end=first_ln,
                    snippet=f"{first_key}=<redacted-live-secret>",
                    metadata={
                        "provider": "dotenv_guard",
                        "env_file": env_rel,
                        "env_keys": [k for k, _, _ in env_secrets_found],
                        "is_client_bundle": False,
                        "needs_auto_bff": False,
                    },
                )
            )
            idx += 1

    return findings
