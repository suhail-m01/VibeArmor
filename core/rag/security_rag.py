"""FAISS-Backed Security RAG Engine & Security Evidence Package Builder.

Grounds remediation proposals in structured vulnerability intelligence:
  - CWE (Common Weakness Enumeration)
  - OWASP Top 10 (2021 / 2025)
  - CAPEC (Common Attack Pattern Enumeration and Classification)
  - India DPDP Act 2023 Statutory Safeguards
  - Language & Framework Verified Minimal Remediation Patterns
"""

from __future__ import annotations

import hashlib
import math
import re
import time
from typing import Any, Dict, List, Optional
import numpy as np
from pydantic import BaseModel, Field

try:
    import faiss  # type: ignore
    _FAISS_AVAILABLE = True
except Exception:
    faiss = None  # type: ignore
    _FAISS_AVAILABLE = False

from core.models import Finding, MinimalSecuritySlice
from core.security_masking import mask_secrets

EMBED_DIM = 384


class SecurityKnowledgeDoc(BaseModel):
    doc_id: str
    cwe: str
    rule_ids: List[str] = Field(default_factory=list)
    owasp_category: str
    capec_id: str
    capec_attack_pattern: str
    title: str
    languages: List[str] = Field(default_factory=list)
    guidance_summary: str
    recommended_pattern: str
    verified_example: str
    remediation_constraints: List[str] = Field(default_factory=list)


class RetrievedEvidenceItem(BaseModel):
    doc_id: str
    cwe: str
    owasp_category: str
    capec_id: str
    capec_attack_pattern: str
    title: str
    similarity_score: float
    guidance_summary: str
    recommended_pattern: str
    verified_example: str


class SecurityEvidencePackage(BaseModel):
    finding_id: str
    rule_id: str
    vulnerability: str
    severity: str
    cwe: str
    owasp_category: str
    capec_id: str
    attack_pattern: str
    source_location: str
    code_context_masked: str
    ast_evidence: Dict[str, Any]
    data_flow_slice: List[str]
    retrieved_security_evidence: List[RetrievedEvidenceItem]
    recommended_pattern: str
    remediation_constraints: List[str]
    rag_backend: str
    retrieval_latency_ms: float


# Curated Security Intelligence Knowledge Base (CWE + OWASP + CAPEC + Verified Minimal Patterns)
SECURITY_CORPUS: List[SecurityKnowledgeDoc] = [
    SecurityKnowledgeDoc(
        doc_id="KB-CWE-89-SQLI",
        cwe="CWE-89",
        rule_ids=["VA-TNT-001", "VA-SQLI-001"],
        owasp_category="A03:2021 — Injection",
        capec_id="CAPEC-66",
        capec_attack_pattern="SQL Injection via String Concatenation or f-String Interpolation",
        title="SQL Injection Parameterization & Bound Query Enforcement",
        languages=["python", "typescript", "javascript", "sql"],
        guidance_summary="Never interpolate or concatenate user-controlled variables into SQL strings. Bind parameters via driver placeholders (?, %s, :param, or $1) so the database parser separates SQL AST structure from runtime data.",
        recommended_pattern="cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))",
        verified_example="cursor.execute(\"SELECT id, status FROM customer_orders WHERE order_code = ?\", (order_code,))",
        remediation_constraints=[
            "Preserve exact SELECT column list and table names",
            "Bind runtime arguments as a parameter tuple; never use f-strings or % formatting",
            "Do not alter return type or surrounding transaction commit semantics",
        ],
    ),
    SecurityKnowledgeDoc(
        doc_id="KB-CWE-284-RLS-MISSING",
        cwe="CWE-284",
        rule_ids=["VA-RLS-001", "VA-RLS-004"],
        owasp_category="A01:2021 — Broken Access Control",
        capec_id="CAPEC-122",
        capec_attack_pattern="Privilege Abuse on PostgREST / Supabase Public Schema Tables Without RLS",
        title="PostgreSQL & Supabase Row-Level Security (RLS) Tenant/Owner Isolation",
        languages=["sql", "postgresql"],
        guidance_summary="Tables created in PostgreSQL 'public' schema exposed via PostgREST/Supabase grant table-wide CRUD to the public anon key unless ENABLE ROW LEVEL SECURITY and an explicit owner-scoped CREATE POLICY are enforced.",
        recommended_pattern="ALTER TABLE public.<table> ENABLE ROW LEVEL SECURITY; CREATE POLICY ... TO authenticated USING ((select auth.uid()) = user_id) WITH CHECK ((select auth.uid()) = user_id);",
        verified_example="ALTER TABLE public.customer_orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY \"vibearmor_customer_orders_iso\" ON public.customer_orders FOR ALL TO authenticated USING ((select auth.uid()) = user_id) WITH CHECK ((select auth.uid()) = user_id);",
        remediation_constraints=[
            "Wrap auth.uid() in scalar subquery (select auth.uid()) for PostgreSQL initPlan caching",
            "Enforce both USING (read/delete) and WITH CHECK (insert/update) predicates",
            "If multi-tenant role semantics are ambiguous, abstain for explicit human policy spec",
        ],
    ),
    SecurityKnowledgeDoc(
        doc_id="KB-CWE-732-RLS-VACUOUS",
        cwe="CWE-732",
        rule_ids=["VA-RLS-002"],
        owasp_category="A01:2021 — Broken Access Control",
        capec_id="CAPEC-180",
        capec_attack_pattern="Exploiting Incorrectly Configured Access Control Security Levels (Vacuous USING true)",
        title="Eliminate Vacuous USING (true) / OR 1=1 RLS Policies on Sensitive Tables",
        languages=["sql", "postgresql"],
        guidance_summary="AI code generators frequently emit CREATE POLICY ... USING (true) to bypass permission errors during prototyping, silently exposing Aadhaar, PAN, phone, and order rows under India DPDP Act 2023 §8(5).",
        recommended_pattern="DROP POLICY IF EXISTS <vacuous_policy> ON public.<table>; CREATE POLICY <owner_policy> ON public.<table> FOR ALL TO authenticated USING ((select auth.uid()) = <owner_col>);",
        verified_example="DROP POLICY IF EXISTS \"allow_all_orders\" ON public.customer_orders;\nCREATE POLICY \"customer_orders_owner_only\" ON public.customer_orders FOR ALL TO authenticated USING ((select auth.uid()) = buyer_id) WITH CHECK ((select auth.uid()) = buyer_id);",
        remediation_constraints=[
            "Drop or replace only the vacuous policy; preserve unrelated strict policies",
            "Bind predicate to verified owner column or foreign-key join chain",
        ],
    ),
    SecurityKnowledgeDoc(
        doc_id="KB-CWE-269-SEC-DEFINER",
        cwe="CWE-269",
        rule_ids=["VA-RLS-003"],
        owasp_category="A04:2021 — Insecure Design / Privilege Escalation",
        capec_id="CAPEC-233",
        capec_attack_pattern="Privilege Escalation via Unpinned search_path in PostgreSQL SECURITY DEFINER RPC",
        title="Harden PostgreSQL SECURITY DEFINER Functions with Pinned search_path & REVOKE PUBLIC",
        languages=["sql", "postgresql"],
        guidance_summary="SECURITY DEFINER functions execute with superuser/owner privileges. Without SET search_path = public, pg_temp and REVOKE EXECUTE FROM PUBLIC, anon, attackers hijack object resolution or invoke privileged RPCs anonymously.",
        recommended_pattern="ALTER FUNCTION public.<fn>(<args>) SET search_path = public, pg_temp; REVOKE EXECUTE ON FUNCTION public.<fn>(<args>) FROM PUBLIC, anon;",
        verified_example="ALTER FUNCTION public.admin_grant_credit(UUID, NUMERIC) SET search_path = public, pg_temp;\nREVOKE EXECUTE ON FUNCTION public.admin_grant_credit(UUID, NUMERIC) FROM PUBLIC, anon;",
        remediation_constraints=[
            "Match exact PostgreSQL argument signature on ALTER/REVOKE statements",
            "Grant EXECUTE strictly to authenticated or service_role",
        ],
    ),
    SecurityKnowledgeDoc(
        doc_id="KB-CWE-798-HARDCODED-SECRET",
        cwe="CWE-798",
        rule_ids=["VA-SEC-001", "VA-SEC-002", "VA-ENV-001"],
        owasp_category="A07:2021 — Identification and Authentication Failures",
        capec_id="CAPEC-191",
        capec_attack_pattern="Read Sensitive Constants & API Keys Embedded in Client Bundle or Git History",
        title="Zero-Trust Secret Relocation, Auto-BFF Proxy Synthesis & .gitignore Enforcement",
        languages=["python", "typescript", "javascript"],
        guidance_summary="Hardcoded OpenAI, Supabase service_role, Stripe, Razorpay, or AWS keys in source files leak via client JS bundles and public Git commits. Relocate secrets to server-only environment variables, route client calls through a server BFF endpoint, and enforce .env* in .gitignore.",
        recommended_pattern="os.getenv('API_KEY', '') / process.env.API_KEY (server-only) + .gitignore '.env*'",
        verified_example="OPENAI_API_KEY = os.getenv(\"OPENAI_API_KEY\", \"\")",
        remediation_constraints=[
            "Never commit raw .env or .env.local files to Git",
            "Mask secret literals in logs and diagnostics (e.g., sk_live_****)",
            "Strip NEXT_PUBLIC_, VITE_, and REACT_APP_ prefixes from private keys",
        ],
    ),
    SecurityKnowledgeDoc(
        doc_id="KB-CWE-200-PUBLIC-ENV-PREFIX",
        cwe="CWE-200",
        rule_ids=["VA-ENV-002"],
        owasp_category="A05:2021 — Security Misconfiguration",
        capec_id="CAPEC-215",
        capec_attack_pattern="Client-Side Bundle Extraction of NEXT_PUBLIC_ / VITE_ Prefixed Private Secrets",
        title="Strip Public Browser Build Prefixes from Server Credentials",
        languages=["env", "typescript", "javascript"],
        guidance_summary="Next.js, Vite, and CRA inline NEXT_PUBLIC_*, VITE_*, and REACT_APP_* variables directly into public static JavaScript bundles shipped to every visitor's browser.",
        recommended_pattern="Rename NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY -> SUPABASE_SERVICE_ROLE_KEY and read only on server.",
        verified_example="SUPABASE_SERVICE_ROLE_KEY=eyJ...\nRAZORPAY_KEY_SECRET=rzp_...",
        remediation_constraints=[
            "Keep legitimate public publishable URLs/anon keys intact; strip prefixes only on secret/private/service_role keys",
        ],
    ),
    SecurityKnowledgeDoc(
        doc_id="KB-CWE-345-WEBHOOK-HMAC",
        cwe="CWE-345",
        rule_ids=["VA-TNT-002", "VA-PAY-001"],
        owasp_category="A08:2021 — Software and Data Integrity Failures",
        capec_id="CAPEC-477",
        capec_attack_pattern="Payment Fulfillment Bypass via Unverified Razorpay / Stripe Webhook Payload",
        title="Constant-Time HMAC-SHA256 Signature Verification for Payment Webhooks",
        languages=["python", "typescript", "javascript"],
        guidance_summary="Payment capture/fulfillment endpoints that trust order_id or payment_id without verifying X-Razorpay-Signature or Stripe-Signature allow zero-rupee order forgery. Compute HMAC-SHA256 over order_id + '|' + payment_id and compare with hmac.compare_digest.",
        recommended_pattern="expected = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest(); hmac.compare_digest(expected, signature)",
        verified_example="expected_sig = hmac.new(secret.encode('utf-8'), f'{order_id}|{payment_id}'.encode('utf-8'), hashlib.sha256).hexdigest()\nif not hmac.compare_digest(expected_sig, signature):\n    raise ValueError('Invalid payment signature')",
        remediation_constraints=[
            "Use constant-time comparison (hmac.compare_digest / crypto.timingSafeEqual) to prevent timing side-channels",
            "Reject empty or missing signatures before mutating order state",
        ],
    ),
    SecurityKnowledgeDoc(
        doc_id="KB-CWE-918-SSRF",
        cwe="CWE-918",
        rule_ids=["VA-TNT-008", "VA-SSRF-001"],
        owasp_category="A10:2021 — Server-Side Request Forgery (SSRF)",
        capec_id="CAPEC-664",
        capec_attack_pattern="Server-Side Request Forgery Targeting Cloud Metadata (169.254.169.254) or Internal Loopback",
        title="URL Scheme & Private IP / Cloud Metadata Allowlist Guard on Outbound HTTP",
        languages=["python", "typescript", "javascript"],
        guidance_summary="Passing user-controlled URLs or webhook endpoints into requests/httpx/fetch enables attackers to read AWS/GCP IMDSv1 credentials (169.254.169.254) or internal VPC services.",
        recommended_pattern="Validate parsed URL scheme in {'https', 'http'} and block loopback/link-local/RFC1918 IP ranges before dispatching request.",
        verified_example="parsed = urllib.parse.urlparse(target_url)\nif parsed.scheme not in ('http', 'https') or parsed.hostname in ('169.254.169.254', 'metadata.google.internal'):\n    raise ValueError('Blocked unsafe SSRF target')",
        remediation_constraints=[
            "Enforce explicit timeout on outbound HTTP requests",
            "Preserve legitimate configured upstream hostnames",
        ],
    ),
    SecurityKnowledgeDoc(
        doc_id="KB-CWE-78-CMD-INJECTION",
        cwe="CWE-78",
        rule_ids=["VA-TNT-003"],
        owasp_category="A03:2021 — Injection",
        capec_id="CAPEC-88",
        capec_attack_pattern="OS Command Injection via Shell Metacharacters in subprocess / os.system",
        title="Eliminate shell=True & Enforce Argument-Array Process Execution",
        languages=["python", "typescript", "javascript"],
        guidance_summary="Invoking subprocess.run/Popen with shell=True or os.system() passes strings through /bin/sh or cmd.exe, allowing ';', '&&', and '$()' command chaining.",
        recommended_pattern="subprocess.run(shlex.split(cmd), shell=False, check=True)",
        verified_example="subprocess.run(['git', 'status', '--porcelain'], shell=False, check=True)",
        remediation_constraints=[
            "Pass command arguments as a list with shell=False",
            "Keep stdout/stderr capture and timeout behavior unchanged",
        ],
    ),
    SecurityKnowledgeDoc(
        doc_id="KB-CWE-502-DESERIALIZATION",
        cwe="CWE-502",
        rule_ids=["VA-TNT-004", "VA-TNT-005"],
        owasp_category="A08:2021 — Software and Data Integrity Failures",
        capec_id="CAPEC-586",
        capec_attack_pattern="Object Injection & Remote Code Execution via Unsafe YAML / Pickle Deserialization",
        title="Safe Deserialization (yaml.safe_load & JSON Schema Validation)",
        languages=["python"],
        guidance_summary="PyYAML yaml.load() without SafeLoader and Python pickle.loads() execute arbitrary __reduce__ callables during parsing, giving attackers instant RCE.",
        recommended_pattern="yaml.safe_load(payload) / json.loads(payload)",
        verified_example="config = yaml.safe_load(raw_yaml_str)",
        remediation_constraints=[
            "Replace yaml.load(...) with yaml.safe_load(...) preserving variable assignment",
            "Replace untrusted pickle.loads(...) with json.loads(...) where data structure is JSON-compatible",
        ],
    ),
    SecurityKnowledgeDoc(
        doc_id="KB-CWE-79-XSS",
        cwe="CWE-79",
        rule_ids=["VA-TNT-006", "VA-XSS-001"],
        owasp_category="A03:2021 — Cross-Site Scripting (XSS)",
        capec_id="CAPEC-63",
        capec_attack_pattern="DOM / Reflected XSS via Unsanitized dangerouslySetInnerHTML or innerHTML",
        title="DOM Output Encoding & Sanitized HTML Rendering",
        languages=["typescript", "javascript", "tsx", "jsx"],
        guidance_summary="Rendering LLM output or user-supplied markdown via dangerouslySetInnerHTML or element.innerHTML executes injected <script> and onerror handlers in the victim's session.",
        recommended_pattern="Render plain text children in JSX or sanitize HTML strictly with DOMPurify.sanitize(rawHtml).",
        verified_example="<div>{userCommentText}</div>",
        remediation_constraints=[
            "Preserve component props and CSS classNames",
            "Strip executable script/event attributes if rich formatting is required",
        ],
    ),
    SecurityKnowledgeDoc(
        doc_id="KB-CWE-862-MISSING-AUTH",
        cwe="CWE-862",
        rule_ids=["VA-AUTH-006", "VA-TNT-007"],
        owasp_category="A01:2021 — Broken Access Control",
        capec_id="CAPEC-115",
        capec_attack_pattern="Authentication Bypass on Mutating Backend API Endpoints (POST/PUT/DELETE)",
        title="Bearer Token / Dependency Authentication Guard on State-Mutating Routes",
        languages=["python", "typescript", "javascript"],
        guidance_summary="AI-generated FastAPI/Express/Next.js POST/DELETE routes frequently omit authentication dependencies, exposing model ingestion, vector deletion, or admin actions to anonymous callers.",
        recommended_pattern="Add FastAPI Depends(_verify_api_bearer) or middleware session verification on mutating routes.",
        verified_example="@app.post('/ingest', dependencies=[Depends(_va_require_auth)])",
        remediation_constraints=[
            "Preserve Python 'from __future__ import annotations' at top of module when inserting auth helpers",
            "Allow local dev fallback only when explicitly configured via server env variable",
        ],
    ),
    SecurityKnowledgeDoc(
        doc_id="KB-CWE-829-SLOPSQUATTING",
        cwe="CWE-829",
        rule_ids=["VA-SUP-001"],
        owasp_category="A06:2021 — Vulnerable and Outdated Components / Supply Chain",
        capec_id="CAPEC-438",
        capec_attack_pattern="Malicious Package Substitution via AI-Hallucinated 'Slopsquatting' Dependency Names",
        title="Supply-Chain Slopsquatting Detection & Verified Canonical Package Replacement",
        languages=["json", "python", "javascript"],
        guidance_summary="LLMs hallucinate plausible package names (e.g. react-router-dom-v7-ai, fastapi-jwt-helper-ai) that attackers register on npm/PyPI with install-time credential stealers.",
        recommended_pattern="Replace hallucinated dependency with verified canonical registry package and validate AST import reachability.",
        verified_example="\"react-router-dom\": \"^6.28.0\"",
        remediation_constraints=[
            "Update package.json / requirements.txt while preserving JSON formatting and sibling dependencies",
        ],
    ),
    SecurityKnowledgeDoc(
        doc_id="KB-CWE-1395-VULN-DEP-CVE",
        cwe="CWE-1395",
        rule_ids=["VA-SUP-002"],
        owasp_category="A06:2021 — Vulnerable and Outdated Components",
        capec_id="CAPEC-310",
        capec_attack_pattern="Exploitation of Known Reachable Dependency CVEs (OSV / NVD Advisories)",
        title="AST-Reachable Vulnerable Dependency Version Upgrade",
        languages=["json", "python", "javascript"],
        guidance_summary="Prioritize dependency CVEs whose vulnerable module is actually imported in the runtime AST graph (eliminating unreachable devDependency noise) and pin to the minimum non-breaking patched version.",
        recommended_pattern="Upgrade vulnerable version pin to patched release verified in OSV advisory.",
        verified_example="pyjwt>=2.9.0\ncryptography>=43.0.1",
        remediation_constraints=[
            "Skip AST-unreachable dev-only packages to avoid unnecessary breaking upgrades",
        ],
    ),
]


def _embed_text_384(text: str) -> np.ndarray:
    """Deterministic 384-dim L2-normalized dense code+security subword & token feature embedding.

    Combines exact CWE/Rule/Sink semantic channels (dims 0..63) with hashed token & character n-gram
    projections (dims 64..383) so FAISS inner-product search achieves exact cosine ranking in <1 ms
    offline with zero network dependency.
    """
    vec = np.zeros(EMBED_DIM, dtype=np.float32)
    norm_txt = (text or "").lower()

    # Dedicated semantic anchor channels (0..31) for high-precision security concept alignment
    semantic_anchors = [
        ("cwe-89", "sql", "select", "execute", "cursor", "parameter"),
        ("cwe-284", "rls", "row level security", "enable row", "postgrest", "supabase"),
        ("cwe-732", "using (true)", "vacuous", "dpdp", "policy", "aadhaar"),
        ("cwe-269", "security definer", "search_path", "revoke", "rpc"),
        ("cwe-798", "secret", "api_key", "hardcoded", "sk_live", "token", "credential"),
        ("cwe-200", "next_public_", "vite_", "react_app_", "bundle", "env"),
        ("cwe-345", "hmac", "razorpay", "stripe", "webhook", "signature", "compare_digest"),
        ("cwe-918", "ssrf", "169.254.169.254", "requests.get", "httpx", "urlparse"),
        ("cwe-78", "shell=true", "subprocess", "os.system", "command injection"),
        ("cwe-502", "yaml.load", "safe_load", "pickle", "deserialize"),
        ("cwe-79", "xss", "dangerouslysetinnerhtml", "innerhtml", "script"),
        ("cwe-862", "unauthenticated", "depends", "bearer", "post", "delete", "auth"),
        ("cwe-829", "slopsquat", "hallucinated", "package.json", "npm", "pypi"),
        ("cwe-1395", "cve", "osv", "outdated", "requirements.txt", "version"),
    ]
    for idx, keywords in enumerate(semantic_anchors):
        hits = sum(1 for kw in keywords if kw in norm_txt)
        if hits:
            vec[idx * 2] = float(hits) * 2.4
            vec[idx * 2 + 1] = math.log1p(hits) * 2.0

    # Token & character 3-gram feature hashing into dims 64..383
    tokens = re.findall(r"[a-z0-9_\-]{2,}", norm_txt)
    for tok in tokens:
        h = int.from_bytes(hashlib.blake2b(tok.encode("utf-8"), digest_size=4).digest(), "little")
        slot = 64 + (h % (EMBED_DIM - 64))
        sign = 1.0 if ((h >> 17) & 1) == 0 else -1.0
        vec[slot] += sign * 1.25
        # Character 3-grams for partial identifier / CWE / API matching
        if len(tok) >= 4:
            for j in range(len(tok) - 2):
                tri = tok[j : j + 3]
                th = int.from_bytes(hashlib.blake2b(tri.encode("utf-8"), digest_size=4).digest(), "little")
                tslot = 64 + (th % (EMBED_DIM - 64))
                vec[tslot] += 0.35

    norm = float(np.linalg.norm(vec))
    if norm > 1e-8:
        vec /= norm
    return vec


class SecurityRAGIndex:
    """Vector-indexed Security Knowledge Base powered by FAISS IndexFlatIP (Cosine Similarity)."""

    def __init__(self, docs: List[SecurityKnowledgeDoc]) -> None:
        self.docs = list(docs)
        self.backend = "faiss_flat_ip_cosine_384d" if _FAISS_AVAILABLE else "numpy_cosine_384d"
        if not self.docs:
            self.matrix = np.zeros((0, EMBED_DIM), dtype=np.float32)
            self.index = None
            return

        mat = np.vstack([self._doc_vector(d) for d in self.docs]).astype(np.float32)
        self.matrix = mat
        if _FAISS_AVAILABLE:
            idx = faiss.IndexFlatIP(EMBED_DIM)
            idx.add(mat)
            self.index = idx
        else:
            self.index = None

    @staticmethod
    def _doc_vector(doc: SecurityKnowledgeDoc) -> np.ndarray:
        composite = " ".join(
            [
                doc.cwe,
                " ".join(doc.rule_ids),
                doc.owasp_category,
                doc.capec_id,
                doc.capec_attack_pattern,
                doc.title,
                " ".join(doc.languages),
                doc.guidance_summary,
                doc.recommended_pattern,
            ]
        )
        return _embed_text_384(composite)

    def retrieve(
        self,
        query: str,
        cwe_hint: str = "",
        rule_id_hint: str = "",
        top_k: int = 3,
    ) -> List[RetrievedEvidenceItem]:
        if not self.docs or top_k <= 0:
            return []
        q_str = f"{cwe_hint} {rule_id_hint} {query}".strip()
        if not q_str:
            return []
        q_vec = _embed_text_384(q_str).reshape(1, EMBED_DIM)
        k = min(top_k, len(self.docs))

        if self.index is not None:
            scores_arr, idxs_arr = self.index.search(q_vec, len(self.docs))
            raw_pairs = list(zip(idxs_arr[0].tolist(), scores_arr[0].tolist()))
        else:
            sims = (self.matrix @ q_vec.T).reshape(-1)
            order = np.argsort(-sims)
            raw_pairs = [(int(i), float(sims[i])) for i in order]

        # Hybrid boost when exact rule_id or CWE matches so canonical CWE guidance is always #1
        ranked: List[tuple[float, SecurityKnowledgeDoc]] = []
        norm_cwe = (cwe_hint or "").upper().strip()
        norm_rule = (rule_id_hint or "").upper().strip()
        for doc_idx, base_sim in raw_pairs:
            if doc_idx < 0 or doc_idx >= len(self.docs):
                continue
            doc = self.docs[doc_idx]
            boosted = float(base_sim)
            if norm_rule and norm_rule in [r.upper() for r in doc.rule_ids]:
                boosted = min(0.99, boosted + 0.25)
            elif norm_cwe and norm_cwe == doc.cwe.upper():
                boosted = min(0.98, boosted + 0.18)
            ranked.append((round(max(0.0, boosted), 4), doc))

        ranked.sort(key=lambda x: x[0], reverse=True)
        results: List[RetrievedEvidenceItem] = []
        for sim, doc in ranked[:k]:
            results.append(
                RetrievedEvidenceItem(
                    doc_id=doc.doc_id,
                    cwe=doc.cwe,
                    owasp_category=doc.owasp_category,
                    capec_id=doc.capec_id,
                    capec_attack_pattern=doc.capec_attack_pattern,
                    title=doc.title,
                    similarity_score=sim,
                    guidance_summary=doc.guidance_summary,
                    recommended_pattern=doc.recommended_pattern,
                    verified_example=doc.verified_example,
                )
            )
        return results


_GLOBAL_RAG_INDEX: Optional[SecurityRAGIndex] = None


def get_security_rag_index() -> SecurityRAGIndex:
    global _GLOBAL_RAG_INDEX
    if _GLOBAL_RAG_INDEX is None:
        _GLOBAL_RAG_INDEX = SecurityRAGIndex(SECURITY_CORPUS)
    return _GLOBAL_RAG_INDEX


def search_security_knowledge_base(
    query: str,
    cwe_hint: str = "",
    rule_id_hint: str = "",
    top_k: int = 3,
) -> Dict[str, Any]:
    t0 = time.perf_counter()
    rag = get_security_rag_index()
    items = rag.retrieve(query=query, cwe_hint=cwe_hint, rule_id_hint=rule_id_hint, top_k=top_k)
    latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
    return {
        "backend": rag.backend,
        "corpus_size": len(rag.docs),
        "retrieval_latency_ms": latency_ms,
        "results": [it.model_dump() for it in items],
    }


def _derive_ast_and_dataflow_evidence(
    finding: Finding,
    mss: Optional[MinimalSecuritySlice] = None,
) -> tuple[Dict[str, Any], List[str]]:
    """Construct honest AST structural metadata & source->transformation->sink slice steps."""
    ext = finding.file_path.rsplit(".", 1)[-1].lower() if "." in finding.file_path else "unknown"
    lang_map = {
        "py": "Python (Tree-sitter AST)",
        "ts": "TypeScript (Tree-sitter AST)",
        "tsx": "TSX / React (Tree-sitter AST)",
        "js": "JavaScript (Tree-sitter AST)",
        "jsx": "JSX / React (Tree-sitter AST)",
        "sql": "PostgreSQL DDL/RLS (sqlglot AST)",
        "json": "Dependency Manifest JSON",
    }
    parser_used = lang_map.get(ext, f"File Scanner ({ext})")

    p_val = finding.pillar.value
    if p_val == "rls_dpdp":
        chain = [
            f"1. Public PostgREST / Anonymous Client Request",
            f"2. Schema Object in {finding.file_path}:{finding.line_start}",
            f"3. Missing or Vacuous PostgreSQL RLS Guard ({finding.rule_id})",
            f"4. Unrestricted Table / RPC Data Sink ({', '.join(finding.dpdp_pii_columns) or 'all rows'})",
        ]
        sink_kind = "postgresql_rls_policy_sink"
    elif p_val == "secret_boundary":
        chain = [
            f"1. Credential Literal / Env Entry in {finding.file_path}:{finding.line_start}",
            "2. Client Bundle / Git Working Tree Inclusion",
            f"3. Boundary Violation ({finding.rule_id} · {finding.cwe})",
            "4. Public Browser / Repository Secret Exposure Sink",
        ]
        sink_kind = "credential_boundary_sink"
    elif p_val == "supply_chain":
        chain = [
            f"1. Package Manifest Entry in {finding.file_path}:{finding.line_start}",
            "2. Cross-File AST Import Reachability Check",
            f"3. Registry / Advisory Verification ({finding.rule_id})",
            "4. Runtime Dependency Execution Sink",
        ]
        sink_kind = "dependency_supply_chain_sink"
    else:
        chain = [
            "1. External HTTP / Caller Input Parameter",
            f"2. Function Scope in {finding.file_path}:{finding.line_start}",
            "3. Unvalidated String / Payload Propagation",
            f"4. Dangerous Execution Sink ({finding.rule_id} · {finding.cwe})",
        ]
        sink_kind = "taint_execution_sink"

    ast_ev = {
        "parser": parser_used,
        "language": ext,
        "file_path": finding.file_path,
        "line_range": f"{finding.line_start}..{finding.line_end}",
        "reachable_in_graph": finding.reachable,
        "sink_category": sink_kind,
        "linked_cross_layer_files": finding.linked_files,
        "mss_compression_pct": mss.compression_pct if mss else 0.0,
        "mss_slice_lines": mss.slice_lines if mss else 0,
    }
    return ast_ev, chain


def build_security_evidence_package(
    finding: Finding,
    mss: Optional[MinimalSecuritySlice] = None,
    top_k: int = 3,
) -> SecurityEvidencePackage:
    """Retrieve grounded CWE/OWASP/CAPEC intelligence and build a formal Security Evidence Package."""
    t0 = time.perf_counter()
    rag = get_security_rag_index()
    q_text = f"{finding.title} {finding.description} {mask_secrets(finding.snippet)}"
    retrieved = rag.retrieve(
        query=q_text,
        cwe_hint=finding.cwe,
        rule_id_hint=finding.rule_id,
        top_k=top_k,
    )
    latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    primary_doc: Optional[SecurityKnowledgeDoc] = None
    if retrieved:
        top_id = retrieved[0].doc_id
        primary_doc = next((d for d in rag.docs if d.doc_id == top_id), None)

    ast_ev, flow_chain = _derive_ast_and_dataflow_evidence(finding, mss)
    code_ctx = mask_secrets(mss.primary_slice if (mss and mss.primary_slice) else finding.snippet)

    return SecurityEvidencePackage(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        vulnerability=finding.title,
        severity=finding.severity.value,
        cwe=finding.cwe,
        owasp_category=retrieved[0].owasp_category if retrieved else "OWASP Top 10 Security Control",
        capec_id=retrieved[0].capec_id if retrieved else "CAPEC-1",
        attack_pattern=retrieved[0].capec_attack_pattern if retrieved else finding.blast_radius,
        source_location=f"{finding.file_path}:{finding.line_start}",
        code_context_masked=code_ctx[:1200],
        ast_evidence=ast_ev,
        data_flow_slice=flow_chain,
        retrieved_security_evidence=retrieved,
        recommended_pattern=(
            primary_doc.recommended_pattern if primary_doc else "Apply minimal verified remediation."
        ),
        remediation_constraints=(
            primary_doc.remediation_constraints
            if primary_doc
            else ["Modify only the vulnerable span", "Pass all 3 deterministic verification gates"]
        ),
        rag_backend=rag.backend,
        retrieval_latency_ms=latency_ms,
    )
