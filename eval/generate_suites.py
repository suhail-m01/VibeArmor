"""Generate persistent, non-circular Track 03 benchmark suites in eval/datasets/:
  1. SecurityEval-30 (verbatim from peer-reviewed s2e-lab/SecurityEval dataset.jsonl)
  2. VibeStack-28    (20 multi-file cross-layer vibe-coding apps + 8 hard-negative safe apps)
  3. FailureModes-6  (6 semantic/architectural boundary cases testing honest abstention)
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any, Dict, List

EVAL_DIR = Path(__file__).resolve().parent
DATASETS_DIR = EVAL_DIR / "datasets"
RAW_SECURITYEVAL = Path("/home/user/.cache/vibearmor/datasets/securityeval_raw.jsonl")

PREFERRED_SECURITYEVAL_IDS = [
    "CWE-089_author_1.py",
    "CWE-089_codeql_1.py",
    "CWE-078_author_1.py",
    "CWE-078_codeql_1.py",
    "CWE-094_author_1.py",
    "CWE-094_codeql_1.py",
    "CWE-094_sonar_1.py",
    "CWE-502_codeql_1.py",
    "CWE-502_mitre_1.py",
    "CWE-502_sonar_1.py",
    "CWE-022_author_1.py",
    "CWE-022_author_2.py",
    "CWE-022_codeql_1.py",
    "CWE-022_codeql_2.py",
    "CWE-079_codeql_1.py",
    "CWE-079_codeql_2.py",
    "CWE-079_sonar_1.py",
    "CWE-327_codeql_1.py",
    "CWE-327_codeql_2.py",
    "CWE-327_codeql_3.py",
    "CWE-327_codeql_4.py",
    "CWE-347_sonar_1.py",
    "CWE-347_sonar_2.py",
    "CWE-347_sonar_3.py",
    "CWE-601_flask_1.py",
    "CWE-601_sonar_1.py",
    "CWE-601_sonar_2.py",
    "CWE-611_author_1.py",
    "CWE-611_codeql_1.py",
    "CWE-611_sonar_1.py",
    "CWE-611_sonar_2.py",
    "CWE-611_sonar_3.py",
    "CWE-918_codeql_1.py",
    "CWE-918_codeql_2.py",
    "CWE-020_codeql_1.py",
    "CWE-020_codeql_2.py",
]


def build_securityeval_30() -> List[Dict[str, Any]]:
    existing_out = DATASETS_DIR / "securityeval_30.json"
    if not RAW_SECURITYEVAL.exists() and existing_out.exists():
        return json.loads(existing_out.read_text(encoding="utf-8"))

    raw_by_id: Dict[str, Dict[str, Any]] = {}
    for ln in RAW_SECURITYEVAL.read_text(encoding="utf-8").splitlines():
        if not ln.strip():
            continue
        obj = json.loads(ln)
        try:
            ast.parse(obj["Insecure_code"])
            raw_by_id[obj["ID"]] = obj
        except SyntaxError:
            continue

    selected: List[Dict[str, Any]] = []
    for tid in PREFERRED_SECURITYEVAL_IDS:
        if tid in raw_by_id and len(selected) < 30:
            item = raw_by_id[tid]
            selected.append(
                {
                    "id": item["ID"].replace(".py", ""),
                    "source": "s2e-lab/SecurityEval (Peer-Reviewed External Dataset)",
                    "cwe": item["ID"].split("_")[0],
                    "expected_vulnerable": True,
                    "files": {item["ID"]: item["Insecure_code"]},
                    "prompt_doc": item.get("Prompt", "")[:240],
                }
            )

    # Top up to 30 if any preferred ID was Python-2 skipped
    if len(selected) < 30:
        seen = {s["id"] + ".py" for s in selected}
        for tid, item in raw_by_id.items():
            if tid not in seen and len(selected) < 30:
                selected.append(
                    {
                        "id": item["ID"].replace(".py", ""),
                        "source": "s2e-lab/SecurityEval (Peer-Reviewed External Dataset)",
                        "cwe": item["ID"].split("_")[0],
                        "expected_vulnerable": True,
                        "files": {item["ID"]: item["Insecure_code"]},
                        "prompt_doc": item.get("Prompt", "")[:240],
                    }
                )
    return selected


def build_vibestack_28() -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = [
        # --- 20 Vulnerable Cross-Layer Multi-File Vibe-Coding Apps ---
        {
            "id": "VS-01-RLS-MISSING-USERS",
            "category": "RLS & DPDP",
            "cwe": "CWE-284",
            "expected_vulnerable": True,
            "files": {
                "supabase/migrations/01.sql": "CREATE TABLE public.profiles (id UUID PRIMARY KEY, user_id UUID, phone TEXT, pan_number TEXT);",
                "src/App.tsx": 'import { supabase } from "./sb"; export const load = () => supabase.from("profiles").select("*");',
            },
        },
        {
            "id": "VS-02-RLS-MISSING-INVOICES",
            "category": "RLS & DPDP",
            "cwe": "CWE-284",
            "expected_vulnerable": True,
            "files": {
                "supabase/migrations/01.sql": "CREATE TABLE public.gst_invoices (id UUID PRIMARY KEY, owner_id UUID, gstin TEXT, amount INT);",
                "src/Invoices.tsx": 'export const getInv = (sb: any) => sb.from("gst_invoices").select("*");',
            },
        },
        {
            "id": "VS-03-RLS-FK-CHILD-JOIN",
            "category": "RLS & DPDP (SLM FK Join)",
            "cwe": "CWE-284",
            "expected_vulnerable": True,
            "files": {
                "supabase/migrations/01.sql": (
                    "CREATE TABLE public.orders (id UUID PRIMARY KEY, user_id UUID NOT NULL);\n"
                    "ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n"
                    'CREATE POLICY "orders_own" ON public.orders FOR ALL TO authenticated USING ((select auth.uid()) = user_id);\n'
                    "CREATE TABLE public.shipment_events (id UUID PRIMARY KEY, order_id UUID REFERENCES public.orders(id), status TEXT);"
                ),
                "src/Track.tsx": 'export const track = (sb: any) => sb.from("shipment_events").select("*");',
            },
        },
        {
            "id": "VS-04-RLS-VACUOUS-TRUE-ALL",
            "category": "RLS & DPDP (CVE-2025-48757)",
            "cwe": "CWE-732",
            "expected_vulnerable": True,
            "files": {
                "supabase/migrations/01.sql": (
                    "CREATE TABLE public.kyc_docs (id UUID PRIMARY KEY, user_id UUID, aadhaar TEXT);\n"
                    "ALTER TABLE public.kyc_docs ENABLE ROW LEVEL SECURITY;\n"
                    'CREATE POLICY "allow_all_vibe" ON public.kyc_docs FOR ALL USING (true);'
                ),
                "src/Kyc.tsx": 'export const kyc = (sb: any) => sb.from("kyc_docs").select("*");',
            },
        },
        {
            "id": "VS-05-RLS-VACUOUS-INSERT",
            "category": "RLS & DPDP",
            "cwe": "CWE-732",
            "expected_vulnerable": True,
            "files": {
                "supabase/migrations/01.sql": (
                    "CREATE TABLE public.wallets (id UUID PRIMARY KEY, customer_id UUID, upi_id TEXT, balance INT);\n"
                    "ALTER TABLE public.wallets ENABLE ROW LEVEL SECURITY;\n"
                    'CREATE POLICY "open_write" ON public.wallets FOR INSERT WITH CHECK (true);'
                ),
            },
        },
        {
            "id": "VS-06-CLOUD-DRIFT-TABLE",
            "category": "Live Cloud Drift",
            "cwe": "CWE-284",
            "expected_vulnerable": True,
            "files": {
                "supabase/cloud_drift_catalog.json": json.dumps(
                    {
                        "pg_tables": [
                            {
                                "schemaname": "public",
                                "tablename": "customer_addresses",
                                "rowsecurity": False,
                                "columns": {"id": "uuid", "user_id": "uuid", "shipping_address": "text", "phone": "text"},
                            }
                        ]
                    }
                ),
            },
        },
        {
            "id": "VS-07-SECURITY-DEFINER-RPC",
            "category": "RPC Hardening",
            "cwe": "CWE-269",
            "expected_vulnerable": True,
            "files": {
                "supabase/migrations/rpc.sql": (
                    "CREATE FUNCTION public.reset_all_quotas() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN END; $$;"
                ),
            },
        },
        {
            "id": "VS-08-CLIENT-OPENAI-KEY",
            "category": "Zero-Trust Auto-BFF",
            "cwe": "CWE-798",
            "expected_vulnerable": True,
            "files": {
                "src/components/Chat.tsx": (
                    '"use client";\n'
                    'const KEY = "sk-proj-LiveSecretKeyForTestingAutoBffRelocation123456";\n'
                    'export async function ask(q: string) {\n'
                    '  return fetch("https://api.openai.com/v1/chat/completions", { method: "POST", headers: { Authorization: `Bearer ${KEY}` }, body: q });\n'
                    "}\n"
                ),
            },
        },
        {
            "id": "VS-09-CLIENT-ANTHROPIC-KEY",
            "category": "Zero-Trust Auto-BFF",
            "cwe": "CWE-798",
            "expected_vulnerable": True,
            "files": {
                "src/components/ClaudeBox.tsx": (
                    '"use client";\n'
                    'const CLAUDE_KEY = "sk-ant-api03-LiveAnthropicTestSecretKey9988776655443322";\n'
                    'export const run = () => fetch("https://api.anthropic.com/v1/messages", { method: "POST", headers: { "x-api-key": CLAUDE_KEY } });\n'
                ),
            },
        },
        {
            "id": "VS-10-CLIENT-SERVICE-ROLE-JWT",
            "category": "Secret Boundary",
            "cwe": "CWE-798",
            "expected_vulnerable": True,
            "files": {
                "src/lib/sbAdmin.ts": (
                    '"use client";\n'
                    "// Accidentally pasted Supabase service_role JWT in client!\n"
                    'export const ADMIN_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUifQ.secret_sig_12345";\n'
                ),
            },
        },
        {
            "id": "VS-11-RAZORPAY-SECRET-SERVER",
            "category": "India Fintech Secret",
            "cwe": "CWE-798",
            "expected_vulnerable": True,
            "files": {
                "backend/pay.py": 'RAZORPAY_SECRET = "rzp_live_SecretKeyIndiaFintech99887766"\ndef ping(): return True\n',
            },
        },
        {
            "id": "VS-12-RAZORPAY-ZERO-RUPEE-SPOOF",
            "category": "India Payment Integrity",
            "cwe": "CWE-345",
            "expected_vulnerable": True,
            "files": {
                "backend/webhook.py": (
                    "from fastapi import FastAPI\napp = FastAPI()\n"
                    "@app.post('/pay/confirm')\n"
                    "def confirm_order(order_id: str, razorpay_payment_id: str):\n"
                    "    return {'order': order_id, 'status': 'paid'}\n"
                ),
            },
        },
        {
            "id": "VS-13-UNAUTH-DELETE-API",
            "category": "API Access Control",
            "cwe": "CWE-306",
            "expected_vulnerable": True,
            "files": {
                "backend/users_api.py": (
                    "from fastapi import FastAPI\napp = FastAPI()\n"
                    "@app.delete('/api/account/{uid}')\n"
                    "def wipe_account(uid: str):\n"
                    "    return {'wiped': uid}\n"
                ),
            },
        },
        {
            "id": "VS-14-PY-SQLI-FSTRING",
            "category": "Taint Injection",
            "cwe": "CWE-089",
            "expected_vulnerable": True,
            "files": {
                "backend/search.py": (
                    "import sqlite3\n"
                    "def find_product(sku: str):\n"
                    "    db = sqlite3.connect(':memory:')\n"
                    "    return db.execute(f\"SELECT * FROM items WHERE sku = '{sku}'\").fetchall()\n"
                ),
            },
        },
        {
            "id": "VS-15-TS-SQLI-TEMPLATE",
            "category": "Taint Injection",
            "cwe": "CWE-089",
            "expected_vulnerable": True,
            "files": {
                "src/server/db.ts": (
                    "export async function lookupUser(pool: any, email: string) {\n"
                    "  return pool.query(`SELECT id, role FROM users WHERE email = '${email}'`);\n"
                    "}\n"
                ),
            },
        },
        {
            "id": "VS-16-PY-CMD-SHELL",
            "category": "Taint Injection",
            "cwe": "CWE-078",
            "expected_vulnerable": True,
            "files": {
                "backend/pdf_export.py": (
                    "import os\n"
                    "def convert_invoice(filename: str):\n"
                    "    os.system(f'ps2pdf {filename}')\n"
                ),
            },
        },
        {
            "id": "VS-17-PY-YAML-UNSAFE",
            "category": "Unsafe Deserialization",
            "cwe": "CWE-502",
            "expected_vulnerable": True,
            "files": {
                "backend/config_loader.py": (
                    "import yaml\n"
                    "def parse_theme(raw_yaml: str):\n"
                    "    return yaml.load(raw_yaml)\n"
                ),
            },
        },
        {
            "id": "VS-18-NPM-SLOPSQUAT-HALLUCINATION",
            "category": "Supply Chain Slopsquatting",
            "cwe": "CWE-829",
            "expected_vulnerable": True,
            "files": {
                "package.json": json.dumps({"name": "app", "dependencies": {"react-razorpay-secure-v2": "^1.0.0"}}),
            },
        },
        {
            "id": "VS-19-NPM-TYPOSQUAT",
            "category": "Supply Chain Typosquatting",
            "cwe": "CWE-829",
            "expected_vulnerable": True,
            "files": {
                "package.json": json.dumps({"name": "app", "dependencies": {"axois": "^1.7.0"}}),
            },
        },
        {
            "id": "VS-20-REACHABLE-CVE-PYJWT",
            "category": "Reachable OSV CVE",
            "cwe": "CWE-1395",
            "expected_vulnerable": True,
            "files": {
                "requirements.txt": "pyjwt==2.1.0\n",
                "backend/auth.py": "import jwt\ndef check(tok: str, key: str):\n    return jwt.decode(tok, key, algorithms=['HS256'])\n",
            },
        },
        # --- 8 Hard-Negative Safe Apps (False-Positive Immunity Suite!) ---
        {
            "id": "HN-01-PUBLIC-CATALOG-SELECT-TRUE",
            "category": "Hard Negative (Public Catalog)",
            "cwe": "NONE",
            "expected_vulnerable": False,
            "files": {
                "supabase/migrations/01.sql": (
                    "CREATE TABLE public.products (id UUID PRIMARY KEY, title TEXT, price_inr INT);\n"
                    "ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;\n"
                    'CREATE POLICY "pub_read" ON public.products FOR SELECT USING (true);'
                ),
            },
        },
        {
            "id": "HN-02-PUBLIC-EVENTS-SELECT-TRUE",
            "category": "Hard Negative (Public Events)",
            "cwe": "NONE",
            "expected_vulnerable": False,
            "files": {
                "supabase/migrations/01.sql": (
                    "CREATE TABLE public.public_events (id UUID PRIMARY KEY, title TEXT, city TEXT);\n"
                    "ALTER TABLE public.public_events ENABLE ROW LEVEL SECURITY;\n"
                    'CREATE POLICY "events_read" ON public.public_events FOR SELECT USING (true);'
                ),
            },
        },
        {
            "id": "HN-03-SAFE-SUPABASE-ANON-JWT",
            "category": "Hard Negative (Safe Anon Key)",
            "cwe": "NONE",
            "expected_vulnerable": False,
            "files": {
                "supabase/migrations/01.sql": (
                    "CREATE TABLE public.notes (id UUID PRIMARY KEY, user_id UUID);\n"
                    "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
                    'CREATE POLICY "own_notes" ON public.notes FOR ALL TO authenticated USING ((select auth.uid()) = user_id);'
                ),
                "src/sb.ts": (
                    '"use client";\n'
                    'export const ANON = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJhbm9uIn0.safe_public_sig";\n'
                ),
            },
        },
        {
            "id": "HN-04-PARAMETERIZED-SQL",
            "category": "Hard Negative (Safe SQL)",
            "cwe": "NONE",
            "expected_vulnerable": False,
            "files": {
                "backend/db.py": (
                    "import sqlite3\n"
                    "def get_order(oid: str):\n"
                    "    conn = sqlite3.connect(':memory:')\n"
                    "    return conn.execute('SELECT * FROM orders WHERE id = ?', (oid,)).fetchall()\n"
                ),
            },
        },
        {
            "id": "HN-05-SAFE-SUBPROCESS-LIST",
            "category": "Hard Negative (Safe Subprocess)",
            "cwe": "NONE",
            "expected_vulnerable": False,
            "files": {
                "backend/runner.py": (
                    "import subprocess\n"
                    "def ping_host(ip: str):\n"
                    "    return subprocess.run(['ping', '-c', '1', ip], shell=False, check=False)\n"
                ),
            },
        },
        {
            "id": "HN-06-VERIFIED-RAZORPAY-HMAC",
            "category": "Hard Negative (Verified HMAC)",
            "cwe": "NONE",
            "expected_vulnerable": False,
            "files": {
                "backend/rzp_ok.py": (
                    "import hmac, hashlib, os\n"
                    "def verify_rzp(order_id: str, payment_id: str, sig: str):\n"
                    "    sec = os.environ.get('RAZORPAY_SECRET', 'dev')\n"
                    "    exp = hmac.new(sec.encode(), f'{order_id}|{payment_id}'.encode(), hashlib.sha256).hexdigest()\n"
                    "    if hmac.compare_digest(exp, sig):\n"
                    "        return {'status': 'paid'}\n"
                    "    return {'status': 'rejected'}\n"
                ),
            },
        },
        {
            "id": "HN-07-UNREACHABLE-DEV-CVE",
            "category": "Hard Negative (Unreachable CVE)",
            "cwe": "NONE",
            "expected_vulnerable": False,
            "files": {
                "requirements.txt": "pytest-cov==2.10.0\n",
                "backend/app.py": "def health():\n    return {'ok': True}\n",
            },
        },
        {
            "id": "HN-08-AUTHENTICATED-DELETE-ROUTE",
            "category": "Hard Negative (Auth Route)",
            "cwe": "NONE",
            "expected_vulnerable": False,
            "files": {
                "backend/api.py": (
                    "from fastapi import FastAPI, Depends\napp = FastAPI()\n"
                    "def get_current_user(): return 'usr_1'\n"
                    "@app.delete('/items/{item_id}')\n"
                    "def remove_item(item_id: str, user: str = Depends(get_current_user)):\n"
                    "    return {'deleted': item_id, 'by': user}\n"
                ),
            },
        },
    ]
    return tasks


def build_failure_modes_6() -> List[Dict[str, Any]]:
    return [
        {
            "id": "FM-01-MULTITENANT-REFUND-APPROVAL",
            "boundary_type": "Multi-Tenant Custom Role & INR Threshold RLS",
            "expected_abstention_code": "NEEDS_POLICY_SPEC",
            "files": {
                "supabase/migrations/01.sql": (
                    "-- POLICY_SPEC: Managers approve refunds <= 10000 INR; Directors approve > 10000 INR within same org_id\n"
                    "CREATE TABLE public.refund_requests (\n"
                    "    id UUID PRIMARY KEY,\n"
                    "    org_id UUID NOT NULL,\n"
                    "    required_role TEXT NOT NULL,\n"
                    "    approval_limit_inr INT NOT NULL,\n"
                    "    refund_amount_inr INT NOT NULL\n"
                    ");"
                )
            },
        },
        {
            "id": "FM-02-ORG-DEPARTMENT-LEDGER",
            "boundary_type": "Multi-Tenant Hierarchical Org/Dept Matrix",
            "expected_abstention_code": "NEEDS_POLICY_SPEC",
            "files": {
                "supabase/migrations/01.sql": (
                    "CREATE TABLE public.org_payout_ledger (\n"
                    "    id UUID PRIMARY KEY,\n"
                    "    tenant_id UUID NOT NULL,\n"
                    "    department_id UUID NOT NULL,\n"
                    "    min_approver_tier INT NOT NULL\n"
                    ");"
                )
            },
        },
        {
            "id": "FM-03-DYNAMIC-PLUGIN-GETATTR",
            "boundary_type": "Dynamic Runtime Reflection Dispatch",
            "expected_abstention_code": "NEEDS_ALLOWLIST_SPEC",
            "files": {
                "backend/plugin_router.py": (
                    "class PaymentPlugins:\n"
                    "    def upi(self): return 'upi'\n"
                    "def dispatch_plugin(registry: PaymentPlugins, plugin_action: str):\n"
                    "    fn = getattr(registry, plugin_action)\n"
                    "    return fn()\n"
                )
            },
        },
        {
            "id": "FM-04-WEBHOOK-REFLECTIVE-HANDLER",
            "boundary_type": "Dynamic Runtime Reflection Dispatch",
            "expected_abstention_code": "NEEDS_ALLOWLIST_SPEC",
            "files": {
                "backend/events.py": (
                    "def handle_webhook_event(controller: object, event_type: str, data: dict):\n"
                    "    handler = getattr(controller, event_type)\n"
                    "    return handler(data)\n"
                )
            },
        },
        {
            "id": "FM-05-STATEFUL-COUPON-RACE",
            "boundary_type": "Stateful Multi-Request TOCTOU Coupon Replay",
            "expected_abstention_code": "NEEDS_BUSINESS_INVARIANT",
            "files": {
                "backend/promo.py": (
                    "# STATEFUL_LOGIC_FLOW: Single-use vs campaign-cap semantics require business invariant\n"
                    "def redeem_festival_coupon(coupon_code: str, used_count: int):\n"
                    "    if coupon_code and used_count == 0:\n"
                    "        return {'applied': True}\n"
                    "    return {'applied': False}\n"
                )
            },
        },
        {
            "id": "FM-06-WALLET-CONCURRENT-DEBIT",
            "boundary_type": "Stateful Non-Atomic Wallet Balance Debit",
            "expected_abstention_code": "NEEDS_BUSINESS_INVARIANT",
            "files": {
                "backend/wallet.py": (
                    "def debit_loyalty_coins(wallet_balance: int, debit_pts: int):\n"
                    "    wallet_balance -= debit_pts\n"
                    "    return {'remaining': wallet_balance}\n"
                )
            },
        },
    ]


def generate_all_suites() -> Dict[str, int]:
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    se30 = build_securityeval_30()
    vs28 = build_vibestack_28()
    fm06 = build_failure_modes_6()

    (DATASETS_DIR / "securityeval_30.json").write_text(json.dumps(se30, indent=2) + "\n", encoding="utf-8")
    (DATASETS_DIR / "vibestack_28.json").write_text(json.dumps(vs28, indent=2) + "\n", encoding="utf-8")
    (DATASETS_DIR / "failure_modes_6.json").write_text(json.dumps(fm06, indent=2) + "\n", encoding="utf-8")
    return {
        "securityeval_30": len(se30),
        "vibestack_28": len(vs28),
        "failure_modes_6": len(fm06),
    }


if __name__ == "__main__":
    counts = generate_all_suites()
    print("[VibeArmor Eval] Generated persistent benchmark suites:", counts)
