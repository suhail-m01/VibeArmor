"""Comprehensive End-to-End Automated Test Suite for VibeArmor (10 Full-Stack Verification Suites)."""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient

from core.engine import scan_and_heal
from core.interfaces.api import _PROJECT_META, _PROJECT_REPORTS, _STAGED_BUNDLES, app
from core.interfaces.cli import main as cli_main
from core.interfaces.mcp_server import vibearmor_heal_snippet, vibearmor_scan
from core.models import FileEdit, RemediationStatus
from core.verifier.gate1_compile import run_gate1_compile


class TestVibeArmorEndToEnd(unittest.TestCase):
    def test_01_clean_fast_path_zero_false_positives(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "supabase" / "migrations").mkdir(parents=True)
            (root / "supabase" / "migrations" / "01.sql").write_text(
                "CREATE TABLE public.products (id UUID PRIMARY KEY, title TEXT, price_inr INT);\n"
                "ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;\n"
                'CREATE POLICY "pub_select" ON public.products FOR SELECT USING (true);\n',
                encoding="utf-8",
            )
            (root / "src").mkdir()
            (root / "src" / "sb.ts").write_text(
                '"use client";\n'
                'export const ANON = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJhbm9uIn0.safe";\n',
                encoding="utf-8",
            )
            (root / "requirements.txt").write_text("pytest-cov==2.10.0\n", encoding="utf-8")
            (root / "app.py").write_text(
                "import sqlite3\n"
                "def safe_q(uid: str):\n"
                "    c = sqlite3.connect(':memory:')\n"
                "    return c.execute('SELECT 1 WHERE ? = ?', (uid, uid)).fetchall()\n",
                encoding="utf-8",
            )

            rep = scan_and_heal(root, auto_heal=False)
            self.assertEqual(rep.summary["actionable_before"], 0)
            self.assertEqual(rep.llm_calls_made, 0)
            self.assertLess(rep.scan_latency_ms, 180.0)
            self.assertEqual(rep.summary["unreachable_info_filtered"], 1)

    def test_02_rls_vacuous_dpdp_and_fk_slm_synthesis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mig = root / "supabase" / "migrations" / "01.sql"
            mig.parent.mkdir(parents=True)
            mig.write_text(
                "CREATE TABLE public.orders (id UUID PRIMARY KEY, user_id UUID NOT NULL, pan_number TEXT);\n"
                "ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n"
                'CREATE POLICY "open_vibe" ON public.orders FOR ALL USING (true);\n'
                "CREATE TABLE public.order_items (id UUID PRIMARY KEY, order_id UUID REFERENCES public.orders(id));\n",
                encoding="utf-8",
            )
            rep = scan_and_heal(root, auto_heal=True, allow_slm=True)
            self.assertEqual(rep.summary["actionable_before"], 2)
            self.assertEqual(rep.summary["actionable_after"], 0)
            self.assertEqual(rep.summary["verified_fixed_count"], 2)
            healed_sql = mig.read_text(encoding="utf-8")
            self.assertIn("auth.uid()", healed_sql)

    def test_03_zero_trust_auto_bff_secret_relocation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            comp = root / "src" / "components" / "Chat.tsx"
            comp.parent.mkdir(parents=True)
            secret = "sk-proj-UnitTestAutoBffLiveSecretKey998877665544"
            comp.write_text(
                f'"use client";\nconst K = "{secret}";\n'
                'export const run = () => fetch("https://api.openai.com/v1/chat/completions", { method: "POST", headers: { Authorization: `Bearer ${K}` } });\n',
                encoding="utf-8",
            )
            rep = scan_and_heal(root, auto_heal=True)
            self.assertEqual(rep.summary["actionable_after"], 0)
            self.assertNotIn(secret, comp.read_text(encoding="utf-8"))
            self.assertIn("/api/vibearmor/openai", comp.read_text(encoding="utf-8"))
            bff = (root / "src" / "app" / "api" / "vibearmor" / "openai" / "route.ts").read_text(encoding="utf-8")
            self.assertIn("verifyCallerSession", bff)
            self.assertIn("checkRateLimit", bff)
            self.assertIn("VIBEARMOR_CSRF_ORIGIN_BLOCKED", bff)
            self.assertIn(secret, (root / ".env.local").read_text(encoding="utf-8"))

    def test_04_razorpay_hmac_and_sqli_closed_loop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            api_py = root / "checkout.py"
            api_py.write_text(
                "import sqlite3\nfrom fastapi import FastAPI, Request\napp = FastAPI()\n"
                "def get_order(oid: str):\n"
                "    c = sqlite3.connect(':memory:')\n"
                "    return c.execute(f\"SELECT * FROM t WHERE id = '{oid}'\").fetchall()\n\n"
                "@app.post('/rzp')\n"
                "async def rzp_cb(request: Request):\n"
                "    payload = await request.json()\n"
                "    payment_id = payload.get('razorpay_payment_id', '')\n"
                "    if payment_id:\n"
                "        return {'status': 'PAID'}\n",
                encoding="utf-8",
            )
            rep = scan_and_heal(root, auto_heal=True)
            self.assertEqual(rep.summary["actionable_after"], 0)
            after_py = api_py.read_text(encoding="utf-8")
            self.assertIn("hmac.compare_digest", after_py)
            self.assertIn("WHERE id = ?", after_py)

    def test_05_supply_chain_slopsquat_and_cve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "package.json"
            pkg.write_text(
                json.dumps({"name": "demo", "dependencies": {"axios": "0.21.1", "supabase-auth-helper-ai": "^1.0.0"}}),
                encoding="utf-8",
            )
            (root / "src").mkdir()
            (root / "src" / "api.ts").write_text('import axios from "axios"; export const a = axios;\n', encoding="utf-8")
            rep = scan_and_heal(root, auto_heal=True)
            self.assertEqual(rep.summary["actionable_after"], 0)
            updated = json.loads(pkg.read_text(encoding="utf-8"))["dependencies"]
            self.assertNotIn("supabase-auth-helper-ai", updated)
            self.assertTrue(updated["axios"].startswith("^1.7"))

    def test_06_honest_policy_abstention_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "schema.sql").write_text(
                "CREATE TABLE public.approvals (id UUID PRIMARY KEY, org_id UUID, required_role TEXT, approval_limit_inr INT);\n",
                encoding="utf-8",
            )
            (root / "reflect.py").write_text(
                "def dispatch(ctrl: object, action: str):\n    return getattr(ctrl, action)()\n",
                encoding="utf-8",
            )
            rep = scan_and_heal(root, auto_heal=True)
            self.assertEqual(len(rep.abstentions), 2)
            self.assertTrue(all(p.status == RemediationStatus.ABSTAINED for p in rep.patches))

    def test_07_gate1_rollback_on_syntax_failure(self) -> None:
        bad_edit = FileEdit(
            file_path="broken.py",
            before_content="def ok():\n    return 1\n",
            after_content="def broken(:\n    return 1\n",
            unified_diff="",
        )
        g1 = run_gate1_compile([bad_edit])
        self.assertFalse(g1.passed)
        self.assertIn("SyntaxError", g1.summary)

    def test_08_cli_init_and_guard_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc_init = cli_main(["init", tmp])
            self.assertEqual(rc_init, 0)
            self.assertTrue((Path(tmp) / ".git" / "hooks" / "pre-commit").exists())
            self.assertTrue((Path(tmp) / ".cursor" / "mcp.json").exists())
            rc_guard = cli_main(["guard", tmp])
            self.assertEqual(rc_guard, 0)

    def test_09_mcp_tools_integration(self) -> None:
        res_json = vibearmor_heal_snippet(
            "vuln.py",
            "import yaml\ndef load_cfg(s: str):\n    return yaml.load(s)\n",
        )
        parsed = json.loads(res_json)
        self.assertIn("yaml.safe_load", parsed["healed_content"])

        with tempfile.TemporaryDirectory() as tmp:
            scan_out = json.loads(vibearmor_scan(tmp))
            self.assertTrue(scan_out["clean_fast_path"])

    def test_10_fastapi_studio_and_demo_arena_cycle(self) -> None:
        client = TestClient(app)

        r_root = client.get("/")
        self.assertEqual(r_root.status_code, 200)
        self.assertIn("VibeArmor", r_root.text)

        r_health = client.get("/api/health")
        self.assertEqual(r_health.status_code, 200)
        self.assertEqual(r_health.json()["status"], "ok")

        # 1. Reset demo to vulnerable baseline
        r_reset = client.post("/api/demo/reset")
        self.assertEqual(r_reset.status_code, 200)
        self.assertFalse(r_reset.json()["breach"]["all_blocked"])

        # 2. Heal all VibeBazaar vulnerabilities via closed-loop API
        r_heal = client.post("/api/demo/heal")
        self.assertEqual(r_heal.status_code, 200)
        heal_data = r_heal.json()
        self.assertEqual(heal_data["report"]["summary"]["verified_fixed_count"], 10)
        self.assertEqual(heal_data["report"]["summary"]["broken_builds"], 0)
        self.assertTrue(heal_data["breach_after"]["all_blocked"])
        self.assertEqual(heal_data["breach_after"]["blocked_count"], 4)

        # 3. Test Judge Paste Sandbox API
        r_sb = client.post(
            "/api/sandbox/analyze",
            json={
                "files": [{"path": "demo.py", "content": "import pickle\ndef f(b: bytes):\n    return pickle.loads(b)\n"}],
                "auto_heal": True,
                "allow_slm": True,
            },
        )
        self.assertEqual(r_sb.status_code, 200)
        self.assertEqual(r_sb.json()["report"]["summary"]["actionable_after"], 0)

        # 4. Verify empirical benchmark endpoint
        r_eval = client.get("/api/eval/results")
        self.assertEqual(r_eval.status_code, 200)
        self.assertEqual(r_eval.json()["datasets"]["total_evaluated_cases"], 64)

        # 5. Leave VibeBazaar demo cleanly reset at vulnerable baseline for interactive UI demo!
        client.post("/api/demo/reset")

    def test_11_live_github_clone_and_scan(self) -> None:
        client = TestClient(app)
        r_gh = client.post(
            "/api/projects/github",
            json={"repo_url": "https://github.com/suhail-m01/NeXGen-Coders-RAG"},
        )
        if r_gh.status_code == 200:
            payload = r_gh.json()
            pid = payload["project"]["id"]
            self.assertTrue(pid.startswith("gh-"))
            self.assertGreater(len(payload["files"]), 0)
            _PROJECT_META.pop(pid, None)
            _PROJECT_REPORTS.pop(pid, None)
            shutil.rmtree(PROJECT_ROOT / "workspaces_store" / pid, ignore_errors=True)
        else:
            self.assertIn(r_gh.status_code, (400, 408))

    def test_12_zip_upload_ndjson_stream_and_exports(self) -> None:
        client = TestClient(app)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "app/db.py",
                "import sqlite3\ndef q(u: str):\n    c = sqlite3.connect(':memory:')\n    return c.execute(f\"SELECT * FROM users WHERE name = '{u}'\").fetchall()\n",
            )
            zf.writestr(
                "supabase/migrations/01.sql",
                "CREATE TABLE public.secrets_tbl (id UUID PRIMARY KEY, user_id UUID, phone TEXT);\n",
            )
        buf.seek(0)

        r_up = client.post(
            "/api/projects/upload-zip",
            files={"file": ("vibe-test.zip", buf.getvalue(), "application/zip")},
        )
        self.assertEqual(r_up.status_code, 200)
        pid = r_up.json()["project"]["id"]

        # Stream heal via NDJSON
        r_stream = client.post(f"/api/projects/{pid}/heal-stream")
        self.assertEqual(r_stream.status_code, 200)
        lines = [json.loads(ln) for ln in r_stream.text.splitlines() if ln.strip()]
        self.assertTrue(any(m["type"] == "progress" for m in lines))
        self.assertTrue(any(m["type"] == "complete" for m in lines))

        # Test exports: .patch, .zip, and DPDP certificate HTML
        r_patch = client.get(f"/api/projects/{pid}/export/patch")
        self.assertEqual(r_patch.status_code, 200)
        self.assertIn("diff --git", r_patch.text)

        r_zip = client.get(f"/api/projects/{pid}/export/zip")
        self.assertEqual(r_zip.status_code, 200)
        self.assertGreater(len(r_zip.content), 100)

        r_cert = client.get(f"/api/projects/{pid}/export/certificate")
        self.assertEqual(r_cert.status_code, 200)
        self.assertIn("DPDP Act 2023 Verification Certificate", r_cert.text)

        _PROJECT_META.pop(pid, None)
        _PROJECT_REPORTS.pop(pid, None)
        shutil.rmtree(PROJECT_ROOT / "workspaces_store" / pid, ignore_errors=True)

    def test_13_custom_live_sqlite_union_injection_and_razorpay_probe(self) -> None:
        client = TestClient(app)
        client.post("/api/demo/reset")

        # Custom UNION SQLi dumps PAN numbers before healing
        r_before = client.post(
            "/api/demo/exploit",
            json={
                "sqli_payload": "' UNION SELECT id, customer_name, amount_inr, pan_number FROM customer_orders --",
                "caller_role": "anon",
            },
        )
        self.assertEqual(r_before.status_code, 200)
        taint_before = next(a for a in r_before.json()["attacks"] if a["id"] == "breach_sqli_razorpay")
        self.assertFalse(taint_before["blocked"])
        self.assertGreaterEqual(taint_before["sqli_rows_dumped"], 3)

        # Heal and re-run exact same UNION SQLi -> 0 rows dumped!
        client.post("/api/demo/heal")
        r_after = client.post(
            "/api/demo/exploit",
            json={
                "sqli_payload": "' UNION SELECT id, customer_name, amount_inr, pan_number FROM customer_orders --",
                "caller_role": "anon",
            },
        )
        taint_after = next(a for a in r_after.json()["attacks"] if a["id"] == "breach_sqli_razorpay")
        self.assertTrue(taint_after["blocked"])
        self.assertEqual(taint_after["sqli_rows_dumped"], 0)

        # Reset baseline cleanly
        client.post("/api/demo/reset")

    def test_14_dotenv_git_push_hygiene_and_public_prefix_guard(self) -> None:
        client = TestClient(app)
        navbar_code = 'export function Navbar() {\n  return <nav className="p-4">Brand</nav>;\n}\n'
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                ".env",
                (
                    "OPENAI_API_KEY=" + ("sk-" + "proj-LiveSecretKey998877665544332211\n")
                    + "NEXT_PUBLIC_STRIPE_SECRET=" + ("sk_" + "live_StripeSecretKey11223344556677\n")
                ),
            )
            zf.writestr("src/components/Navbar.tsx", navbar_code)
        buf.seek(0)

        r_up = client.post(
            "/api/projects/upload-zip",
            files={"file": ("dotenv-leak.zip", buf.getvalue(), "application/zip")},
        )
        self.assertEqual(r_up.status_code, 200)
        pid = r_up.json()["project"]["id"]
        rule_ids = {f["rule_id"] for f in r_up.json()["report"]["findings_before"]}
        self.assertIn("VA-ENV-001", rule_ids)
        self.assertIn("VA-ENV-002", rule_ids)

        # Stage proposals WITHOUT mutating workspace on disk
        r_prop = client.post(f"/api/projects/{pid}/propose-fixes")
        self.assertEqual(r_prop.status_code, 200)
        prop_data = r_prop.json()
        self.assertIn("src/components/Navbar.tsx", prop_data["untouched_safe_files"])

        # Confirm workspace has NOT been modified yet before user consent!
        ws_dir = Path(_PROJECT_META[pid]["workspace_path"])
        self.assertFalse((ws_dir / ".gitignore").exists())

        # Now user explicitly adopts all proposals
        sel_ids = [p["finding_id"] for p in prop_data["proposals"] if p["adoptable"]]
        r_adopt = client.post(f"/api/projects/{pid}/adopt-fixes", json={"selected_finding_ids": sel_ids})
        self.assertEqual(r_adopt.status_code, 200)
        self.assertTrue((ws_dir / ".gitignore").exists())
        self.assertIn(".env", (ws_dir / ".gitignore").read_text(encoding="utf-8"))
        self.assertTrue((ws_dir / ".env.example").exists())
        # Verify Navbar.tsx is 100% byte-for-byte untouched!
        self.assertEqual((ws_dir / "src/components/Navbar.tsx").read_text(encoding="utf-8"), navbar_code)

        _PROJECT_META.pop(pid, None)
        _PROJECT_REPORTS.pop(pid, None)
        _STAGED_BUNDLES.pop(pid, None)
        shutil.rmtree(PROJECT_ROOT / "workspaces_store" / pid, ignore_errors=True)

    def test_15_selective_user_adoption_strict_surgical_precision(self) -> None:
        client = TestClient(app)
        clean_helper = (
            "def calculate_gst_invoice(subtotal: float) -> float:\n"
            "    # Clean business logic that MUST NEVER be modified\n"
            "    return round(subtotal * 1.18, 2)\n"
        )
        orders_py = (
            "import sqlite3\n\n"
            + clean_helper
            + "\ndef find_order(order_code: str):\n"
            "    conn = sqlite3.connect(':memory:')\n"
            "    return conn.execute(f\"SELECT * FROM orders WHERE code = '{order_code}'\").fetchall()\n"
        )
        schema_sql = "CREATE TABLE public.payouts (id UUID PRIMARY KEY, user_id UUID, pan_number TEXT);\n"
        utils_py = "def format_inr(v: int) -> str:\n    return f'INR {v}'\n"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("app/orders.py", orders_py)
            zf.writestr("supabase/migrations/01.sql", schema_sql)
            zf.writestr("app/utils.py", utils_py)
        buf.seek(0)

        r_up = client.post(
            "/api/projects/upload-zip",
            files={"file": ("surgical-select.zip", buf.getvalue(), "application/zip")},
        )
        pid = r_up.json()["project"]["id"]
        r_prop = client.post(f"/api/projects/{pid}/propose-fixes")
        proposals = r_prop.json()["proposals"]

        sqli_prop = next(p for p in proposals if p["rule_id"] == "VA-TNT-001")
        # User chooses ONLY sqli_prop (unchecking RLS fix!)
        r_adopt = client.post(
            f"/api/projects/{pid}/adopt-fixes",
            json={"selected_finding_ids": [sqli_prop["finding_id"]]},
        )
        self.assertEqual(r_adopt.status_code, 200)
        ws_dir = Path(_PROJECT_META[pid]["workspace_path"])

        # 1. SQLi fixed AND clean_helper inside same file preserved byte-for-byte!
        updated_orders = (ws_dir / "app/orders.py").read_text(encoding="utf-8")
        self.assertIn(clean_helper, updated_orders)
        self.assertIn("?", updated_orders)
        # 2. Unchecked 01.sql and unrelated utils.py remain 100% untouched!
        self.assertEqual((ws_dir / "supabase/migrations/01.sql").read_text(encoding="utf-8"), schema_sql)
        self.assertEqual((ws_dir / "app/utils.py").read_text(encoding="utf-8"), utils_py)

        _PROJECT_META.pop(pid, None)
        _PROJECT_REPORTS.pop(pid, None)
        _STAGED_BUNDLES.pop(pid, None)
        shutil.rmtree(PROJECT_ROOT / "workspaces_store" / pid, ignore_errors=True)

    def test_16_multi_editor_vsix_package_and_readiness_protocol(self) -> None:
        client = TestClient(app)
        client.post("/api/demo/reset")

        # 1. Download real .vsix binary and validate manifest + bundle
        r_vsix = client.get("/api/extension/download-vsix")
        self.assertEqual(r_vsix.status_code, 200)
        with zipfile.ZipFile(io.BytesIO(r_vsix.content)) as zf:
            names = set(zf.namelist())
            self.assertIn("extension.vsixmanifest", names)
            self.assertIn("extension/package.json", names)
            self.assertIn("extension/bundle/extension.js", names)

        # 2. Editor verification BEFORE fixing -> BLOCKED
        r_v1 = client.post(
            "/api/extension/verify-readiness",
            json={"editor": "Cursor AI IDE", "project_id": "vibebazaar-india", "branch": "main"},
        )
        self.assertEqual(r_v1.status_code, 200)
        self.assertFalse(r_v1.json()["ready_to_push"])

        # 3. Heal & re-verify from editor -> READY TO PUSH & DEPLOY!
        client.post("/api/demo/heal")
        r_v2 = client.post(
            "/api/extension/verify-readiness",
            json={"editor": "Cursor AI IDE", "project_id": "vibebazaar-india", "branch": "main"},
        )
        self.assertEqual(r_v2.status_code, 200)
        self.assertTrue(r_v2.json()["ready_to_push"])
        self.assertTrue(r_v2.json()["ready_to_deploy"])

        r_st = client.get("/api/extension/status")
        self.assertEqual(r_st.status_code, 200)
        self.assertGreaterEqual(len(r_st.json()["recent_verifications"]), 2)

        client.post("/api/demo/reset")

    def test_17_multi_rpc_sql_migrations_and_workspace_delete(self) -> None:
        """Verify multiple parameterized PL/pgSQL SECURITY DEFINER RPCs in one file (Knot pattern) heal 100%."""
        client = TestClient(app)
        knot_style_sql = (
            "CREATE TABLE public.knot_events (id UUID PRIMARY KEY, organizer_id UUID);\n"
            "ALTER TABLE public.knot_events ENABLE ROW LEVEL SECURITY;\n"
            'CREATE POLICY "knot_events_owner" ON public.knot_events FOR ALL TO authenticated USING ((select auth.uid()) = organizer_id);\n\n'
            "CREATE OR REPLACE FUNCTION public.knot_is_admin()\n"
            "RETURNS boolean LANGUAGE sql SECURITY DEFINER AS $$\n"
            "  SELECT true;\n"
            "$$;\n\n"
            "CREATE OR REPLACE FUNCTION public.knot_can_manage_event(target_event uuid)\n"
            "RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
            "BEGIN\n"
            "  RETURN EXISTS(SELECT 1 FROM public.knot_events WHERE id = target_event);\n"
            "END;\n"
            "$$;\n"
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("supabase/migrations/001_knot_rpcs.sql", knot_style_sql)
        buf.seek(0)

        r_up = client.post(
            "/api/projects/upload-zip",
            files={"file": ("knot-rpc-test.zip", buf.getvalue(), "application/zip")},
        )
        self.assertEqual(r_up.status_code, 200)
        pid = r_up.json()["project"]["id"]
        self.assertEqual(r_up.json()["report"]["summary"]["actionable_before"], 2)

        r_prop = client.post(f"/api/projects/{pid}/propose-fixes")
        self.assertEqual(r_prop.status_code, 200)
        prop_json = r_prop.json()
        self.assertEqual(prop_json["adoptable_count"], 2)

        sel_ids = [p["finding_id"] for p in prop_json["proposals"] if p["adoptable"]]
        r_adopt = client.post(f"/api/projects/{pid}/adopt-fixes", json={"selected_finding_ids": sel_ids})
        self.assertEqual(r_adopt.status_code, 200)
        self.assertEqual(r_adopt.json()["report"]["summary"]["actionable_after"], 0)

        ws_dir = Path(_PROJECT_META[pid]["workspace_path"])
        patched_sql = (ws_dir / "supabase/migrations/001_knot_rpcs.sql").read_text(encoding="utf-8")
        self.assertIn("ALTER FUNCTION public.knot_is_admin() SET search_path = '';", patched_sql)
        self.assertIn("ALTER FUNCTION public.knot_can_manage_event(uuid) SET search_path = '';", patched_sql)

        r_del = client.delete(f"/api/projects/{pid}")
        self.assertEqual(r_del.status_code, 200)
        self.assertTrue(r_del.json()["deleted"])

    def test_18_two_way_editor_pairing_and_browser_extension_gate(self) -> None:
        """Verify live Two-Way Editor <-> Web Studio pairing sync + Chrome Manifest V3 Browser Extension."""
        client = TestClient(app)

        # 1. Verify Browser Extension (.zip) and Local Bridge (.py) downloads
        r_bzip = client.get("/api/extension/download-browser-zip")
        self.assertEqual(r_bzip.status_code, 200)
        with zipfile.ZipFile(io.BytesIO(r_bzip.content)) as zf:
            bnames = set(zf.namelist())
            self.assertIn("vibearmor-browser-guard/manifest.json", bnames)
            self.assertIn("vibearmor-browser-guard/content_guard.js", bnames)
            self.assertIn("vibearmor-browser-guard/icons/icon128.png", bnames)

        r_bridge = client.get("/api/extension/download-bridge")
        self.assertEqual(r_bridge.status_code, 200)
        self.assertIn("run_pre_push_gate", r_bridge.text)

        # 2. Create Pairing Token & sync a vulnerable local editor folder UP to VibeArmor
        r_pair = client.post(
            "/api/extension/pair/create",
            json={"editor": "Cursor", "workspace_name": "paired-checkout-app"},
        )
        self.assertEqual(r_pair.status_code, 200)
        token = r_pair.json()["pair_token"]
        self.assertTrue(token.startswith("va_pair_"))

        clean_readme = "# Paired Checkout App\nDo not touch this file.\n"
        vuln_py = (
            "import sqlite3\n"
            "def lookup_user(email: str):\n"
            "    conn = sqlite3.connect(':memory:')\n"
            "    return conn.execute(f\"SELECT * FROM users WHERE email = '{email}'\").fetchall()\n"
        )
        r_up = client.post(
            "/api/extension/pair/sync-up",
            json={
                "pair_token": token,
                "editor": "Cursor",
                "workspace_name": "paired-checkout-app",
                "local_path": "/tmp/paired-checkout-app",
                "branch": "main",
                "files": [
                    {"path": "README.md", "content": clean_readme},
                    {"path": "api/users.py", "content": vuln_py},
                ],
            },
        )
        self.assertEqual(r_up.status_code, 200)
        up_data = r_up.json()
        self.assertFalse(up_data["ready_to_push"])
        self.assertEqual(up_data["gate_verdict"], "BLOCKED")
        paired_pid = up_data["project_id"]

        # 3. Browser extension check against paired token reports BLOCKED
        r_brw1 = client.post(
            "/api/extension/browser/check-repo",
            json={"pair_token": token, "page_host": "vercel.com"},
        )
        self.assertEqual(r_brw1.status_code, 200)
        self.assertFalse(r_brw1.json()["ready_to_push"])

        # 4. User approves surgical fix in Web Studio -> queues ONLY api/users.py for editor write-back!
        r_prop = client.post(f"/api/projects/{paired_pid}/propose-fixes")
        sel_ids = [p["finding_id"] for p in r_prop.json()["proposals"] if p["adoptable"]]
        r_adopt = client.post(f"/api/projects/{paired_pid}/adopt-fixes", json={"selected_finding_ids": sel_ids})
        self.assertEqual(r_adopt.status_code, 200)

        r_pend = client.get(f"/api/extension/pair/{token}/pending-fixes")
        self.assertEqual(r_pend.status_code, 200)
        pending_files = r_pend.json()["pending_files"]
        self.assertIn("api/users.py", pending_files)
        self.assertNotIn("README.md", pending_files)  # Clean file strictly excluded from write-back!
        self.assertIn("?", pending_files["api/users.py"])

        r_ack = client.post(
            f"/api/extension/pair/{token}/ack-fixes",
            json={"applied_files": list(pending_files.keys())},
        )
        self.assertEqual(r_ack.status_code, 200)

        # 5. Browser extension check now reports READY TO PUSH & DEPLOY!
        r_brw2 = client.post(
            "/api/extension/browser/check-repo",
            json={"pair_token": token, "page_host": "vercel.com"},
        )
        self.assertTrue(r_brw2.json()["ready_to_push"])

        # Cleanup test pairing & workspace
        client.delete(f"/api/projects/{paired_pid}")

    def test_19_python_future_annotations_and_multiline_fastapi_healing(self) -> None:
        """Verify files with `from __future__ import annotations`, multi-line FastAPI routes, and `?` join placeholders heal cleanly."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "api.py").write_text(
                '"""RAG API module."""\n'
                "from __future__ import annotations\n\n"
                "from fastapi import (\n"
                "    BackgroundTasks,\n"
                "    FastAPI,\n"
                ")\n"
                "import requests\n\n"
                "app = FastAPI()\n\n"
                '@app.post("/ingest")\n'
                "def ingest_source(\n"
                "    source_url: str,\n"
                "    bg: BackgroundTasks,\n"
                ") -> dict:\n"
                "    resp = requests.post(source_url, timeout=5)\n"
                "    return {'status': resp.status_code}\n",
                encoding="utf-8",
            )
            (root / "store.py").write_text(
                "from __future__ import annotations\n"
                "import sqlite3\n\n"
                "def get_items(conn: sqlite3.Connection, ids: list[str]) -> list:\n"
                "    return conn.execute(\n"
                '        "SELECT id FROM items WHERE id IN "\n'
                "        f\"({','.join('?' * len(ids))})\",\n"
                "        ids,\n"
                "    ).fetchall()\n",
                encoding="utf-8",
            )
            rep = scan_and_heal(root, auto_heal=True)
            self.assertEqual(rep.summary["broken_builds"], 0)
            self.assertEqual(rep.summary["actionable_after"], 0)
            # Safe parameterized IN (?,?,?) in store.py must NOT be modified at all!
            self.assertNotIn("_va_", (root / "store.py").read_text(encoding="utf-8"))
            # api.py must compile cleanly with `from __future__ import annotations` preserved before other imports
            compile((root / "api.py").read_text(encoding="utf-8"), "api.py", "exec")

    def test_20_github_403_token_verifier_and_contents_api_fallback(self) -> None:
        """Verify GitHub Fine-Grained PAT read-only detection AND Contents API + Compare-PR fallback on 403."""
        from unittest.mock import patch
        import httpx as _httpx
        from core.github_sync import (
            build_local_git_push_script,
            push_surgical_fixes_to_github,
            verify_github_token_access,
        )

        # Scenario A: Owner's token on a PUBLIC repo where GitHub STILL reports `permissions.push=True`,
        # while actual write probe (`POST /git/refs`) returns 403!
        def _readonly_public_owner_handler(request: _httpx.Request) -> _httpx.Response:
            if request.url.path == "/user":
                return _httpx.Response(200, json={"login": "suhail-m01"})
            if request.url.path == "/repos/suhail-m01/NeXGen-Coders-RAG" and request.method == "GET":
                return _httpx.Response(
                    200,
                    json={"default_branch": "main", "private": False, "permissions": {"admin": True, "push": True, "pull": True}},
                )
            if request.url.path == "/repos/suhail-m01/NeXGen-Coders-RAG/git/ref/heads/main":
                return _httpx.Response(200, json={"object": {"sha": "basecommit123456"}})
            if request.url.path == "/repos/suhail-m01/NeXGen-Coders-RAG/git/commits/basecommit123456":
                return _httpx.Response(200, json={"tree": {"sha": "basetree123456"}})
            return _httpx.Response(
                403,
                headers={"X-Accepted-GitHub-Permissions": "contents=write"},
                json={"message": "Resource not accessible by personal access token"},
            )

        orig_client = _httpx.Client
        with patch(
            "core.github_sync.httpx.Client",
            side_effect=lambda **kw: orig_client(transport=_httpx.MockTransport(_readonly_public_owner_handler), base_url=kw["base_url"], headers=kw["headers"]),
        ), patch("core.github_sync._push_via_native_git_https", return_value=(False, "403 Forbidden")):
            v = verify_github_token_access("https://github.com/suhail-m01/NeXGen-Coders-RAG", "github_pat_testreadonly123")
            self.assertFalse(v["ok"])
            self.assertEqual(v["status"], "read_only_token")
            self.assertIn("READ-ONLY", v["message"])
            self.assertIn("contents=write", v["message"])

            with self.assertRaises(ValueError) as ctx_err:
                push_surgical_fixes_to_github(
                    repo_url="https://github.com/suhail-m01/NeXGen-Coders-RAG",
                    github_token="github_pat_testreadonly123",
                    changed_files={"api.py": "print('fixed')\n", ".env.local": "SECRET=123\n"},
                    mode="pull_request",
                )
            self.assertIn("lacks write permission", str(ctx_err.exception))

        # Scenario A2: Zero-PAT Self-Contained Local Git Push Script compiles cleanly & excludes `.env.local`
        script_src = build_local_git_push_script(
            repo_url="https://github.com/suhail-m01/NeXGen-Coders-RAG",
            changed_files={"api.py": "print('fixed')\n", ".env.local": "SECRET=123\n"},
        )
        compile(script_src, "push_vibearmor_fixes.py", "exec")
        self.assertIn("suhail-m01/NeXGen-Coders-RAG", script_src)
        self.assertNotIn("SECRET=123", script_src)

        # Scenario B: Token has Contents:write, `/git/trees` returns 403 -> falls back to Contents API, and `/pulls` 403 -> returns Compare PR URL!
        def _contents_fallback_handler(request: _httpx.Request) -> _httpx.Response:
            p = request.url.path
            m = request.method
            if p == "/user":
                return _httpx.Response(200, json={"login": "suhail-m01"})
            if p == "/repos/suhail-m01/NeXGen-Coders-RAG" and m == "GET":
                return _httpx.Response(
                    200,
                    json={"default_branch": "main", "permissions": {"admin": False, "push": True, "pull": True}},
                )
            if p == "/repos/suhail-m01/NeXGen-Coders-RAG/git/ref/heads/main":
                return _httpx.Response(200, json={"object": {"sha": "basecommit123456"}})
            if p == "/repos/suhail-m01/NeXGen-Coders-RAG/git/commits/basecommit123456":
                return _httpx.Response(200, json={"tree": {"sha": "basetree123456"}})
            if p == "/repos/suhail-m01/NeXGen-Coders-RAG/git/trees" and m == "POST":
                return _httpx.Response(403, json={"message": "Resource not accessible by personal access token"})
            if p == "/repos/suhail-m01/NeXGen-Coders-RAG/git/refs" and m == "POST":
                return _httpx.Response(201, json={"ref": "refs/heads/vibearmor/security-fixes"})
            if p == "/repos/suhail-m01/NeXGen-Coders-RAG/contents/api.py" and m == "GET":
                return _httpx.Response(200, json={"sha": "oldblobsha999"})
            if p == "/repos/suhail-m01/NeXGen-Coders-RAG/contents/api.py" and m == "PUT":
                return _httpx.Response(200, json={"commit": {"sha": "newcommit789012345"}})
            if p == "/repos/suhail-m01/NeXGen-Coders-RAG/pulls" and m == "POST":
                return _httpx.Response(403, json={"message": "Resource not accessible by personal access token"})
            return _httpx.Response(404, json={"message": f"Unhandled {m} {p}"})

        with patch(
            "core.github_sync.httpx.Client",
            side_effect=lambda **kw: orig_client(transport=_httpx.MockTransport(_contents_fallback_handler), base_url=kw["base_url"], headers=kw["headers"]),
        ):
            res = push_surgical_fixes_to_github(
                repo_url="https://github.com/suhail-m01/NeXGen-Coders-RAG",
                github_token="github_pat_contentswrite123",
                changed_files={"api.py": "print('fixed')\n", ".env.local": "SECRET=123\n"},
                mode="pull_request",
            )
            self.assertEqual(res["commit_sha"], "newcommit789012345")
            self.assertTrue(res["compare_only"])
            self.assertIn("/compare/main...", res["pr_url"])
            self.assertEqual(res["files_pushed"], ["api.py"])
            self.assertEqual(res["secret_files_excluded"], [".env.local"])

    def test_21_fine_grained_pat_schema_valid_probe_catches_readonly_vs_write(self) -> None:
        """Exact regression test for image-7: GitHub returns 422 on empty json={} BEFORE checking Fine-Grained PAT scopes!"""
        from unittest.mock import patch
        import httpx as _httpx
        from core.github_sync import verify_github_token_access

        def _make_real_github_schema_first_handler(has_write_scope: bool):
            def _handler(request: _httpx.Request) -> _httpx.Response:
                p = request.url.path
                m = request.method
                if p == "/user":
                    return _httpx.Response(200, json={"login": "suhail-m01"})
                if p == "/repos/suhail-m01/NeXGen-Coders-RAG" and m == "GET":
                    return _httpx.Response(
                        200,
                        json={"default_branch": "main", "private": False, "permissions": {"admin": True, "push": True, "pull": True}},
                    )
                if p == "/repos/suhail-m01/NeXGen-Coders-RAG/git/ref/heads/main" and m == "GET":
                    return _httpx.Response(200, json={"object": {"sha": "a090b2b122dc1120b07814e2af203f91434d586b"}})
                if p == "/repos/suhail-m01/NeXGen-Coders-RAG/git/refs" and m == "POST":
                    body = json.loads(request.content.decode("utf-8") or "{}")
                    # Real GitHub validates schema BEFORE Fine-Grained PAT write authz!
                    if not body.get("ref") or not body.get("sha"):
                        return _httpx.Response(422, json={"message": "Invalid request.\n\n\"ref\", \"sha\" wasn't supplied."})
                    if not has_write_scope:
                        return _httpx.Response(
                            403,
                            headers={"X-Accepted-GitHub-Permissions": "contents=write"},
                            json={"message": "Resource not accessible by personal access token"},
                        )
                    return _httpx.Response(422, json={"message": "Reference already exists"})
                return _httpx.Response(404, json={"message": f"Unhandled {m} {p}"})
            return _handler

        orig_client = _httpx.Client
        # Read-only Fine-Grained PAT MUST return ok=False (never false-positive Verified!)
        with patch(
            "core.github_sync.httpx.Client",
            side_effect=lambda **kw: orig_client(
                transport=_httpx.MockTransport(_make_real_github_schema_first_handler(False)),
                base_url=kw["base_url"],
                headers=kw["headers"],
            ),
        ):
            v_ro = verify_github_token_access("https://github.com/suhail-m01/NeXGen-Coders-RAG", "github_pat_readonly93chars")
            self.assertFalse(v_ro["ok"])
            self.assertEqual(v_ro["status"], "read_only_token")

        # Write-capable Fine-Grained PAT gets 422 "Reference already exists" on existing ref -> ok=True, zero mutation!
        with patch(
            "core.github_sync.httpx.Client",
            side_effect=lambda **kw: orig_client(
                transport=_httpx.MockTransport(_make_real_github_schema_first_handler(True)),
                base_url=kw["base_url"],
                headers=kw["headers"],
            ),
        ):
            v_rw = verify_github_token_access("https://github.com/suhail-m01/NeXGen-Coders-RAG", "github_pat_readwrite93chars")
            self.assertTrue(v_rw["ok"])
            self.assertIn(v_rw["status"], {"ready", "ready_direct"})

    def test_22_extension_and_project_export_staging_api(self) -> None:
        """Verify all 7 downloadable artifacts stage cleanly to /home/user/exports/ and return valid payloads."""
        client = TestClient(app)

        for ext_kind in ("vsix", "browser_zip", "bridge_py"):
            r = client.post("/api/exports/stage", json={"artifact_kind": ext_kind})
            self.assertEqual(r.status_code, 200, r.text)
            d = r.json()
            self.assertGreater(d["size_bytes"], 500)
            staged_file = Path("/home/user") / d["saved_workspace_path"]
            self.assertTrue(staged_file.exists(), f"Missing {staged_file}")
            # Verify raw GET download endpoint also returns 200 with exact bytes
            r_dl = client.get(d["download_path"])
            self.assertEqual(r_dl.status_code, 200)
            self.assertEqual(len(r_dl.content), d["size_bytes"])

        # Heal vibebazaar-india, stage project_zip, project_patch, project_cert, github_push_script, then reset
        client.post("/api/projects/vibebazaar-india/heal")
        for proj_kind in ("project_zip", "project_patch", "project_cert", "github_push_script"):
            r_p = client.post(
                "/api/exports/stage",
                json={
                    "artifact_kind": proj_kind,
                    "project_id": "vibebazaar-india",
                    "repo_url": "https://github.com/suhail-m01/NeXGen-Coders-RAG",
                },
            )
            self.assertEqual(r_p.status_code, 200, r_p.text)
            dp = r_p.json()
            self.assertGreater(dp["size_bytes"], 100)
            self.assertTrue((Path("/home/user") / dp["saved_workspace_path"]).exists())
        client.post("/api/projects/vibebazaar-india/reset")

    def test_23_workspace_live_exploit_and_supabase_sql_audit_endpoints(self) -> None:
        """Verify custom workspaces support Live Exploit Lab probes and Supabase SQL Schema Audit."""
        client = TestClient(app)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "backend/api.py",
                "import requests\ndef run_fetch(url: str):\n    return requests.get(url).text\n",
            )
            zf.writestr(
                "supabase/migrations/01.sql",
                "CREATE TABLE public.customer_profiles (id UUID PRIMARY KEY, user_id UUID, email TEXT, phone TEXT);\n",
            )
        buf.seek(0)
        r_up = client.post(
            "/api/projects/upload-zip",
            files={"file": ("custom-ws.zip", buf.getvalue(), "application/zip")},
        )
        self.assertEqual(r_up.status_code, 200)
        up_json = r_up.json()
        pid = up_json["project"]["id"]
        # Breach simulation MUST be populated on non-vibebazaar workspaces!
        self.assertIsNotNone(up_json["breach"])
        self.assertEqual(up_json["breach"]["total_attacks"], 4)
        self.assertFalse(up_json["breach"]["all_blocked"])

        # Custom exploit probe endpoint on custom workspace
        r_exp = client.post(f"/api/projects/{pid}/exploit", json={"sqli_payload": "' OR '1'='1"})
        self.assertEqual(r_exp.status_code, 200)
        self.assertEqual(r_exp.json()["total_attacks"], 4)

        # Workspace Supabase SQL Schema Audit endpoint
        r_sql = client.post(f"/api/projects/{pid}/supabase-sql-audit")
        self.assertEqual(r_sql.status_code, 200)
        sql_data = r_sql.json()
        self.assertEqual(sql_data["tables_discovered"], 1)
        self.assertEqual(sql_data["tables"][0]["risk"], "CRITICAL_NO_RLS")

        # Heal custom workspace -> all 4 attacks blocked & SQL table now SAFE!
        client.post(f"/api/projects/{pid}/heal")
        r_exp_after = client.post(f"/api/projects/{pid}/exploit", json={})
        self.assertEqual(r_exp_after.status_code, 200)
        self.assertTrue(r_exp_after.json()["all_blocked"])

        r_sql_after = client.post(f"/api/projects/{pid}/supabase-sql-audit")
        self.assertEqual(r_sql_after.status_code, 200)
        self.assertEqual(r_sql_after.json()["tables"][0]["risk"], "SAFE")

        _PROJECT_META.pop(pid, None)
        _PROJECT_REPORTS.pop(pid, None)
        shutil.rmtree(PROJECT_ROOT / "workspaces_store" / pid, ignore_errors=True)

    def test_24_restart_resilient_unified_diff_patch_export(self) -> None:
        """Verify GET /export/patch computes a clean unified diff even after report.patches is cleared."""
        client = TestClient(app)
        client.post("/api/projects/vibebazaar-india/heal")
        # Simulate process restart clearing cached in-memory PatchReport list
        _PROJECT_REPORTS.pop("vibebazaar-india", None)
        r_patch = client.get("/api/projects/vibebazaar-india/export/patch")
        self.assertEqual(r_patch.status_code, 200)
        self.assertIn("--- a/", r_patch.text)
        self.assertIn("+++ b/", r_patch.text)
        self.assertNotIn(".env.local", r_patch.text)
        client.post("/api/projects/vibebazaar-india/reset")

    def test_25_secret_masking_never_leaks_raw_credentials(self) -> None:
        """Verify secrets, PATs, JWTs, and DB URLs are deterministically masked in UI/evidence outputs."""
        from core.security_masking import mask_secrets, mask_token_preview

        raw = (
            'STRIPE="' + ('sk_' + 'live_9876543210abcdef123456') + '" '
            'GH="' + ('github_' + 'pat_11ABCDEFG0123456789_secretTokenValueXYZ') + '" '
            'DB="postgresql://admin:SuperSecretPass99@db.example.com:5432/prod"'
        )
        masked = mask_secrets(raw)
        self.assertNotIn("9876543210abcdef123456", masked)
        self.assertNotIn("secretTokenValueXYZ", masked)
        self.assertNotIn("SuperSecretPass99", masked)
        self.assertIn("sk_live_", masked)
        self.assertNotIn("secret", mask_token_preview("gh" + "p_1234567890secretvalue9999"))

    def test_26_faiss_security_rag_and_evidence_package(self) -> None:
        """Verify real FAISS IndexFlatIP retrieval and grounded SecurityEvidencePackage construction."""
        from core.rag.security_rag import build_security_evidence_package, get_security_rag_index
        from core.engine import scan_and_heal
        from core.graph.cross_layer_graph import build_workspace_context
        from core.slicer.mss_slicer import extract_mss

        rag = get_security_rag_index()
        hits = rag.retrieve("SQL injection parameterized query cursor execute", cwe_hint="CWE-89", top_k=3)
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0].cwe, "CWE-89")
        self.assertGreater(hits[0].similarity_score, 0.25)

        tpl = PROJECT_ROOT / "vibebazaar-demo" / "template_vulnerable"
        ctx = build_workspace_context(tpl)
        report = scan_and_heal(tpl, auto_heal=False)
        self.assertGreater(len(report.findings_before), 0)
        f0 = report.findings_before[0]
        mss0 = extract_mss(f0, ctx)
        pkg = build_security_evidence_package(f0, mss0)
        self.assertTrue(pkg.cwe.startswith("CWE-"))
        self.assertGreaterEqual(len(pkg.retrieved_security_evidence), 1)
        self.assertIn("faiss", pkg.rag_backend.lower())

    def test_27_langgraph_4_agent_workflow_and_no_ai_self_certification(self) -> None:
        """Verify LangGraph 4-agent workflow runs end-to-end and NEVER converts ERROR/FAIL into VERIFIED."""
        from core.agents.langgraph_workflow import (
            _deterministic_decision,
            run_agentic_security_workflow_on_workspace,
        )

        # Invariant 1: ERROR or FAIL must NEVER become VERIFIED
        self.assertEqual(_deterministic_decision(False, True, "ERROR", "PASS", "PASS"), "REJECTED")
        self.assertEqual(_deterministic_decision(False, True, "PASS", "FAIL", "PASS"), "REJECTED")
        self.assertEqual(_deterministic_decision(False, True, "PASS", "PASS", "NOT_APPLICABLE"), "VERIFIED")
        self.assertEqual(_deterministic_decision(True, False, "NOT_APPLICABLE", "NOT_APPLICABLE", "NOT_APPLICABLE"), "ABSTAINED_POLICY_SPEC")

        # Invariant 2: Full LangGraph StateGraph run on isolated vulnerable workspace
        with tempfile.TemporaryDirectory(prefix="va_lg_test_") as tmp:
            ws = Path(tmp)
            (ws / "api.py").write_text(
                "import sqlite3\ndef get_user(uid: str):\n    conn = sqlite3.connect(':memory:')\n    return conn.execute(f\"SELECT * FROM users WHERE id = '{uid}'\").fetchall()\n",
                encoding="utf-8",
            )
            res = run_agentic_security_workflow_on_workspace(ws)
            self.assertEqual(res["orchestrator"], "langgraph_state_graph")
            self.assertEqual(res["findings_processed"], 1)
            self.assertEqual(res["verified_count"], 1)
            item = res["runs"][0]
            self.assertEqual(item["final_status"], "VERIFIED")
            self.assertGreaterEqual(len(item["agent_trace"]), 4)

    def test_28_deterministic_security_policy_engine_and_api(self) -> None:
        """Verify security_policy.yaml blocks vulnerable workspaces and passes verified workspaces."""
        client = TestClient(app)
        client.post("/api/projects/vibebazaar-india/reset")

        r_pol = client.get("/api/policy")
        self.assertEqual(r_pol.status_code, 200)
        self.assertTrue(r_pol.json()["security"]["block_critical"])
        self.assertFalse(r_pol.json()["security"]["allow_unverified_ai_patch"])

        r_ev_before = client.get("/api/projects/vibebazaar-india/evidence")
        self.assertEqual(r_ev_before.status_code, 200)
        self.assertEqual(r_ev_before.json()["policy_evaluation"]["verdict"], "BLOCK")

        client.post("/api/projects/vibebazaar-india/heal")
        r_ev_after = client.get("/api/projects/vibebazaar-india/evidence")
        self.assertEqual(r_ev_after.status_code, 200)
        self.assertEqual(r_ev_after.json()["policy_evaluation"]["verdict"], "PASS")
        client.post("/api/projects/vibebazaar-india/reset")

    def test_29_evidence_bundle_and_12_node_evidence_graph_api(self) -> None:
        """Verify Evidence Graph nodes, RAG search API, and live LangGraph run API."""
        client = TestClient(app)
        r_ev = client.get("/api/projects/vibebazaar-india/evidence")
        self.assertEqual(r_ev.status_code, 200)
        data = r_ev.json()
        self.assertGreater(len(data["items"]), 0)
        first = data["items"][0]
        self.assertEqual(len(first["evidence_graph"]["nodes"]), 12)
        self.assertTrue(first["evidence_graph"]["why_vulnerable"])
        self.assertTrue(first["evidence_graph"]["why_verified"])

        r_rag = client.post("/api/rag/search", json={"query": "Supabase row level security policy", "top_k": 2})
        self.assertEqual(r_rag.status_code, 200)
        self.assertEqual(len(r_rag.json()["results"]), 2)

    def test_30_offline_powershell_5_1_and_bash_extension_installers(self) -> None:
        """Verify extension stage commands have ZERO '&&', ZERO 'Invoke-WebRequest', ZERO 'sbx-' URLs, and valid Base64."""
        import base64 as _b64
        import re as _re

        client = TestClient(app)
        for kind in ("vsix", "browser_zip", "bridge_py"):
            res = client.post("/api/exports/stage", json={"artifact_kind": kind})
            self.assertEqual(res.status_code, 200)
            body = res.json()
            ps = body["offline_powershell_cmd"]
            sh = body["offline_bash_cmd"]
            self.assertTrue(ps and sh)
            # Windows PowerShell 5.1 safety invariants (fixes image-9 & image-10!)
            self.assertNotIn("&&", ps)
            self.assertNotIn("Invoke-WebRequest", ps)
            self.assertNotIn("sbx-", ps)
            self.assertNotIn("sbx-", sh)
            if kind in ("vsix", "browser_zip"):
                self.assertIn("Downloads", ps)
                m = _re.search(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", ps)
                self.assertIsNotNone(m)
                raw = _b64.b64decode(m.group(1))
                with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                    self.assertGreater(len(zf.namelist()), 2)

    def test_31_vscode_vsix_v35_bundle_and_browser_mv3_pure_js(self) -> None:
        """Verify compiled VSIX bundle includes v3.5 offline scanner & exact-range quick fixes, and MV3 JS has zero TS syntax."""
        import subprocess as _sp

        vsix_path = PROJECT_ROOT / "ide-extension" / "vibearmor-guard-3.0.0.vsix"
        with zipfile.ZipFile(vsix_path) as zf:
            ext_js = zf.read("extension/bundle/extension.js").decode("utf-8")
            # Must NEVER contain naive 10000-line full-document range replacement
            self.assertNotIn("10000", ext_js)
            self.assertIn("registerCodeActionsProvider", ext_js)

        for js_file in ("popup.js", "background.js", "content_guard.js"):
            p = PROJECT_ROOT / "browser-extension" / js_file
            chk = _sp.run(["node", "--check", str(p)], capture_output=True, text=True)
            self.assertEqual(chk.returncode, 0, msg=chk.stderr)

    def test_32_git_staged_only_pre_commit_guard(self) -> None:
        """Verify `vibearmor guard --staged` scans ONLY staged Git index files and ignores unstaged WIP files."""
        import subprocess as _sp
        from core.interfaces.cli import main as cli_main

        with tempfile.TemporaryDirectory(prefix="va_git_staged_") as tmp:
            repo = Path(tmp)
            _sp.run(["git", "init"], cwd=repo, check=True, capture_output=True)
            _sp.run(["git", "config", "user.email", "dev@example.com"], cwd=repo, check=True)
            _sp.run(["git", "config", "user.name", "Dev"], cwd=repo, check=True)

            # 1. Stage a CLEAN file while an UNSTAGED vulnerable file sits in working tree
            (repo / "clean.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
            (repo / "wip_unstaged.py").write_text(
                "import sqlite3\ndef bad(u: str):\n    return sqlite3.connect(':memory:').execute(f\"SELECT * FROM t WHERE u='{u}'\")\n",
                encoding="utf-8",
            )
            _sp.run(["git", "add", "clean.py"], cwd=repo, check=True)
            rc_clean_staged = cli_main(["guard", str(repo), "--staged"])
            self.assertEqual(rc_clean_staged, 0)

            # 2. Now stage the vulnerable file -> pre-commit guard MUST block (exit code 1)!
            _sp.run(["git", "add", "wip_unstaged.py"], cwd=repo, check=True)
            rc_vuln_staged = cli_main(["guard", str(repo), "--staged"])
            self.assertEqual(rc_vuln_staged, 1)

    def test_33_github_push_module_offline_patch_and_config(self) -> None:
        """Verify Step 4 offline surgical Git push command decompresses & applies cleanly via `git apply --check`."""
        import base64 as _b64
        import gzip as _gzip
        import re as _re
        import subprocess as _sp

        client = TestClient(app)
        client.post("/api/projects/vibebazaar-india/heal")

        r_off = client.post(
            "/api/projects/vibebazaar-india/offline-git-push",
            json={"repo_url": "https://github.com/suhail-m01/NeXGen-Coders-RAG", "mode": "pull_request"},
        )
        self.assertEqual(r_off.status_code, 200)
        d = r_off.json()
        self.assertNotIn("&&", d["powershell_cmd"])
        self.assertNotIn("Invoke-WebRequest", d["powershell_cmd"])
        self.assertNotIn("sbx-", d["powershell_cmd"])

        m = _re.search(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", d["powershell_cmd"])
        self.assertIsNotNone(m)
        patch_bytes = _gzip.decompress(_b64.b64decode(m.group(1)))

        with tempfile.TemporaryDirectory(prefix="va_patch_apply_") as tmp:
            shutil.copytree(PROJECT_ROOT / "vibebazaar-demo" / "template_vulnerable", Path(tmp) / "repo")
            repo_dir = Path(tmp) / "repo"
            _sp.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
            patch_file = Path(tmp) / "surgical.patch"
            patch_file.write_bytes(patch_bytes)
            chk = _sp.run(
                ["git", "apply", "--check", "--whitespace=nowarn", str(patch_file)],
                cwd=repo_dir,
                capture_output=True,
                text=True,
            )
            self.assertEqual(chk.returncode, 0, msg=chk.stderr)

        client.post("/api/projects/vibebazaar-india/reset")

    def test_34_mcp_controlled_security_tools(self) -> None:
        """Verify MCP controlled security research, AST, slice, and evidence tools."""
        from core.interfaces.mcp_server import (
            get_ast,
            get_evidence,
            get_security_slice,
            search_security_knowledge,
        )

        demo_tpl = str(PROJECT_ROOT / "vibebazaar-demo" / "template_vulnerable")
        rag_res = json.loads(search_security_knowledge("SSRF internal metadata", cwe_hint="CWE-918"))
        self.assertGreaterEqual(len(rag_res["results"]), 1)

        ast_res = json.loads(get_ast(demo_tpl))
        self.assertGreater(ast_res["node_count"], 3)

        slice_res = json.loads(get_security_slice(demo_tpl))
        self.assertGreater(slice_res["slice_count"], 0)

        ev_res = json.loads(get_evidence(demo_tpl))
        self.assertGreater(len(ev_res["items"]), 0)

    def test_35_vscode_v36_git_auto_init_and_safe_push_helpers(self) -> None:
        """Verify VS Code VSIX v3.6 handles uninitialized/broken .git folders, .venv/.env gitignore shield, and URL normalization."""
        import subprocess as _sp

        vsix_path = PROJECT_ROOT / "ide-extension" / "vibearmor-guard-3.0.0.vsix"
        with zipfile.ZipFile(vsix_path) as zf:
            pkg_meta = json.loads(zf.read("extension/package.json").decode("utf-8"))
            self.assertEqual(pkg_meta["version"], "3.6.0")
            ext_js = zf.read("extension/bundle/extension.js").decode("utf-8")
            self.assertIn("isValidGitWorktree", ext_js)
            self.assertIn("ensureSafeGitignore", ext_js)
            self.assertIn("Initialize Git & Connect GitHub", ext_js)
            self.assertIn("vibearmor.configureGitRemote", ext_js)

        node_script = (
            'const fs=require("fs"),os=require("os"),path=require("path"),cp=require("child_process"),Module=require("module");'
            'const o=Module.prototype.require;Module.prototype.require=function(i){return i==="vscode"?{env:{appName:"VS Code"}}:o.apply(this,arguments);};'
            f'const ext=require("{PROJECT_ROOT.as_posix()}/ide-extension/bundle/extension.js");'
            'if(ext.normalizeGitHubRemoteUrl("suhail-m01/Repo")!=="https://github.com/suhail-m01/Repo.git")process.exit(1);'
            'const t=fs.mkdtempSync(path.join(os.tmpdir(),"va_t35_"));'
            'fs.mkdirSync(path.join(t,".git","hooks"),{recursive:true});'
            'if(ext.isValidGitWorktree(t)!==false)process.exit(2);'
            'ext.ensureSafeGitignore(t);'
            'cp.execFileSync("git",["init","-b","main"],{cwd:t});'
            'if(ext.isValidGitWorktree(t)!==true)process.exit(3);'
            'fs.rmSync(t,{recursive:true,force:true});'
        )
        res = _sp.run(["node", "-e", node_script], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, msg=res.stderr)

    def test_36_fullstack_npm_dev_launcher_and_vscode_configs(self) -> None:
        """Verify full-stack `npm run dev` launcher (`dev_fullstack.mjs`), VS Code launch/tasks configs, and Windows scripts."""
        import subprocess as _sp

        launcher = PROJECT_ROOT / "studio" / "scripts" / "dev_fullstack.mjs"
        self.assertTrue(launcher.exists())
        chk = _sp.run(["node", "--check", str(launcher)], capture_output=True, text=True)
        self.assertEqual(chk.returncode, 0, msg=chk.stderr)

        studio_pkg = json.loads((PROJECT_ROOT / "studio" / "package.json").read_text(encoding="utf-8"))
        self.assertIn("dev_fullstack.mjs", studio_pkg["scripts"]["dev"])

        root_pkg = json.loads((PROJECT_ROOT / "package.json").read_text(encoding="utf-8"))
        self.assertIn("dev_fullstack.mjs", root_pkg["scripts"]["dev"])

        self.assertTrue((PROJECT_ROOT / ".vscode" / "launch.json").exists())
        self.assertTrue((PROJECT_ROOT / ".vscode" / "tasks.json").exists())
        self.assertTrue((PROJECT_ROOT / "start_studio.ps1").exists())
        self.assertTrue((PROJECT_ROOT / "start_studio.bat").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
