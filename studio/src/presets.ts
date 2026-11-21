export interface SandboxPreset {
  id: string;
  label: string;
  badge: string;
  description: string;
  files: Array<{ path: string; content: string }>;
}

export const SANDBOX_PRESETS: SandboxPreset[] = [
  {
    id: "rls_vacuous_dpdp",
    label: "1. Fake RLS USING(true) + DPDP PII",
    badge: "CVE-2025-48757",
    description: "Lovable/Bolt style cosmetic RLS that exposes Indian customer PAN & phone records to anon PostgREST.",
    files: [
      {
        path: "supabase/migrations/001_kyc.sql",
        content: `CREATE TABLE public.customer_kyc (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    full_name TEXT NOT NULL,
    phone TEXT NOT NULL,
    pan_number TEXT NOT NULL
);

ALTER TABLE public.customer_kyc ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all access"
    ON public.customer_kyc
    FOR ALL
    USING (true);`,
      },
      {
        path: "src/ProfileCard.tsx",
        content: `import { supabase } from "./sb";
export const loadKyc = () => supabase.from("customer_kyc").select("*");`,
      },
    ],
  },
  {
    id: "client_key_autobff",
    label: "2. Client OpenAI Secret -> Zero-Trust Auto-BFF",
    badge: "Auto-BFF Proxy",
    description: "Extracts leaked sk-proj-... key to .env.local and synthesizes an authenticated, rate-limited Next.js BFF route.",
    files: [
      {
        path: "src/components/Concierge.tsx",
        content: `"use client";
const OPENAI_KEY = "sk-proj-JudgeLiveSandboxKeyTest998877665544332211";

export async function generateSummary(prompt: string) {
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: \`Bearer \${OPENAI_KEY}\`
    },
    body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: prompt }] })
  });
  return res.json();
}`,
      },
    ],
  },
  {
    id: "razorpay_and_sqli",
    label: "3. Razorpay ₹0 Fake Order + Python SQLi",
    badge: "India Fintech",
    description: "Fixes unverified Razorpay payment confirmation with constant-time HMAC-SHA256 and parameterizes SQLi.",
    files: [
      {
        path: "backend/payment_routes.py",
        content: `import sqlite3
from fastapi import FastAPI, Request

app = FastAPI()

@app.get("/invoices")
def get_invoice(invoice_no: str):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(f"SELECT id, amount_inr FROM invoices WHERE invoice_no = '{invoice_no}'")
    return {"rows": cur.fetchall()}

@app.post("/razorpay/callback")
async def confirm_razorpay(request: Request):
    payload = await request.json()
    order_id = payload.get("razorpay_order_id", "")
    payment_id = payload.get("razorpay_payment_id", "")
    if payment_id:
        return {"order_id": order_id, "status": "PAID"}
    return {"status": "FAILED"}`,
      },
    ],
  },
  {
    id: "slm_fk_join_rls",
    label: "4. Child FK Table RLS (Local Qwen SLM)",
    badge: "Tier-2 Local SLM",
    description: "Table has no user_id column — Local Qwen2.5-Coder GGUF synthesizes EXISTS(...) join policy via orders(id)!",
    files: [
      {
        path: "supabase/migrations/002_shipments.sql",
        content: `CREATE TABLE public.orders (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL
);
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY "orders_owner" ON public.orders FOR ALL TO authenticated USING ((select auth.uid()) = user_id);

CREATE TABLE public.shipment_tracking (
    id UUID PRIMARY KEY,
    order_id UUID NOT NULL REFERENCES public.orders(id),
    courier_awb TEXT NOT NULL
);`,
      },
    ],
  },
  {
    id: "slopsquat_and_cve",
    label: "5. AI Hallucinated Package + Typosquat",
    badge: "Supply Chain",
    description: "Quarantines AI-hallucinated npm package before postinstall runs and swaps typosquatted 'axois' -> 'axios'.",
    files: [
      {
        path: "package.json",
        content: JSON.stringify(
          {
            name: "vibe-checkout",
            dependencies: {
              axois: "^1.7.0",
              "react-razorpay-secure-v2": "^1.0.0",
            },
          },
          null,
          2
        ),
      },
    ],
  },
  {
    id: "hard_negative_catalog",
    label: "6. Hard Negative: Public Catalog (0 FP!)",
    badge: "False-Positive Test",
    description: "Read-only public products catalog with FOR SELECT USING (true) — VibeArmor stays 100% silent (<20ms)!",
    files: [
      {
        path: "supabase/migrations/001_catalog.sql",
        content: `CREATE TABLE public.products (
    id UUID PRIMARY KEY,
    title TEXT NOT NULL,
    price_inr INT NOT NULL
);
ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;
CREATE POLICY "public_catalog_read" ON public.products FOR SELECT USING (true);`,
      },
    ],
  },
  {
    id: "abstain_multitenant",
    label: "7. Boundary: Multi-Tenant Policy Abstention",
    badge: "Honest Abstention",
    description: "Custom org_id + required_role + INR limit matrix triggers NEEDS_POLICY_SPEC instead of guessing broken SQL.",
    files: [
      {
        path: "supabase/migrations/003_b2b_approvals.sql",
        content: `-- POLICY_SPEC: Finance managers approve <= 50,000 INR; CFO role required above 50,000 INR per org_id
CREATE TABLE public.payout_approvals (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    required_role TEXT NOT NULL,
    approval_limit_inr INT NOT NULL,
    payout_inr INT NOT NULL
);`,
      },
    ],
  },
];
