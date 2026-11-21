-- VibeBazaar India (Bengaluru D2C Ethnic & Artisan Marketplace)
-- Generated during rapid AI "vibe coding" sprint

-- 1. Public Catalog Table (SAFE HARD NEGATIVE: Read-only public catalog)
CREATE TABLE public.products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sku TEXT NOT NULL,
    title TEXT NOT NULL,
    price_inr INTEGER NOT NULL,
    category TEXT NOT NULL
);

ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Public catalog readable by everyone"
    ON public.products
    FOR SELECT
    USING (true);

-- 2. Customer Orders Table (VULNERABLE CVE-2025-48757: Vacuous USING (true) + DPDP Act PII!)
CREATE TABLE public.customer_orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    customer_name TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT NOT NULL,
    pan_number TEXT NOT NULL,
    delivery_address TEXT NOT NULL,
    amount_inr INTEGER NOT NULL,
    payment_status TEXT DEFAULT 'PENDING'
);

ALTER TABLE public.customer_orders ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Enable access to all users"
    ON public.customer_orders
    FOR ALL
    USING (true);

-- 3. Order Line Items Table (VULNERABLE: Missing RLS; linked via FK order_id -> customer_orders.id)
CREATE TABLE public.order_line_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id UUID NOT NULL REFERENCES public.customer_orders(id),
    product_sku TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    subtotal_inr INTEGER NOT NULL
);

-- 4. Multi-Tenant B2B Vendor Invoices (TRACK 03 BOUNDARY: Ambiguous org_id + required_role + approval_limit_inr -> ABSTAIN!)
-- POLICY_SPEC: Requires custom org finance_approver vs vendor_viewer role matrix and INR threshold rules
CREATE TABLE public.b2b_vendor_invoices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    vendor_id UUID NOT NULL,
    required_role TEXT NOT NULL,
    approval_limit_inr INTEGER NOT NULL,
    gst_number TEXT NOT NULL,
    payout_inr INTEGER NOT NULL
);

-- 5. Privileged Helper RPC without pinned search_path (VULNERABLE VA-RLS-004)
CREATE OR REPLACE FUNCTION public.admin_purge_stale_carts(days_old INT)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    DELETE FROM public.order_line_items WHERE quantity <= 0;
END;
$$;
