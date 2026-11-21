import { createClient } from "@supabase/supabase-js";
import axios from "axios";

// Safe Supabase anon JWT (role = "anon") — VibeArmor verifies JWT role & avoids false positives
const SUPABASE_URL = "https://vibebazaar.supabase.co";
const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZpYmViYXphYXIiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTczMDAwMDAwMH0.signature_anon_public_safe";

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

export async function fetchCatalogAndOrders(currentUserId: string) {
  const catalog = await supabase.from("products").select("*");
  const orders = await supabase.from("customer_orders").select("*");
  const items = await supabase.from("order_line_items").select("*");
  const kyc = await supabase.from("aadhaar_kyc_verifications").select("*");
  const vendorBills = await supabase.from("b2b_vendor_invoices").select("*");
  const shippingRates = await axios.get("/api/shipping/blr-rates");
  return { catalog, orders, items, kyc, vendorBills, shippingRates: shippingRates.data, currentUserId };
}
