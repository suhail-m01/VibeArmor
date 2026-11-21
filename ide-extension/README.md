# VibeArmor — Pre-Push & Deploy Security Gate Extension (`v3.0.0`)

Compatible with **VS Code, Cursor, Windsurf, VSCodium, Trae, and Kiro**.

## What It Checks Before GitHub Push or Cloud Deployment
1. **`.env` & Secret Leak Gate (`VA-ENV-001` / `VA-ENV-002`):** Blocks unignored `.env` files and `NEXT_PUBLIC_` / `VITE_` private key leaks.
2. **Supabase Row-Level Security (`CVE-2025-48757`):** Catches tables with missing RLS or vacuous `USING (true)` policies exposing user data.
3. **Browser-Bundled API Keys:** Relocates hardcoded OpenAI / Razorpay / Stripe / Service-Role keys behind a server-only Zero-Trust Auto-BFF.
4. **Database Injections & Payment Callback Spoofing:** Fixes SQLi, Command Injection, unsafe eval/deserialization, and unsigned Razorpay/Stripe webhooks.
5. **AI-Hallucinated & Vulnerable Packages:** Quarantines slopsquatted package names and upgrades reachable CVEs.

## Quick Install
```bash
# VS Code
code --install-extension vibearmor-guard-3.0.0.vsix

# Cursor
cursor --install-extension vibearmor-guard-3.0.0.vsix

# Windsurf
windsurf --install-extension vibearmor-guard-3.0.0.vsix
```
