# VibeArmor Browser Guard Extension (Chrome · Edge · Brave · Manifest V3)

Actively gates GitHub repository Merges/Commits and Cloud Deployments (`Vercel`, `Netlify`, `Render`, `Railway`, `Lovable`, `Bolt.new`) against 5 pre-push AI-coding risks:
1. Unignored `.env` files & exposed `NEXT_PUBLIC_` / `VITE_` keys
2. Missing or vacuous Supabase / PostgreSQL Row-Level Security (`RLS`) & unpinned `SECURITY DEFINER` RPCs
3. Hardcoded private API keys in browser bundles
4. SQL / Command / Code injections & unsigned Razorpay/Stripe payment callbacks
5. AI-hallucinated slopsquat package names & vulnerable dependencies

## Quick Install (`< 20 seconds`)
1. Unzip `vibearmor-browser-guard-3.0.0.zip` into a folder.
2. Open `chrome://extensions` (or `edge://extensions` / `brave://extensions`).
3. Toggle **Developer mode** ON in the top-right corner.
4. Click **Load unpacked** and select the unzipped folder.
5. Click the **VibeArmor Shield** icon in your toolbar, paste your VibeArmor Studio Server URL (`http://127.0.0.1:8000` or your live Studio URL), and visit any GitHub repo or deployment dashboard!
