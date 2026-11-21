# VibeArmor v3.6 — Evidence-Driven Agentic Security & Closed-Loop Remediation Suite
**Team NeXGen Coder's** · Presidency University, Bengaluru

> **Core Architectural Invariant:** *"The AI proposes the fix. VibeArmor decides whether the fix is safe."*

---

## ⚡ Quick Start in VS Code (1 Command — Auto-Starts Backend `:8000` + UI `:5173`)

Open the `vibearmor` folder in VS Code, open the Terminal (`` Ctrl+` ``), and run **any one** of the following:

### Option 1 — Full-Stack Dev Mode (`npm run dev` from Root or `studio/`)
Automatically checks/installs Python & Node dependencies, boots the **FastAPI Security Engine on `http://127.0.0.1:8000`**, and launches **Vite Hot-Reload UI on `http://localhost:5173`**:
```powershell
npm run dev
```
*(Or from inside `studio/`: `cd studio`, `npm install`, `npm run dev` — it now auto-starts the `:8000` Python backend too!)*

### Option 2 — Windows One-Click Script (No Node.js Required — Serves Pre-Built UI on `:8000`)
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned; .\start_studio.ps1
```
*(Or simply double-click `start_studio.bat` in Windows Explorer, or press **`F5`** inside VS Code!)*

---

VibeArmor protects AI-generated ("vibe-coded") repositories before they are committed, pushed to GitHub, or deployed to Vercel, Netlify, Render, or Railway—combining **Tree-sitter & `sqlglot` AST Code Intelligence**, **FAISS Security RAG (`OWASP` · `CWE` · `CAPEC`)**, **LangGraph 4-Agent Orchestration**, and a **Deterministic 3-Gate Verification & Policy Engine** (`0` bytes modified on clean files, `0` raw secret leaks, `0` unverified AI self-certifications).

---

## 1. Evidence-Driven Agentic Security Architecture

```
Developer / AI Coding Tool (Cursor · VS Code · GitHub · Browser Snippet)
                        │
                        ▼
[1. DetectionAgent] Tree-sitter (TS/JS), Python AST, sqlglot PostgreSQL/RLS & Dependency Graph
                        │
                        ▼
[2. SecurityResearchAgent (Read-Only)] 384-dim FAISS IndexFlatIP Security RAG (CWE · OWASP · CAPEC)
                        │   Produces Grounded `SecurityEvidencePackage` +Masked Minimal Security Slice
                        ▼
[3. RemediationAgent] Deterministic AST/SQL Codemods + ModelProvider (`PROPOSED_UNVERIFIED`)
                        │
                        ▼
[4. VerificationAgent] Isolated Sandbox Copy -> Gate 1 (Compile/Tests) · Gate 2 (Rescan) · Gate 3 (Exploit)
                        │
                        ▼
[Deterministic Security Decision & Policy Engine (`security_policy.yaml`)]
  VERIFIED iff (Gate1 == PASS and Gate2 == PASS and Gate3 in {PASS, NOT_APPLICABLE})
```

- **Security Evidence Graph UI (`Evidence & Agentic RAG` tab):** Inspect the 12-node causal graph answering *"Why is this vulnerable?"* and *"Why is this fix verified?"* with masked code slices (`sk_live_****`) and live FAISS vector search.
- **Configurable Policy Gate (`security_policy.yaml`):** Deterministic enforcement of `block_critical`, `block_high`, `require_verification`, `require_tests`, `allow_unverified_ai_patch: false`, and `secrets_block_commit`.

---

## 2. Five Cross-Layer Threat Pillars Covered
1. **`.env` Variables & Gitignore Hygiene (`VA-ENV-001`, `VA-ENV-002`)** — Catches unignored `.env` files containing live credentials and private keys prefixed with `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_`.
2. **Supabase / PostgreSQL Access & RPC Hardening (`CVE-2025-48757`, `VA-RLS-001..004`)** — Synthesizes owner/FK-scoped Row-Level Security policies and pins parameterized `SECURITY DEFINER` RPC `search_path` + revokes `PUBLIC, anon` execution.
3. **Client-Exposed Private API Keys (`VA-SEC-001`, `VA-SEC-002`)** — Relocates hardcoded OpenAI, Razorpay, Stripe, AWS, or `service_role` keys to server `.env.local` and generates a Zero-Trust Next.js BFF route.
4. **Database / Code Injections & Payment Callbacks (`VA-TNT-*`, `VA-PAY-*`)** — Parameterizes raw SQL/shell/eval sinks (including chained `.connect().execute()` calls) and enforces `hmac.compare_digest` verification on Razorpay/Stripe webhooks.
5. **Supply-Chain Hallucinations & Vulnerable Dependencies (`VA-SUP-*`)** — Quarantines AI-hallucinated slopsquat packages and upgrades AST-reachable CVEs.

---

## 3. Multi-Editor, Browser MV3 & Staged Git Guard Suite

### A. VS Code / Cursor / Windsurf Extension (`ide-extension/vibearmor-guard-3.0.0.vsix`)
- **Standalone Offline + Paired Studio Mode:** Scans `.py`, `.ts`, `.tsx`, `.js`, `.jsx`, `.sql`, and `.env` files in `<50ms` even when VibeArmor Studio is offline.
- **Exact Line-Range Quick Fixes (`Ctrl+.` / `Cmd+.`):** Computes minimal changed line ranges (`computeMinimalLinePatch`)—never replacing entire files indiscriminately.
- **Cross-Platform Install:**
  - **1-Paste Offline Installer (Recommended on Windows PowerShell 5.1/7 & macOS):** Click **`Code Editor (.vsix)`** in VibeArmor Studio -> **`Copy 1-Paste Installer (Windows PowerShell)`** (writes safely to `$env:USERPROFILE\Downloads\vibearmor-guard-3.0.0.vsix` with zero network/TLS dependencies and zero `&&` syntax errors).
  - **Direct CLI Install (after saving to `Downloads`):**
    ```powershell
    # Windows PowerShell 5.1 / 7
    code --install-extension "$env:USERPROFILE\Downloads\vibearmor-guard-3.0.0.vsix"
    cursor --install-extension "$env:USERPROFILE\Downloads\vibearmor-guard-3.0.0.vsix"
    ```
    ```bash
    # macOS / Linux
    code --install-extension "$HOME/Downloads/vibearmor-guard-3.0.0.vsix"
    ```

### B. Chrome / Edge / Brave Manifest V3 Guard (`browser-extension/vibearmor-browser-guard-3.0.0.zip`)
- **Scope:** Inspects AI-generated code snippets in the browser (ChatGPT, Claude, v0, Bolt, Lovable, GitHub) with 1-click active-tab selection capture + offline CWE vulnerability scanner, and gates unsafe GitHub Merge / Vercel / Netlify / Render / Railway deploys when paired with VibeArmor Studio.
- **Install:** Click **`Browser Guard (.zip)`** -> run the 1-Paste PowerShell/Bash extractor -> open `chrome://extensions` -> **Developer mode ON** -> **Load unpacked** -> select `Downloads/vibearmor-browser-guard`.

### C. Staged-Only Git Pre-Commit Guard & GitHub Actions Gate
```bash
# Install staged-only pre-commit hook + pre-push gate + Cursor MCP config
vibearmor init .

# Manually scan ONLY staged Git index files (<60ms, ignores unstaged WIP files)
vibearmor guard . --staged
```
CI/CD pull requests are deterministically gated via `.github/workflows/vibearmor-security-gate.yml`.

---

## 4. Precision GitHub Push Module (Step 4)
1. **Method 1 · Instant 1-Paste Offline Local Git Push (Zero Token Required):** Generates a ~4 KB Gzip+Base64 unified surgical diff command (`new file mode 100644` compliant) for Windows PowerShell 5.1/7 and Bash that clones, applies `git apply`, commits, pushes using your PC's existing Git login, and opens the GitHub PR Compare page.
2. **Method 2 · Verified GitHub Personal Access Token Push:** Pre-verifies a 4-row permission checklist (`Identity`, `Repo Located`, `Contents: Read & Write`, `Pull Request Flow`), persists masked credentials (`github_pat_****`), and pushes strictly surgical changes while blocking raw `.env` files.

---

## 5. Run Locally & Execute All 34 Automated Tests
```bash
pip install -r requirements.txt pytest
pip install -e . --no-deps
pytest tests/test_vibearmor_e2e.py -v
uvicorn core.interfaces.api:app --host 0.0.0.0 --port 8000
```
