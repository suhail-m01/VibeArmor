/**
 * Pure ES2020 JavaScript Popup Controller for VibeArmor Browser Extension (Manifest V3)
 * Zero TypeScript syntax; includes standalone offline AI snippet scanning + Studio server sync.
 */
const serverInput = document.getElementById("serverUrl");
const tokenInput = document.getElementById("pairToken");
const repoInput = document.getElementById("repoInput");
const snippetInput = document.getElementById("snippetInput");
const grabBtn = document.getElementById("grabBtn");
const scanSnippetBtn = document.getElementById("scanSnippetBtn");
const saveCfgBtn = document.getElementById("saveCfgBtn");
const auditBtn = document.getElementById("auditBtn");
const resultBox = document.getElementById("resultBox");

function esc(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function maskSecretsJs(text) {
  return String(text || "")
    .replace(/\b(sk_(?:live|test)_[A-Za-z0-9]{4})[A-Za-z0-9]{8,}\b/g, "$1************")
    .replace(/\b(sk-[A-Za-z0-9]{4})[A-Za-z0-9_-]{12,}\b/g, "$1************")
    .replace(/\b(ghp_[A-Za-z0-9]{4})[A-Za-z0-9]{16,}\b/g, "$1************")
    .replace(/\b(github_pat_[A-Za-z0-9_]{6})[A-Za-z0-9_]{16,}\b/g, "$1************")
    .replace(/\b(AIza[0-9A-Za-z_-]{4})[0-9A-Za-z_-]{16,}\b/g, "$1************");
}

function scanSnippetLocally(code) {
  const issues = [];
  const src = String(code || "");
  if (/(?:sk_(?:live|test)_|sk-[A-Za-z0-9]{16}|ghp_[A-Za-z0-9]{20}|github_pat_[A-Za-z0-9_]{20}|AIza[0-9A-Za-z_-]{20})/.test(src)) {
    issues.push({
      cwe: "CWE-798",
      owasp: "A07:2021 Identification & Auth Failures",
      sev: "CRITICAL",
      title: "Hardcoded API Credential Detected",
      fix: "Relocate credential to server-only environment variable (os.getenv / process.env).",
    });
  }
  if (/SELECT\s+.*\+\s*[a-zA-Z_]|execute\s*\(\s*f["']\s*SELECT/i.test(src)) {
    issues.push({
      cwe: "CWE-89",
      owasp: "A03:2021 Injection",
      sev: "CRITICAL",
      title: "SQL Injection via String Concatenation / Interpolation",
      fix: "Use parameterized placeholders (?, %s, or $1) instead of string concatenation.",
    });
  }
  if (/\bdangerouslySetInnerHTML\b|\.innerHTML\s*=/.test(src)) {
    issues.push({
      cwe: "CWE-79",
      owasp: "A03:2021 Cross-Site Scripting (XSS)",
      sev: "HIGH",
      title: "Unescaped DOM HTML Sink (XSS Risk)",
      fix: "Render text safely or sanitize untrusted HTML with DOMPurify before injection.",
    });
  }
  if (/\byaml\.load\s*\(|\bpickle\.loads\s*\(|\bshell\s*=\s*True\b/.test(src)) {
    issues.push({
      cwe: "CWE-78 / CWE-502",
      owasp: "A03/A08 Injection & Deserialization",
      sev: "CRITICAL",
      title: "Dangerous Execution / Deserialization Sink",
      fix: "Use yaml.safe_load(), JSON serialization, and subprocess(..., shell=False).",
    });
  }
  if (/CREATE\s+TABLE/i.test(src) && !/ENABLE\s+ROW\s+LEVEL\s+SECURITY/i.test(src)) {
    issues.push({
      cwe: "CWE-284",
      owasp: "A01:2021 Broken Access Control",
      sev: "CRITICAL",
      title: "PostgreSQL / Supabase Table Missing Row-Level Security (RLS)",
      fix: "Add ALTER TABLE ... ENABLE ROW LEVEL SECURITY and an owner-scoped CREATE POLICY.",
    });
  }
  return issues;
}

chrome.storage.local.get({ serverUrl: "http://127.0.0.1:8000", pairToken: "" }, (cfg) => {
  serverInput.value = cfg.serverUrl;
  tokenInput.value = cfg.pairToken;
});

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs && tabs[0];
  if (!tab || !tab.url) return;
  try {
    const u = new URL(tab.url);
    if (u.hostname === "github.com") {
      const parts = u.pathname.split("/").filter(Boolean);
      if (parts.length >= 2) {
        repoInput.value = "https://github.com/" + parts[0] + "/" + parts[1].replace(/\.git$/, "");
      }
    }
  } catch (_err) {
    // ignore invalid tab URL
  }
});

grabBtn.addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs && tabs[0];
    if (!tab || !tab.id || !chrome.scripting) return;
    chrome.scripting.executeScript(
      {
        target: { tabId: tab.id },
        func: function getSelectedCode() {
          const sel = window.getSelection();
          return sel ? String(sel.toString()) : "";
        },
      },
      (results) => {
        const txt = results && results[0] && results[0].result ? results[0].result : "";
        if (txt.trim()) {
          snippetInput.value = txt;
        } else {
          resultBox.classList.remove("hidden");
          resultBox.innerHTML = `<div style="font-size:11px;color:#64748b;">Highlight code on the active page first, or paste code directly above.</div>`;
        }
      }
    );
  });
});

scanSnippetBtn.addEventListener("click", async () => {
  const rawCode = snippetInput.value || "";
  if (!rawCode.trim()) {
    resultBox.classList.remove("hidden");
    resultBox.innerHTML = `<div style="font-size:11px;color:#be123c;font-weight:700;">Paste or grab an AI-generated code snippet first.</div>`;
    return;
  }
  resultBox.classList.remove("hidden");
  const localFindings = scanSnippetLocally(rawCode);
  if (localFindings.length === 0) {
    resultBox.innerHTML = `
      <div style="padding:8px 10px;border-radius:8px;background:#ecfdf5;border:1px solid #6ee7b7;color:#065f46;font-weight:800;font-size:11.5px;">
        ✓ 0 High-Risk Sinks Detected in Snippet (${rawCode.split(/\r?\n/).length} lines)
      </div>`;
    return;
  }
  const rows = localFindings
    .map(
      (f) => `
      <div style="padding:7px 8px;border-radius:7px;background:#fff1f2;border:1px solid #fecdd3;margin-top:6px;font-size:11px;">
        <div style="font-weight:800;color:#9f1239;">[${esc(f.sev)} · ${esc(f.cwe)}] ${esc(f.title)}</div>
        <div style="color:#64748b;font-size:10px;margin-top:2px;">${esc(f.owasp)}</div>
        <div style="color:#065f46;font-size:10.5px;margin-top:4px;font-weight:600;">Fix: ${esc(maskSecretsJs(f.fix))}</div>
      </div>`
    )
    .join("");
  resultBox.innerHTML = `
    <div style="padding:7px 10px;border-radius:8px;background:#fff1f2;border:1px solid #fda4af;color:#9f1239;font-weight:800;font-size:11.5px;">
      🛑 ${localFindings.length} Vulnerability Signal(s) Found in AI Snippet
    </div>
    ${rows}`;
});

saveCfgBtn.addEventListener("click", () => {
  chrome.storage.local.set(
    { serverUrl: serverInput.value.trim() || "http://127.0.0.1:8000", pairToken: tokenInput.value.trim() },
    () => {
      saveCfgBtn.textContent = "Saved ✓";
      setTimeout(() => {
        saveCfgBtn.textContent = "Save";
      }, 1200);
    }
  );
});

auditBtn.addEventListener("click", () => {
  chrome.storage.local.set(
    { serverUrl: serverInput.value.trim() || "http://127.0.0.1:8000", pairToken: tokenInput.value.trim() },
    () => {
      auditBtn.disabled = true;
      auditBtn.textContent = "Scanning Cross-Layer Graph...";
      resultBox.classList.remove("hidden");
      resultBox.innerHTML = `<div style="font-size:11.5px;color:#475569;">Running VibeArmor 5-point security gate...</div>`;

      chrome.runtime.sendMessage(
        {
          type: "VIBEARMOR_CHECK_REPO",
          repoUrl: repoInput.value.trim(),
          scanIfMissing: true,
        },
        (res) => {
          auditBtn.disabled = false;
          auditBtn.textContent = "Audit & Verify Push / Deploy Gate";
          if (!res || !res.ok || !res.data) {
            resultBox.innerHTML = `<div style="color:#be123c;font-size:11px;font-weight:700;">Studio Server (${esc(
              serverInput.value || "http://127.0.0.1:8000"
            )}) not reachable: ${esc((res && res.error) || "Start VibeArmor Studio locally for full repo graph audit, or use the Offline AI Snippet Scanner above!")}</div>`;
            return;
          }
          const d = res.data;
          const ready = Boolean(d.ready_to_push);
          const bg = ready ? "#ecfdf5" : "#fff1f2";
          const bd = ready ? "#6ee7b7" : "#fda4af";
          const fg = ready ? "#065f46" : "#9f1239";
          const checksHtml = Object.values(d.checks || {})
            .map(
              (c) =>
                `<div style="display:flex;justify-content:space-between;font-size:11px;padding:4px 0;border-bottom:1px solid #f1f5f9;">
                  <span>${c.passed ? "✅" : "❌"} ${esc(c.label)}</span>
                  <strong style="color:${c.passed ? "#059669" : "#e11d48"};">${c.passed ? "PASS" : c.count + " open"}</strong>
                </div>`
            )
            .join("");

          resultBox.innerHTML = `
            <div style="padding:8px 10px;border-radius:8px;background:${bg};border:1px solid ${bd};color:${fg};font-weight:800;font-size:11.5px;margin-bottom:8px;">
              ${ready ? "✓ READY TO PUSH & DEPLOY" : "🛑 PUSH & DEPLOY BLOCKED (" + d.open_threats + " Threats)"} · ${d.security_score}/100
            </div>
            <div style="margin-bottom:9px;">${checksHtml}</div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;">
              <button id="openGraphBtn" class="btn-sec" type="button">1. View Graph ↗</button>
              <button id="openDiffBtn" class="btn-pri" type="button">3. Fix Diffs ↗</button>
            </div>
          `;
          document.getElementById("openGraphBtn").onclick = () =>
            chrome.runtime.sendMessage({ type: "VIBEARMOR_OPEN_STUDIO", projectId: d.project_id, step: "step1_graph" });
          document.getElementById("openDiffBtn").onclick = () =>
            chrome.runtime.sendMessage({ type: "VIBEARMOR_OPEN_STUDIO", projectId: d.project_id, step: "step3_diff" });
        }
      );
    }
  );
});
