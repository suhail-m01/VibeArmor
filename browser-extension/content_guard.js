/**
 * VibeArmor Content Guard for GitHub, Vercel, Netlify, Render, Railway, Lovable & Bolt
 * Actively gates Merge / Commit / Deploy buttons when open security vulnerabilities exist!
 */
(function () {
  if (window.__VIBEARMOR_GUARD_LOADED__) return;
  window.__VIBEARMOR_GUARD_LOADED__ = true;

  let gateState = null; // { audited, ready_to_push, security_score, open_threats, project_id, repo_slug, top_findings }
  let emergencyBypass = false;

  function extractGitHubRepoSlug() {
    if (location.hostname !== "github.com") return "";
    const parts = location.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return "";
    const reserved = new Set([
      "settings", "orgs", "organizations", "marketplace", "explore", "topics",
      "trending", "collections", "events", "sponsors", "notifications", "login", "signup", "new"
    ]);
    if (reserved.has(parts[0].toLowerCase())) return "";
    return `${parts[0]}/${parts[1].replace(/\.git$/, "")}`;
  }

  function ensurePill() {
    let pill = document.getElementById("vibearmor-floating-pill");
    if (!pill) {
      pill = document.createElement("div");
      pill.id = "vibearmor-floating-pill";
      pill.className = "va-neutral";
      pill.innerHTML = `<span>🛡️ VibeArmor Gate: Verify Repo</span>`;
      pill.addEventListener("click", () => {
        if (!gateState || !gateState.audited) {
          refreshGate(true);
        } else if (!gateState.ready_to_push) {
          showHardBlockModal("Pre-Push & Deploy Inspection");
        } else {
          chrome.runtime.sendMessage({
            type: "VIBEARMOR_OPEN_STUDIO",
            projectId: gateState.project_id,
            step: "step4_deliver",
          });
        }
      });
      document.body.appendChild(pill);
    }
    return pill;
  }

  function updatePillUI() {
    const pill = ensurePill();
    if (!gateState || !gateState.audited) {
      const slug = extractGitHubRepoSlug();
      pill.className = "va-neutral";
      pill.textContent = slug
        ? `🛡️ VibeArmor: Click to Audit ${slug}`
        : `🛡️ VibeArmor Deploy Guard Active`;
      return;
    }
    if (gateState.ready_to_push) {
      pill.className = "va-ready";
      pill.textContent = `✓ VibeArmor Ready to Push & Deploy (${gateState.security_score}/100)`;
    } else {
      pill.className = "va-blocked";
      pill.textContent = `🛑 VibeArmor Blocked (${gateState.open_threats} Open Threats · ${gateState.security_score}/100)`;
    }
  }

  function refreshGate(scanIfMissing) {
    const slug = extractGitHubRepoSlug();
    const pill = ensurePill();
    if (scanIfMissing) {
      pill.className = "va-neutral";
      pill.textContent = "⏳ VibeArmor: Scanning Cross-Layer Graph...";
    }
    chrome.runtime.sendMessage(
      {
        type: "VIBEARMOR_CHECK_REPO",
        repoUrl: slug ? `https://github.com/${slug}` : "",
        pageHost: location.hostname,
        scanIfMissing: Boolean(scanIfMissing),
      },
      (res) => {
        if (res && res.ok && res.data) {
          gateState = res.data;
          updatePillUI();
        } else if (scanIfMissing) {
          pill.className = "va-neutral";
          pill.textContent = "⚠️ VibeArmor Studio Offline (Open Popup)";
        }
      }
    );
  }

  function showHardBlockModal(actionLabel) {
    const existing = document.getElementById("vibearmor-gate-modal-backdrop");
    if (existing) existing.remove();

    const findingsList = ((gateState && gateState.top_findings) || [])
      .slice(0, 5)
      .map(
        (f) =>
          `<div style="padding:7px 9px;border-radius:8px;background:#FFF1F2;border:1px solid #FECDD3;margin-bottom:6px;font-size:11.5px;">
            <strong style="color:#9F1239;">[${f.rule_id}] ${f.title}</strong>
            <div style="font-family:monospace;font-size:10.5px;color:#64748B;margin-top:2px;">${f.file_path}:${f.line_start}</div>
          </div>`
      )
      .join("");

    const backdrop = document.createElement("div");
    backdrop.id = "vibearmor-gate-modal-backdrop";
    backdrop.innerHTML = `
      <div id="vibearmor-gate-modal">
        <div style="display:inline-block;padding:3px 9px;border-radius:999px;background:#FFF1F2;color:#BE123C;border:1px solid #FDA4AF;font-size:10.5px;font-weight:800;margin-bottom:8px;">
          HARD PUSH & DEPLOY SECURITY GATE
        </div>
        <h3 style="margin:0 0 6px;font-size:17px;font-weight:800;color:#0F172A;">
          Blocked Unsafe ${actionLabel}: ${gateState ? gateState.open_threats : "Multiple"} Open Vulnerabilities
        </h3>
        <p style="margin:0 0 12px;font-size:12.5px;color:#475569;line-height:1.45;">
          Repository <strong>${(gateState && gateState.repo_slug) || "workspace"}</strong> scored <strong>${gateState ? gateState.security_score : 0}/100</strong>.
          Review Vulnerable vs. Corrected code and adopt surgical fixes before pushing or deploying:
        </p>
        <div style="max-height:200px;overflow-y:auto;margin-bottom:14px;">
          ${findingsList || '<div style="font-size:12px;color:#9F1239;">Open pre-deployment threats detected.</div>'}
        </div>
        <div style="display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;">
          <button id="va-modal-close" style="padding:8px 13px;border-radius:9px;border:1px solid #CBD5E1;background:#fff;color:#334155;font-size:12px;font-weight:600;cursor:pointer;">
            Cancel Push / Deploy
          </button>
          <button id="va-modal-fix" style="padding:8px 15px;border-radius:9px;border:none;background:#4F46E5;color:#fff;font-size:12px;font-weight:700;cursor:pointer;">
            Fix Surgically in VibeArmor Studio ↗
          </button>
        </div>
      </div>
    `;
    document.body.appendChild(backdrop);

    document.getElementById("va-modal-close").onclick = () => backdrop.remove();
    document.getElementById("va-modal-fix").onclick = () => {
      chrome.runtime.sendMessage({
        type: "VIBEARMOR_OPEN_STUDIO",
        projectId: gateState && gateState.project_id,
        step: "step3_diff",
      });
      backdrop.remove();
    };
  }

  // Hard-Gate Click Interceptor on GitHub Merge/Commit & Cloud Deploy buttons!
  document.addEventListener(
    "click",
    (ev) => {
      if (emergencyBypass || !gateState || !gateState.audited || gateState.ready_to_push) return;
      const btn = ev.target && ev.target.closest ? ev.target.closest("button, a[role='button'], summary.btn-primary") : null;
      if (!btn) return;
      const txt = (btn.textContent || "").trim().toLowerCase();
      const gatedActions = [
        "merge pull request",
        "squash and merge",
        "rebase and merge",
        "commit changes",
        "deploy",
        "create deployment",
        "trigger deploy",
        "publish",
      ];
      const matched = gatedActions.find((kw) => txt === kw || txt.startsWith(kw));
      if (matched) {
        ev.preventDefault();
        ev.stopPropagation();
        showHardBlockModal(matched.toUpperCase());
      }
    },
    true
  );

  // Initial check + SPA navigation observer
  if (extractGitHubRepoSlug() || location.hostname !== "github.com") {
    ensurePill();
    refreshGate(false);
  }
  let lastHref = location.href;
  setInterval(() => {
    if (location.href !== lastHref) {
      lastHref = location.href;
      refreshGate(false);
    }
  }, 2000);
})();
