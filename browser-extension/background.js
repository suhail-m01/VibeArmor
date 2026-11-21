/**
 * VibeArmor Browser Guard Background Service Worker (Manifest V3)
 * Proxies readiness checks to the VibeArmor Web Application server cleanly without page CSP friction.
 */
const DEFAULT_SERVER = "http://127.0.0.1:8000";

async function getConfig() {
  return new Promise((resolve) => {
    chrome.storage.local.get(
      { serverUrl: DEFAULT_SERVER, pairToken: "", bypassOnceRepo: "" },
      (items) => resolve(items)
    );
  });
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "VIBEARMOR_CHECK_REPO") {
    (async () => {
      try {
        const cfg = await getConfig();
        const base = String(cfg.serverUrl || DEFAULT_SERVER).replace(/\/$/, "");
        const resp = await fetch(`${base}/api/extension/browser/check-repo`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            repo_url: msg.repoUrl || "",
            page_host: msg.pageHost || "",
            pair_token: cfg.pairToken || "",
            scan_if_missing: Boolean(msg.scanIfMissing),
          }),
        });
        const data = await resp.json();
        if (!resp.ok) {
          sendResponse({ ok: false, error: data.detail || `HTTP ${resp.status}` });
          return;
        }
        sendResponse({ ok: true, serverUrl: base, data });
      } catch (err) {
        sendResponse({ ok: false, error: err && err.message ? err.message : "Server unreachable" });
      }
    })();
    return true; // async sendResponse
  }

  if (msg.type === "VIBEARMOR_OPEN_STUDIO") {
    (async () => {
      const cfg = await getConfig();
      const base = String(cfg.serverUrl || DEFAULT_SERVER).replace(/\/$/, "");
      const step = msg.step || "step3_diff";
      const target = msg.projectId
        ? `${base}/?project=${encodeURIComponent(msg.projectId)}&step=${encodeURIComponent(step)}`
        : base;
      chrome.tabs.create({ url: target });
      sendResponse({ ok: true });
    })();
    return true;
  }
});
