// PhishGuard AI - background service worker
// Talks to the FastAPI backend so content scripts never have to make
// cross-origin requests directly from a page (avoids page CSP issues).

const API_BASE = "https://phishguard-ai-6qdq.onrender.com".replace(/\/+$/, "");

// tabId -> { url, result, timestamp }
const scanCache = {};

// tabId -> { url, egress_data, evaluation, timestamp }
const tabEgress = {};

// Restore cache from session storage when service worker starts
if (typeof chrome !== "undefined" && chrome.storage?.session) {
  chrome.storage.session.get(["pg_scan_cache", "pg_tab_egress"]).then((data) => {
    if (data?.pg_scan_cache) Object.assign(scanCache, data.pg_scan_cache);
    if (data?.pg_tab_egress) Object.assign(tabEgress, data.pg_tab_egress);
  }).catch(() => {});
}

function persistCache() {
  try {
    if (typeof chrome !== "undefined" && chrome.storage?.session) {
      chrome.storage.session.set({
        pg_scan_cache: scanCache,
        pg_tab_egress: tabEgress,
      }).catch(() => {});
    }
  } catch (_) {}
}

async function fetchWithRetry(url, options = {}, retries = 2, timeoutMs = 15000) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const res = await fetch(url, { ...options, signal: controller.signal });
      clearTimeout(timer);
      return res;
    } catch (err) {
      if (attempt === retries) throw err;
      // Wait 1.5s before retry (handles Render spin-up / transient cold boot)
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
}

async function scanUrl(url, networkTelemetry = null) {
  const payload = { url };
  if (networkTelemetry) {
    payload.network_telemetry = networkTelemetry;
  }

  const res = await fetchWithRetry(`${API_BASE}/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }, 2, 15000);

  if (!res.ok) {
    let detail = `Backend returned ${res.status}`;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch (_) {
      /* ignore non-JSON error body */
    }
    throw new Error(detail);
  }

  return res.json();
}

async function sendFeedback(url, isPhishing) {
  const res = await fetchWithRetry(`${API_BASE}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, is_phishing: isPhishing }),
  }, 1, 15000);

  if (!res.ok) {
    let detail = `Backend returned ${res.status}`;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch (_) {
      /* ignore non-JSON error body */
    }
    throw new Error(detail);
  }

  return res.json();
}

async function reportEgress(url, egressData) {
  const res = await fetchWithRetry(`${API_BASE}/telemetry/network-egress`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, egress_data: egressData }),
  }, 1, 15000);

  if (!res.ok) {
    let detail = `Backend returned ${res.status}`;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch (_) {
      /* ignore non-JSON error body */
    }
    throw new Error(detail);
  }

  return res.json();
}

chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishGuard AI installed with Network Chunking & Egress Inspection");
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "PHISHGUARD_HEALTH_CHECK") {
    fetchWithRetry(`${API_BASE}/health`, { method: "GET" }, 1, 8000)
      .then((res) => {
        sendResponse({ ok: res && res.ok, status: res && res.ok ? "Active" : "Degraded" });
      })
      .catch((err) => {
        sendResponse({ ok: false, error: err?.message || String(err) });
      });
    return true;
  }

  if (message?.type === "PHISHGUARD_SCAN") {
    const tabId = sender.tab?.id ?? message.tabId;
    const networkTelemetry = tabId !== undefined ? tabEgress[tabId]?.egress_data : null;

    scanUrl(message.url, networkTelemetry)
      .then((result) => {
        if (tabId !== undefined) {
          scanCache[tabId] = { url: message.url, result, timestamp: Date.now() };
          persistCache();
        }
        sendResponse({ ok: true, result });
      })
      .catch((err) => {
        sendResponse({ ok: false, error: err?.message || String(err) });
      });

    return true; // keep the message channel open for the async response
  }

  if (message?.type === "PHISHGUARD_NETWORK_CHUNK") {
    const tabId = sender.tab?.id ?? message.tabId;
    const { url, egress_data } = message;

    reportEgress(url, egress_data)
      .then((evaluation) => {
        if (tabId !== undefined) {
          tabEgress[tabId] = {
            url,
            egress_data,
            evaluation,
            timestamp: Date.now(),
          };
          persistCache();
        }
        sendResponse({ ok: true, evaluation });
      })
      .catch((err) => {
        if (tabId !== undefined) {
          tabEgress[tabId] = {
            url,
            egress_data,
            evaluation: {
              egress_risk_penalty: 0,
              egress_level: "Safe",
              reasons: ["Backend offline or telemetry pending"],
            },
            timestamp: Date.now(),
          };
          persistCache();
        }
        sendResponse({ ok: false, error: err?.message || String(err) });
      });

    return true;
  }

  if (message?.type === "PHISHGUARD_FEEDBACK") {
    sendFeedback(message.url, message.isPhishing)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((err) => sendResponse({ ok: false, error: err?.message || String(err) }));

    return true; // keep the message channel open for the async response
  }

  if (message?.type === "PHISHGUARD_GET_ACTIVE_RESULT") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      const cached = tab ? scanCache[tab.id] : undefined;
      const egress = tab ? tabEgress[tab.id] : undefined;
      sendResponse({
        ok: true,
        cached,
        egress,
        tab: tab ? { id: tab.id, url: tab.url } : null,
      });
    });

    return true;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete scanCache[tabId];
  delete tabEgress[tabId];
  persistCache();
});
