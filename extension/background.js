// PhishGuard AI - background service worker
// Talks to the FastAPI backend so content scripts never have to make
// cross-origin requests directly from a page (avoids page CSP issues).

const API_BASE = "https://phishguard-ai-6qdq.onrender.com";

// tabId -> { url, result, timestamp }
const scanCache = {};

// tabId -> { url, egress_data, evaluation, timestamp }
const tabEgress = {};

async function scanUrl(url, networkTelemetry = null) {
  const payload = { url };
  if (networkTelemetry) {
    payload.network_telemetry = networkTelemetry;
  }

  const res = await fetch(`${API_BASE}/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

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
  const res = await fetch(`${API_BASE}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, is_phishing: isPhishing }),
  });

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
  const res = await fetch(`${API_BASE}/telemetry/network-egress`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, egress_data: egressData }),
  });

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
  if (message?.type === "PHISHGUARD_SCAN") {
    const tabId = sender.tab?.id ?? message.tabId;
    const networkTelemetry = tabId !== undefined ? tabEgress[tabId]?.egress_data : null;

    scanUrl(message.url, networkTelemetry)
      .then((result) => {
        if (tabId !== undefined) {
          scanCache[tabId] = { url: message.url, result, timestamp: Date.now() };
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
});
