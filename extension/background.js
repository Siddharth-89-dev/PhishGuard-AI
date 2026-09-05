// PhishGuard AI - background service worker
// Talks to the FastAPI backend so content scripts never have to make
// cross-origin requests directly from a page (avoids page CSP issues).

const API_BASE = "http://127.0.0.1:8000";

// tabId -> { url, result, timestamp }
const scanCache = {};

async function scanUrl(url) {
  const res = await fetch(`${API_BASE}/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
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

chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishGuard AI installed");
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "PHISHGUARD_SCAN") {
    const tabId = sender.tab?.id ?? message.tabId;

    scanUrl(message.url)
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
      sendResponse({
        ok: true,
        cached,
        tab: tab ? { id: tab.id, url: tab.url } : null,
      });
    });

    return true;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete scanCache[tabId];
});
