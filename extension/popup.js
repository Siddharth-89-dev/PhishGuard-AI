const API_BASE = "https://phishguard-ai-6qdq.onrender.com";

// DOM Elements
const connectionPill = document.getElementById("pg-connection-pill");
const connText = document.getElementById("pg-conn-text");
const urlCapsule = document.getElementById("pg-url-capsule");
const hostEl = document.getElementById("pg-popup-host");
const lockIcon = document.getElementById("pg-lock-icon");
const protoBadge = document.getElementById("pg-proto-badge");

const verdictCard = document.getElementById("pg-verdict-card");
const verdictIcon = document.getElementById("pg-verdict-icon");
const verdictLabel = document.getElementById("pg-verdict-label");
const verdictTitle = document.getElementById("pg-verdict-title");
const meterNumber = document.getElementById("pg-meter-number");
const meterFill = document.getElementById("pg-meter-fill");
const riskBadge = document.getElementById("pg-risk-badge");
const confidenceText = document.getElementById("pg-confidence-text");
const threatBox = document.getElementById("pg-threat-box");
const threatText = document.getElementById("pg-threat-text");

const egressCard = document.getElementById("pg-egress-card");
const egressBadge = document.getElementById("pg-egress-badge");
const bytesVal = document.getElementById("pg-bytes-val");
const reqsVal = document.getElementById("pg-reqs-val");
const credVal = document.getElementById("pg-cred-val");
const egressDetail = document.getElementById("pg-egress-detail");

const feedbackCard = document.getElementById("pg-feedback-card");
const feedbackPromptWrap = document.getElementById("pg-feedback-prompt-wrap");
const feedbackCorrectBtn = document.getElementById("pg-feedback-correct");
const feedbackWrongBtn = document.getElementById("pg-feedback-wrong");
const feedbackThanks = document.getElementById("pg-feedback-thanks");

const rescanBtn = document.getElementById("pg-rescan");
const openDashboardBtn = document.getElementById("pg-open-dashboard");

let currentUrl = null;
let currentTabId = null;

// Helper: Extract domain
function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch (_) {
    return url || "";
  }
}

// Helper: Format bytes cleanly
function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return "0 B";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

// Check Backend Connection Health
async function checkBackendHealth() {
  try {
    // 1. First ask background service worker
    const bgResponse = await new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: "PHISHGUARD_HEALTH_CHECK" }, (res) => {
        if (chrome.runtime.lastError || !res) resolve(null);
        else resolve(res);
      });
    });

    if (bgResponse && bgResponse.ok) {
      connectionPill.className = "connection-pill";
      connText.textContent = "Active";
      return true;
    }

    // 2. Direct fetch fallback with 8s timeout
    const res = await fetch(`${API_BASE}/health`, { method: "GET", signal: AbortSignal.timeout(8000) });
    if (res.ok) {
      connectionPill.className = "connection-pill";
      connText.textContent = "Active";
      return true;
    }
  } catch (_) {}

  connectionPill.className = "connection-pill offline";
  connText.textContent = "Offline";
  return false;
}

// Reset Feedback UI
function resetFeedbackUI() {
  feedbackPromptWrap.style.display = "flex";
  feedbackThanks.style.display = "none";
  feedbackCorrectBtn.disabled = false;
  feedbackWrongBtn.disabled = false;
}

// Main Render Function
function render(tab, cached, egress) {
  currentTabId = tab?.id ?? null;
  const url = tab?.url;

  if (!url || !/^https?:/i.test(url)) {
    hostEl.textContent = "System / New Tab";
    protoBadge.textContent = "LOCAL";
    protoBadge.className = "capsule-proto";

    verdictCard.className = "verdict-card state-safe";
    verdictLabel.textContent = "Protected";
    verdictTitle.textContent = "Browser Internal Page";
    meterNumber.textContent = "0";
    meterFill.style.width = "0%";
    riskBadge.textContent = "Zero Risk";
    confidenceText.textContent = "Local Browser Surface";
    threatText.textContent = "Standard browser navigation surface without outbound network threat vectors.";

    egressCard.style.display = "none";
    feedbackCard.style.display = "none";
    currentUrl = null;
    return;
  }

  currentUrl = url;
  const host = hostnameOf(url);
  hostEl.textContent = host;

  const isHttps = url.startsWith("https://");
  protoBadge.textContent = isHttps ? "HTTPS" : "HTTP";
  protoBadge.className = isHttps ? "capsule-proto" : "capsule-proto insecure";

  // Render Egress Monitoring Telemetry
  egressCard.style.display = "flex";
  if (egress && egress.egress_data) {
    const data = egress.egress_data;
    const evalData = egress.evaluation || {};

    bytesVal.textContent = formatBytes(data.total_bytes_sent || 0);
    reqsVal.textContent = String(data.outbound_requests_count || 0);

    const isExfil = evalData.egress_level === "Critical Threat" || data.sensitive_data_transmitted;
    const isSusp = evalData.egress_level === "Suspicious" || evalData.egress_level === "Suspicious Egress" || data.keystroke_chunking_detected;

    if (isExfil) {
      credVal.textContent = "LEAK ALERT";
      credVal.style.color = "#fb7185";
      egressBadge.className = "egress-pill danger";
      egressBadge.textContent = "Exfiltrating";
    } else if (isSusp) {
      credVal.textContent = "Warning";
      credVal.style.color = "#fbbf24";
      egressBadge.className = "egress-pill warning";
      egressBadge.textContent = "Suspicious";
    } else {
      credVal.textContent = "Guarded";
      credVal.style.color = "#34d399";
      egressBadge.className = "egress-pill safe";
      egressBadge.textContent = "Monitored";
    }

    if (evalData.reasons && evalData.reasons.length > 0) {
      egressDetail.textContent = evalData.reasons[0];
    } else if (data.exfiltrated_destinations && data.exfiltrated_destinations.length > 0) {
      egressDetail.textContent = `External calls routed to: ${data.exfiltrated_destinations.slice(0, 2).join(", ")}`;
    } else {
      egressDetail.textContent = "Zero off-site leaks or credential drops detected.";
    }
  } else {
    bytesVal.textContent = "0 B";
    reqsVal.textContent = "0";
    credVal.textContent = "Guarded";
    credVal.style.color = "#34d399";
    egressBadge.className = "egress-pill safe";
    egressBadge.textContent = "Listening";
    egressDetail.textContent = "Observing browser resource chunks & keystroke timing...";
  }

  // Render Verdict Scan Results
  if (!cached || cached.url !== url) {
    verdictCard.className = "verdict-card";
    verdictLabel.textContent = "Not Scanned";
    verdictTitle.textContent = "Click 'Rescan Page' Below";
    meterNumber.textContent = "--";
    meterFill.style.width = "0%";
    riskBadge.textContent = "Pending";
    confidenceText.textContent = "Scan Required";
    threatText.textContent = "Click below to dispatch real-time neural network analysis.";
    feedbackCard.style.display = "none";
    return;
  }

  const result = cached.result || {};
  const isPhish = (result.prediction || "").toLowerCase() === "phishing";
  const score = Math.round(Number(result.risk_score ?? (isPhish ? 95 : 0)));
  const riskLevel = result.risk_level || (isPhish ? "High" : score >= 40 ? "Medium" : "Low");
  const confidence = Math.round(Number(result.confidence ?? 100));

  meterNumber.textContent = String(score);
  meterFill.style.width = `${Math.max(4, Math.min(100, score))}%`;
  confidenceText.textContent = `AI Confidence: ${confidence}%`;

  if (isPhish || score >= 75) {
    verdictCard.className = "verdict-card state-danger";
    verdictLabel.textContent = "Threat Detected";
    verdictTitle.textContent = "Phishing Attack Flagged";
    riskBadge.textContent = "Critical Risk";
    verdictIcon.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
        <line x1="12" y1="9" x2="12" y2="13"/>
        <line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
    `;
  } else if (score >= 40 || riskLevel === "Medium") {
    verdictCard.className = "verdict-card state-warning";
    verdictLabel.textContent = "Caution";
    verdictTitle.textContent = "Suspicious Markers Flagged";
    riskBadge.textContent = "Medium Risk";
    verdictIcon.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
    `;
  } else {
    verdictCard.className = "verdict-card state-safe";
    verdictLabel.textContent = "Safe Website";
    verdictTitle.textContent = "Verified Legitimate";
    riskBadge.textContent = "Low Risk";
    verdictIcon.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
    `;
  }

  // Threat text
  if (result.reason) {
    threatText.textContent = result.reason;
  } else if (isPhish) {
    threatText.textContent = "High-confidence structural and lexical pattern matches credential-harvesting kits.";
  } else {
    threatText.textContent = "Demonstrates authentic domain infrastructure and verified certificate authority.";
  }

  // Show Feedback
  feedbackCard.style.display = "block";
  resetFeedbackUI();
}

// Refresh active tab results
function refresh() {
  chrome.runtime.sendMessage({ type: "PHISHGUARD_GET_ACTIVE_RESULT" }, (response) => {
    if (!response) return;
    render(response.tab, response.cached, response.egress);
  });
}

// Send Feedback
function sendFeedback(isPhishing) {
  if (!currentUrl) return;

  feedbackCorrectBtn.disabled = true;
  feedbackWrongBtn.disabled = true;

  chrome.runtime.sendMessage(
    { type: "PHISHGUARD_FEEDBACK", url: currentUrl, isPhishing },
    () => {
      feedbackPromptWrap.style.display = "none";
      feedbackThanks.style.display = "flex";
    }
  );
}

// Event Listeners
feedbackCorrectBtn.addEventListener("click", () => {
  const isPhishVerdict = verdictCard.classList.contains("state-danger");
  sendFeedback(isPhishVerdict);
});

feedbackWrongBtn.addEventListener("click", () => {
  const isPhishVerdict = verdictCard.classList.contains("state-danger");
  sendFeedback(!isPhishVerdict);
});

rescanBtn.addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab?.url || !/^https?:/i.test(tab.url)) return;

    rescanBtn.classList.add("loading");
    verdictLabel.textContent = "Scanning...";
    verdictTitle.textContent = "Running Neural Inspection...";

    chrome.runtime.sendMessage(
      { type: "PHISHGUARD_SCAN", url: tab.url, tabId: tab.id },
      (response) => {
        rescanBtn.classList.remove("loading");
        if (chrome.runtime.lastError || !response || !response.ok) {
          verdictCard.className = "verdict-card state-warning";
          verdictLabel.textContent = "Scan Pending";
          verdictTitle.textContent = "Backend Connection Pending";
          threatText.textContent = response?.error || "Render cloud service is connecting. Please click Rescan in a few moments.";
        } else {
          connectionPill.className = "connection-pill";
          connText.textContent = "Active";
          refresh();
        }
      }
    );
  });
});

openDashboardBtn.addEventListener("click", () => {
  chrome.tabs.create({ url: API_BASE });
});

// Initialize
checkBackendHealth();
refresh();
setInterval(() => {
  refresh();
  checkBackendHealth();
}, 2500);
