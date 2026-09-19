// PhishGuard AI - Content Script with Apple Liquid Glass Security Capsule & Egress Guard
// Injects sleek floating security capsule bottom-left and observes in-browser network egress

(() => {
  const SKIP_PREFIXES = [
    "chrome://",
    "chrome-extension://",
    "edge://",
    "about:",
    "moz-extension://",
    "https://chrome.google.com/webstore",
  ];
  const BACKEND_HOSTS = ["127.0.0.1:8000", "localhost:8000", "phishguard-ai-6qdq.onrender.com"]; // don't scan backend UI

  const currentUrl = window.location.href;

  if (SKIP_PREFIXES.some((p) => currentUrl.startsWith(p))) return;
  if (BACKEND_HOSTS.includes(window.location.host)) return;

  let dismissed = false;

  // ==========================================
  // 1. INJECT LIQUID GLASS CAPSULE WIDGET
  // ==========================================
  const widget = document.createElement("div");
  widget.id = "phishguard-bunny";
  widget.className = "pg-state-scanning";
  widget.innerHTML = `
    <div class="pg-glow-backdrop"></div>
    <div class="pg-glass-pill">
      <div class="pg-icon-wrap">
        <div class="pg-icon" id="pg-status-icon">
          <svg class="pg-spin-scan" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <circle cx="12" cy="12" r="3"/>
          </svg>
        </div>
      </div>
      <div class="pg-content">
        <div class="pg-top-row">
          <span class="pg-brand-tag">PhishGuard</span>
          <span class="pg-badge-pill" id="pg-badge-status">AI Active</span>
        </div>
        <div class="pg-label">Scanning site&hellip;</div>
        <div class="pg-score" hidden></div>
      </div>
      <button id="pg-close" title="Dismiss" aria-label="Dismiss">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
    </div>
  `;

  const inject = () => {
    if (dismissed || !document.body || document.getElementById("phishguard-bunny")) return;
    document.body.appendChild(widget);
  };

  if (document.body) {
    inject();
  } else {
    document.addEventListener("DOMContentLoaded", inject, { once: true });
  }

  widget.querySelector("#pg-close").addEventListener("click", (e) => {
    e.stopPropagation();
    dismissed = true;
    widget.classList.add("pg-dismissing");
    setTimeout(() => widget.remove(), 320);
  });

  const labelEl = widget.querySelector(".pg-label");
  const scoreEl = widget.querySelector(".pg-score");
  const badgeEl = widget.querySelector("#pg-badge-status");
  const iconEl = widget.querySelector("#pg-status-icon");

  const ICONS = {
    safe: `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <polyline points="9 12 11 14 15 10"/>
      </svg>
    `,
    warning: `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
    `,
    danger: `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
        <line x1="12" y1="9" x2="12" y2="13"/>
        <line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
    `,
    scanning: `
      <svg class="pg-spin-scan" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <circle cx="12" cy="12" r="3"/>
      </svg>
    `,
    error: `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/>
        <line x1="15" y1="9" x2="9" y2="15"/>
        <line x1="9" y1="9" x2="15" y2="15"/>
      </svg>
    `
  };

  function setState(state, text, scoreText, badgeText) {
    widget.className = `pg-state-${state}`;
    labelEl.textContent = text;
    if (scoreText) {
      scoreEl.textContent = scoreText;
      scoreEl.hidden = false;
    } else {
      scoreEl.hidden = true;
    }

    if (badgeEl) {
      badgeEl.textContent = badgeText || (state === "safe" ? "Verified Safe" : state === "danger" ? "Threat Alert" : state === "warning" ? "Caution" : "AI Active");
    }

    if (iconEl && ICONS[state]) {
      iconEl.innerHTML = ICONS[state];
    }
  }

  // ==========================================
  // 2. INITIAL URL SCAN (STAGE 1)
  // ==========================================
  function scanCurrentPage(retried = false) {
    chrome.runtime.sendMessage(
      { type: "PHISHGUARD_SCAN", url: currentUrl },
      (response) => {
        if (dismissed) return;

        if (chrome.runtime.lastError || !response) {
          if (!retried) {
            setTimeout(() => scanCurrentPage(true), 3500);
            return;
          }
          setState("error", "PhishGuard offline", null, "Offline");
          return;
        }

        if (!response.ok) {
          if (!retried) {
            setTimeout(() => scanCurrentPage(true), 3500);
            return;
          }
          const offline = /failed to fetch|networkerror/i.test(response.error || "");
          setState("error", offline ? "Backend offline" : "Scan failed", null, "Error");
          return;
        }

        const { prediction, risk_score, risk_level } = response.result;
        const score = Math.round(Number(risk_score ?? 0));
        const scoreText = `Risk score: ${score}/100`;

        if (prediction === "Phishing" || risk_level === "High") {
          setState("danger", "Phishing threat flagged", scoreText, "Threat Alert");
        } else if (risk_level === "Medium" || score >= 40) {
          setState("warning", "Use caution on this site", scoreText, "Caution");
        } else {
          setState("safe", "Looks safe", scoreText, "Verified Safe");
        }
      }
    );
  }

  scanCurrentPage();

  // ==========================================
  // 3. NETWORK CHUNKING & DATA EGRESS OBSERVER
  // ==========================================
  let totalEgressBytes = 0;
  let outboundRequestsCount = 0;
  let lastKeystrokeTime = 0;
  let keystrokeChunkCount = 0;
  const externalDestinations = new Set();
  const crossOriginRequests = [];

  function hasPasswordField() {
    return !!document.querySelector('input[type="password"]');
  }

  function hasCreditCardField() {
    return !!document.querySelector(
      'input[name*="card" i], input[name*="cvv" i], input[id*="card" i], input[autocomplete*="cc-" i]'
    );
  }

  // Report egress payload to background worker
  function reportEgress(customData = {}) {
    const egressPayload = {
      total_bytes_sent: totalEgressBytes,
      outbound_requests_count: outboundRequestsCount,
      cross_origin_requests: crossOriginRequests.slice(-15),
      has_password_field: hasPasswordField(),
      has_credit_card_field: hasCreditCardField(),
      keystroke_chunking_detected: keystrokeChunkCount >= 3,
      exfiltrated_destinations: Array.from(externalDestinations),
      sensitive_data_transmitted: false,
      ...customData,
    };

    chrome.runtime.sendMessage({
      type: "PHISHGUARD_NETWORK_CHUNK",
      url: currentUrl,
      egress_data: egressPayload,
    }, (resp) => {
      if (resp?.evaluation?.egress_level === "Critical Threat") {
        setState("danger", "🚨 Exfiltration Alert", resp.evaluation.reasons[0] || "Data transmitted off-site", "Exfiltrating");
      }
    });
  }

  // A. Monitor user typing for keystroke micro-chunking
  document.addEventListener("input", (e) => {
    if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") {
      lastKeystrokeTime = performance.now();
    }
  }, true);

  // B. Intercept Form Submissions (Cross-Domain Credential Posts)
  document.addEventListener("submit", (e) => {
    const form = e.target;
    let actionUrl;
    try {
      actionUrl = new URL(form.action || window.location.href, window.location.href);
    } catch {
      actionUrl = new URL(window.location.href);
    }

    const currentHost = window.location.hostname.toLowerCase();
    const targetHost = (actionUrl.hostname || "").toLowerCase();
    const hasPassword = hasPasswordField();
    const hasCard = hasCreditCardField();

    const isCrossOrigin = targetHost && targetHost !== currentHost && !targetHost.endsWith("." + currentHost);

    if (isCrossOrigin) {
      console.warn("[PhishGuard] Form submitted across origins to:", targetHost);
      const isSensitive = hasPassword || hasCard;

      reportEgress({
        total_bytes_sent: totalEgressBytes + 512,
        cross_origin_requests: [{
          destination_host: targetHost,
          method: (form.method || "POST").toUpperCase(),
          has_credentials: isSensitive,
          destination_url: actionUrl.href,
        }],
        sensitive_data_transmitted: isSensitive,
        exfiltrated_destinations: [targetHost],
      });

      if (isSensitive) {
        setState("danger", "🚨 Exfiltration Alert", `Credentials sent to ${targetHost}`, "Exfiltrating");
      }
    }
  }, true);

  // C. Browser Resource & Network Performance Observer
  if (window.PerformanceObserver) {
    try {
      const observer = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (entry.entryType === "resource") {
            try {
              const reqUrl = new URL(entry.name);
              const destHost = reqUrl.hostname.toLowerCase();
              const currentHost = window.location.hostname.toLowerCase();

              const bytes = entry.transferSize || entry.encodedBodySize || 150;
              totalEgressBytes += bytes;
              outboundRequestsCount++;

              // Check keystroke chunking: small packet fired right after keystrokes to external host
              const timeSinceKey = performance.now() - lastKeystrokeTime;
              if (timeSinceKey < 900 && bytes < 1200 && destHost !== currentHost) {
                keystrokeChunkCount++;
              }

              if (destHost && destHost !== currentHost && !destHost.endsWith("." + currentHost)) {
                externalDestinations.add(destHost);
                if (crossOriginRequests.length < 30) {
                  crossOriginRequests.push({
                    destination_host: destHost,
                    method: entry.initiatorType || "fetch",
                    bytes: bytes,
                    destination_url: entry.name,
                  });
                }
              }
            } catch (_) {}
          }
        }
      });
      observer.observe({ entryTypes: ["resource"] });
    } catch (_) {}
  }

  // D. Periodic Sync (Every 4.5 seconds)
  setInterval(() => {
    if (outboundRequestsCount > 0 || crossOriginRequests.length > 0 || hasPasswordField()) {
      reportEgress();
    }
  }, 4500);

})();
