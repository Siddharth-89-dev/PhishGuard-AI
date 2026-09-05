// PhishGuard AI - content script
// Injects a small "bunny" scan widget bottom-left on every page and asks
// the background worker to score the current URL against the backend.

(() => {
  const SKIP_PREFIXES = [
    "chrome://",
    "chrome-extension://",
    "edge://",
    "about:",
    "moz-extension://",
    "https://chrome.google.com/webstore",
  ];
  const BACKEND_HOST = "127.0.0.1:8000"; // don't scan the backend's own web UI

  const currentUrl = window.location.href;

  if (SKIP_PREFIXES.some((p) => currentUrl.startsWith(p))) return;
  if (window.location.host === BACKEND_HOST) return;

  let dismissed = false;

  const widget = document.createElement("div");
  widget.id = "phishguard-bunny";
  widget.className = "pg-state-scanning";
  widget.innerHTML = `
    <button id="pg-close" title="Dismiss" aria-label="Dismiss">&times;</button>
    <div class="pg-icon">🐰</div>
    <div class="pg-text">
      <div class="pg-label">Scanning site&hellip;</div>
      <div class="pg-score" hidden></div>
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

  widget.querySelector("#pg-close").addEventListener("click", () => {
    dismissed = true;
    widget.remove();
  });

  const labelEl = widget.querySelector(".pg-label");
  const scoreEl = widget.querySelector(".pg-score");

  function setState(state, text, scoreText) {
    widget.className = `pg-state-${state}`;
    labelEl.textContent = text;
    if (scoreText) {
      scoreEl.textContent = scoreText;
      scoreEl.hidden = false;
    } else {
      scoreEl.hidden = true;
    }
  }

  chrome.runtime.sendMessage(
    { type: "PHISHGUARD_SCAN", url: currentUrl },
    (response) => {
      if (dismissed) return;

      if (chrome.runtime.lastError || !response) {
        setState("error", "PhishGuard unavailable");
        return;
      }

      if (!response.ok) {
        const offline = /failed to fetch|networkerror/i.test(response.error || "");
        setState("error", offline ? "Backend offline" : "Scan failed");
        return;
      }

      const { prediction, risk_score, risk_level } = response.result;
      const score = Math.round(Number(risk_score ?? 0));
      const scoreText = `Risk score: ${score}/100`;

      if (prediction === "Phishing" || risk_level === "High") {
        setState("danger", "⚠ Phishing risk", scoreText);
      } else if (risk_level === "Medium") {
        setState("warning", "Use caution", scoreText);
      } else {
        setState("safe", "Looks safe", scoreText);
      }
    }
  );
})();
