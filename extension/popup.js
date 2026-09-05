const hostEl = document.getElementById("pg-popup-host");
const statusEl = document.getElementById("pg-popup-status");
const rescanBtn = document.getElementById("pg-rescan");

const feedbackEl = document.getElementById("pg-feedback");
const feedbackPromptEl = document.getElementById("pg-feedback-prompt");
const feedbackButtonsEl = document.getElementById("pg-feedback-buttons");
const feedbackCorrectBtn = document.getElementById("pg-feedback-correct");
const feedbackWrongBtn = document.getElementById("pg-feedback-wrong");
const feedbackThanksEl = document.getElementById("pg-feedback-thanks");

let currentUrl = null;

function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch (_) {
    return url || "";
  }
}

function resetFeedbackUI() {
  feedbackButtonsEl.style.display = "flex";
  feedbackPromptEl.classList.remove("pg-visible");
  feedbackThanksEl.classList.remove("pg-visible");
  feedbackCorrectBtn.disabled = false;
  feedbackWrongBtn.disabled = false;
}

function render(tab, cached) {
  hostEl.textContent = tab?.url ? hostnameOf(tab.url) : "";

  if (!tab || !tab.url || !/^https?:/i.test(tab.url)) {
    statusEl.textContent = "Nothing to scan on this tab.";
    statusEl.className = "";
    feedbackEl.classList.remove("pg-visible");
    currentUrl = null;
    return;
  }

  if (!cached || cached.url !== tab.url) {
    statusEl.textContent = "Not scanned yet.";
    statusEl.className = "";
    feedbackEl.classList.remove("pg-visible");
    currentUrl = null;
    return;
  }

  const { prediction, risk_score, risk_level } = cached.result;
  const score = Math.round(Number(risk_score ?? 0));
  statusEl.textContent = `${prediction} — ${score}/100 (${risk_level} risk)`;
  statusEl.className =
    prediction === "Phishing" ? "danger" : risk_level === "Medium" ? "warning" : "safe";

  // Let the user confirm or correct the verdict — this feedback is what
  // actually teaches the model, since the backend only self-labels scans
  // it's already very confident about.
  currentUrl = tab.url;
  resetFeedbackUI();
  feedbackPromptEl.classList.add("pg-visible");
  feedbackEl.classList.add("pg-visible");
}

function refresh() {
  chrome.runtime.sendMessage({ type: "PHISHGUARD_GET_ACTIVE_RESULT" }, (response) => {
    if (!response) return;
    render(response.tab, response.cached);
  });
}

function sendFeedback(isPhishing) {
  if (!currentUrl) return;

  feedbackCorrectBtn.disabled = true;
  feedbackWrongBtn.disabled = true;

  chrome.runtime.sendMessage(
    { type: "PHISHGUARD_FEEDBACK", url: currentUrl, isPhishing },
    () => {
      feedbackButtonsEl.style.display = "none";
      feedbackPromptEl.classList.remove("pg-visible");
      feedbackThanksEl.classList.add("pg-visible");
    }
  );
}

feedbackCorrectBtn.addEventListener("click", () => {
  // "Correct" means: yes, the shown prediction was right.
  const wasPhishing = statusEl.textContent.startsWith("Phishing");
  sendFeedback(wasPhishing);
});

feedbackWrongBtn.addEventListener("click", () => {
  // "Wrong" means: flip whatever the model said.
  const wasPhishing = statusEl.textContent.startsWith("Phishing");
  sendFeedback(!wasPhishing);
});

rescanBtn.addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab?.url || !/^https?:/i.test(tab.url)) return;

    statusEl.textContent = "Scanning…";
    statusEl.className = "";
    feedbackEl.classList.remove("pg-visible");

    chrome.runtime.sendMessage(
      { type: "PHISHGUARD_SCAN", url: tab.url, tabId: tab.id },
      () => refresh()
    );
  });
});

refresh();
