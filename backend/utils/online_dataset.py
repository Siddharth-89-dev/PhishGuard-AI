"""
Append-only log of scans that PhishGuard has seen "in the wild" through the
extension, used to grow the training dataset automatically.

Two kinds of rows land here:
  - source="auto"          -> the model scored the URL itself and was very
                               confident (>= AUTO_LABEL_CONFIDENCE). We treat
                               its own prediction as a pseudo-label.
  - source="user_feedback"  -> a human confirmed or corrected a prediction via
                               the extension's "Correct / Wrong" buttons.

user_feedback rows are ground truth and always take priority over auto rows
for the same URL (handled in online_retrain.py), because self-labeling on
the model's own guesses can quietly reinforce the model's own mistakes if
nothing ever corrects it.
"""

import csv
import os
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COLLECTED_PATH = os.path.join(BASE_DIR, "collected_dataset.csv")

FIELDS = ["url", "label", "confidence", "source", "timestamp"]

# Only self-label a scan automatically when the model is at least this sure.
# Below this threshold we still show the user a result, but we don't trust
# it enough to feed back into training without a human confirming it.
AUTO_LABEL_CONFIDENCE = 0.90


def _ensure_file():
    if not os.path.exists(COLLECTED_PATH):
        with open(COLLECTED_PATH, "w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=FIELDS).writeheader()


def record_scan(url: str, label: str, confidence: float, source: str = "auto"):
    """
    label:  "phishing" | "legitimate"
    source: "auto" | "user_feedback"
    """
    _ensure_file()
    with open(COLLECTED_PATH, "a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=FIELDS).writerow({
            "url": url,
            "label": label,
            "confidence": round(float(confidence), 4),
            "source": source,
            "timestamp": int(time.time()),
        })


def pending_count() -> int:
    if not os.path.exists(COLLECTED_PATH):
        return 0
    with open(COLLECTED_PATH, newline="", encoding="utf-8") as f:
        return max(0, sum(1 for _ in f) - 1)  # minus header row
