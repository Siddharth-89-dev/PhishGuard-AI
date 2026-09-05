"""
Fold newly collected scans (auto-labeled + user feedback) into
final_phishguard_dataset.csv and retrain phish_model.pkl.

This is run automatically by app.py in a background thread once enough new
scans have piled up (see MIN_NEW_ROWS below) — it is deliberately NOT run
on every single request, because retraining a 500-tree XGBoost model on the
full dataset takes real time and a single bad or adversarial sample
shouldn't be able to move the model on its own.

Can also be run by hand / from a cron job:
    cd backend && python online_retrain.py
"""

import os
import shutil

import numpy as np
import pandas as pd
from xgboost import XGBClassifier

from utils.feature_extractor import extract_url_features
from utils.whitelist import is_whitelisted

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAIN_DATASET = os.path.join(BASE_DIR, "final_phishguard_dataset.csv")
COLLECTED = os.path.join(BASE_DIR, "collected_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "phish_model.pkl")
ARCHIVE_DIR = os.path.join(BASE_DIR, "collected_archive")

# Don't bother retraining for a handful of scans - wait for a real batch.
MIN_NEW_ROWS = 25


def _load_collected() -> pd.DataFrame:
    if not os.path.exists(COLLECTED):
        return pd.DataFrame(columns=["url", "label", "confidence", "source", "timestamp"])
    return pd.read_csv(COLLECTED)


def run() -> bool:
    """Returns True if a retrain actually happened."""
    collected = _load_collected()
    if len(collected) < MIN_NEW_ROWS:
        print(f"Only {len(collected)} new samples collected (< {MIN_NEW_ROWS}). Skipping retrain.")
        return False

    # user_feedback is ground truth and wins over the model's own auto-labeled
    # guesses when the same URL shows up in both.
    collected = collected.sort_values(
        "source", key=lambda s: s.map({"user_feedback": 1, "auto": 0}).fillna(0)
    )
    collected = collected.drop_duplicates(subset="url", keep="last")
    collected["label"] = collected["label"].map({"phishing": 1, "legitimate": 0})

    main_df = pd.read_csv(MAIN_DATASET)
    main_df["label"] = main_df["label"].map(
        lambda v: 1 if str(v).strip().lower() in {"1", "phishing"} else 0
    )

    merged = pd.concat([main_df[["url", "label"]], collected[["url", "label"]]], ignore_index=True)
    merged["url"] = merged["url"].astype(str).str.strip()
    merged = merged.drop_duplicates(subset="url", keep="last")

    # Same safety net train_model.py uses: known-trusted domains are never
    # allowed to sit in the dataset labeled as phishing.
    trusted = merged["url"].map(is_whitelisted)
    merged.loc[trusted, "label"] = 0

    print(f"Training set: {len(main_df)} existing + {len(collected)} newly collected "
          f"-> {len(merged)} unique rows after merge")

    X = np.array([extract_url_features(u) for u in merged["url"]], dtype=np.float32)
    y = merged["label"].to_numpy()

    model = XGBClassifier(
        n_estimators=500,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.85,
        colsample_bytree=0.85,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X, y)

    # Back up the previous model before overwriting it, so a bad batch of
    # feedback can be rolled back by restoring phish_model.pkl.bak.
    if os.path.exists(MODEL_PATH):
        shutil.copy(MODEL_PATH, MODEL_PATH + ".bak")

    import joblib
    joblib.dump(model, MODEL_PATH)

    merged_out = merged.copy()
    merged_out["label"] = merged_out["label"].map({1: "phishing", 0: "legitimate"})
    merged_out.to_csv(MAIN_DATASET, index=False)

    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    archive_path = os.path.join(ARCHIVE_DIR, f"collected_{pd.Timestamp.now():%Y%m%d_%H%M%S}.csv")
    shutil.move(COLLECTED, archive_path)

    print(f"Retrained model saved to {MODEL_PATH}")
    print(f"Dataset grown to {len(merged_out)} rows; collected log archived to {archive_path}")
    return True


if __name__ == "__main__":
    run()
