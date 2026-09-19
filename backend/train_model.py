import os
import re
import shutil
import joblib
import pandas as pd
import numpy as np
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from xgboost import XGBClassifier
from joblib import Parallel, delayed

from utils.feature_extractor import extract_url_features
from utils.whitelist import is_whitelisted

DATASET = os.path.join(os.path.dirname(__file__), "final_phishguard_dataset.csv")
MODEL = os.path.join(os.path.dirname(__file__), "phish_model.pkl")
ORIG_MODEL = os.path.join(os.path.dirname(__file__), "phish_model.pkl.orig")

def find_column(df, candidates):
    lower = {str(c).strip().lower(): c for c in df.columns}
    for c in candidates:
        if c in lower:
            return lower[c]
    return None

def normalize_label(value):
    s = str(value).strip().lower()
    if s in {"1", "phishing", "phish", "malicious", "bad", "fraud"}:
        return 1
    if s in {"0", "legitimate", "legit", "benign", "safe", "good"}:
        return 0
    try:
        return 1 if float(s) == 1 else 0
    except Exception:
        return None

def train():
    # Backup original model if not yet backed up
    if os.path.exists(MODEL) and not os.path.exists(ORIG_MODEL):
        shutil.copy(MODEL, ORIG_MODEL)
        print(f"Backed up original model to: {ORIG_MODEL}")

    df = pd.read_csv(DATASET)

    url_col = find_column(df, ["url", "urls", "link", "uri", "domain"])
    label_col = find_column(df, ["label", "labels", "class", "type", "status", "target"])

    if not url_col or not label_col:
        raise ValueError(f"Could not detect URL/label columns. Columns: {list(df.columns)}")

    df = df[[url_col, label_col]].rename(columns={url_col: "url", label_col: "label"})
    df["url"] = df["url"].astype(str).str.strip()
    df["label"] = df["label"].map(normalize_label)
    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)

    # Remove duplicate URLs.
    df = df.drop_duplicates(subset=["url"])

    # Correct only the obvious dataset contradiction:
    # an exact trusted root/domain URL must be legitimate.
    trusted = df["url"].map(is_whitelisted)
    df.loc[trusted, "label"] = 0

    # Remove invalid/empty URLs.
    df = df[df["url"].str.len() > 3]

    # Prevent dataset bias where legitimate sites were crawled with "www."
    # but real-world users browse without "www." (e.g. example.com).
    www_mask = df["url"].str.contains("://www.", regex=False)
    if www_mask.any():
        df_no_www = df[www_mask].copy()
        df_no_www["url"] = df_no_www["url"].str.replace("://www.", "://", regex=False)
        df = pd.concat([df, df_no_www]).drop_duplicates(subset=["url"])

    print("Dataset after cleaning:", len(df))
    print(df["label"].value_counts().sort_index())

    print("Extracting features in parallel across available CPU cores...")
    feature_list = Parallel(n_jobs=-1, batch_size=500)(
        delayed(extract_url_features)(u) for u in df["url"]
    )
    X = np.array(feature_list, dtype=np.float32)
    y = df["label"].to_numpy()

    print(f"Feature matrix shape: {X.shape}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    model = XGBClassifier(
        n_estimators=500,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.85,
        colsample_bytree=0.85,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1
    )

    print("Training XGBoost classifier...")
    model.fit(X_train, y_train)

    pred = model.predict(X_test)
    prob = model.predict_proba(X_test)[:, 1]

    print("\nClassification report:")
    print(classification_report(y_test, pred, digits=4))
    print("ROC-AUC:", round(roc_auc_score(y_test, prob), 4))
    print("\nConfusion matrix:")
    print(confusion_matrix(y_test, pred))

    joblib.dump(model, MODEL)
    print(f"\nSaved model: {MODEL}")

if __name__ == "__main__":
    train()
