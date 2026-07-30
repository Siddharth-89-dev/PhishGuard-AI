import pandas as pd
import numpy as np
import joblib
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from utils.feature_extractor import extract_url_features

# Load dataset (CSV version)
df = pd.read_csv("final_phishguard_dataset.csv")

# Convert labels
df["label"] = df["label"].map({
    "legitimate": 0,
    "phishing": 1
})

df = df.dropna()

urls = df["url"]
labels = df["label"]

print("Extracting features...")

# 🔥 ONLY 20 FEATURES
X = np.array([extract_url_features(url) for url in urls])
y = labels.values

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Model
model = XGBClassifier(
    n_estimators=400,
    max_depth=7,
    learning_rate=0.05,
    subsample=0.9,
    colsample_bytree=0.8,
    min_child_weight=2,
    eval_metric="logloss",
    random_state=42
)

model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save
joblib.dump(model, "phish_model.pkl")

print("\nModel saved (20-feature model)")