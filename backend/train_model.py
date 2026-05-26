import pandas as pd
import numpy as np
import joblib
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from utils.feature_extractor import extract_url_features

# Load dataset (CSV version)
df = pd.read_csv("phishing_dataset.csv")

# Convert labels
df["label"] = df["label"].map({
    "legitimate": 0,
    "phishing": 1
})

df = df.dropna()

urls = df["url"]
labels = df["label"]

print("Extracting features...")

# 🔥 ONLY 7 FEATURES
X = np.array([extract_url_features(url) for url in urls])
y = labels.values

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Model
model = XGBClassifier(
    n_estimators=200,
    max_depth=5,
    learning_rate=0.1,
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

print("\nModel saved (7-feature model)")