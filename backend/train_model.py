import pandas as pd
import numpy as np
import joblib
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from utils.feature_extractor import extract_url_features

# Load dataset
df = pd.read_csv("raw_data.csv")  # <-- change filename if needed

# Convert labels to numeric
df["label"] = df["label"].map({
    "legitimate": 0,
    "phishing": 1
})

# Drop missing rows
df = df.dropna()

urls = df["url"]
labels = df["label"]

print("Extracting features...")

# Extract features
X = [extract_url_features(url) for url in urls]
y = labels

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# XGBoost Model
model = XGBClassifier(
    n_estimators=300,
    learning_rate=0.1,
    max_depth=6,
    scale_pos_weight=1,
    use_label_encoder=False,
    eval_metric='logloss',
    random_state=42
)

model.fit(X_train, y_train)
probability = model.predict_proba(X)[0][1]
prediction = 1 if probability >= 0.35 else 0

# Evaluate
y_pred = model.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save model
joblib.dump(model, "phish_model.pkl")

print("\nModel trained and saved successfully.")