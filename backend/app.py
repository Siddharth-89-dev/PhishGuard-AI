from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import numpy as np
import joblib
import os

from utils.feature_extractor import extract_url_features

app = FastAPI()

# ---------------- CORS ----------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- PATH SETUP ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")
MODEL_PATH = os.path.join(BASE_DIR, "phish_model.pkl")

# ---------------- STATIC FRONTEND ----------------
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/")
def serve_home():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/product")
def serve_product():
    return FileResponse(os.path.join(FRONTEND_DIR, "product.html"))

@app.get("/docs")
def serve_docs():
    return FileResponse(os.path.join(FRONTEND_DIR, "docs.html"))

@app.get("/contact")
def serve_contact():
    return FileResponse(os.path.join(FRONTEND_DIR, "contact.html"))

# ---------------- LOAD MODEL ----------------
model = joblib.load(MODEL_PATH)

# ---------------- REQUEST SCHEMA ----------------
class URLRequest(BaseModel):
    url: str

# ---------------- PHISHING DETECTION API ----------------
@app.post("/predict")
def predict_url(data: URLRequest):
    features = extract_url_features(data.url)
    X = np.array([features])

    probability = model.predict_proba(X)[0][1]
    prediction = 1 if probability >= 0.35 else 0

    return {
        "url": data.url,
        "prediction": "Phishing" if prediction == 1 else "Legitimate",
        "risk_score": round(float(probability), 2)
    }
