import os
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import joblib
import numpy as np

from utils.feature_extractor import extract_url_features

app = FastAPI()

# -------- PATH SETUP --------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")

# -------- STATIC FILES (IMPORTANT) --------
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

# -------- LOAD MODEL --------
model = joblib.load(os.path.join(BASE_DIR, "phish_model.pkl"))

# -------- REQUEST MODEL --------
class URLRequest(BaseModel):
    url: str


# -------- ROUTES --------
@app.get("/")
def home():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


@app.get("/product")
def product():
    return FileResponse(os.path.join(FRONTEND_DIR, "product.html"))


# ⚠️ CHANGE THIS (docs conflict)
@app.get("/docs-page")
def docs_page():
    return FileResponse(os.path.join(FRONTEND_DIR, "docs.html"))


@app.get("/contact")
def contact():
    return FileResponse(os.path.join(FRONTEND_DIR, "contact.html"))


# -------- PREDICTION API --------
@app.post("/predict")
def predict_url(data: URLRequest):
    try:
        features = extract_url_features(data.url)
        X = np.array([features])

        prob = model.predict_proba(X)[0][1]
        prediction = "Phishing" if prob >= 0.4 else "Legitimate"

        return {
            "prediction": prediction,
            "risk_score": round(float(prob), 2)
        }

    except Exception as e:
        return {"error": str(e)}