import os
import re
import hmac
import hashlib
import base64
import json
import secrets
import subprocess
import sys
import threading

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlparse
from pydantic import BaseModel
import joblib
import numpy as np

from typing import Optional
from utils.whitelist import is_whitelisted
from utils.feature_extractor import extract_url_features, extract_url_features_dict
from utils.safe_browsing import check_safe_browsing
from utils.domain_age import domain_age_days
from utils.adaptive_whitelist import register_feedback
from utils.online_dataset import record_scan, pending_count, AUTO_LABEL_CONFIDENCE
from utils.network_analyzer import evaluate_network_egress
from online_retrain import MIN_NEW_ROWS

app = FastAPI(title="PhishGuard AI")

# =========================
# CORS
# =========================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# PATH SETUP
# =========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))

# =========================
# AUTHENTICATION
# =========================
AUTH_SECRET = os.getenv("PHISHGUARD_AUTH_SECRET", "change-this-secret-before-production")
DEMO_EMAIL = os.getenv("PHISHGUARD_DEMO_EMAIL", "admin@phishguard.ai")
DEMO_PASSWORD = os.getenv("PHISHGUARD_DEMO_PASSWORD", "PhishGuard@123")


class LoginRequest(BaseModel):
    email: str
    password: str


def create_token(email: str) -> str:
    payload = {"email": email, "nonce": secrets.token_hex(8)}
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(payload_bytes).decode()
    signature = hmac.new(AUTH_SECRET.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def verify_token(token: str):
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac.new(AUTH_SECRET.encode(), encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(encoded.encode()))
        return payload
    except Exception:
        return None


@app.post("/auth/login")
def login(data: LoginRequest):
    email = data.email.strip()
    password = data.password.strip()

    is_demo_admin = (
        email.lower() == DEMO_EMAIL.lower() and 
        (hmac.compare_digest(password, DEMO_PASSWORD) or password == DEMO_PASSWORD)
    )
    is_valid_demo = ("@" in email and "." in email and len(password) >= 6)

    if not (is_demo_admin or is_valid_demo):
        raise HTTPException(
            status_code=401, 
            detail="Invalid credentials. Use admin@phishguard.ai / PhishGuard@123 or any valid email with 6+ characters password."
        )

    token = create_token(email)
    user_info = {
        "email": email,
        "name": "Security Admin" if is_demo_admin else email.split("@")[0].replace(".", " ").title(),
        "role": "Administrator" if is_demo_admin else "Security Analyst",
        "plan": "Enterprise Pro" if is_demo_admin else "Professional Tier"
    }
    return {"success": True, "token": token, "user": user_info}


@app.get("/auth/me")
def auth_me(token: str):
    user = verify_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return {"authenticated": True, "user": user}


# =========================
# MODEL
# =========================
MODEL_PATH = os.path.join(BASE_DIR, "phish_model.pkl")
model = joblib.load(MODEL_PATH)


class URLRequest(BaseModel):
    url: str
    network_telemetry: Optional[dict] = None


class NetworkEgressRequest(BaseModel):
    url: str
    tab_id: Optional[int] = None
    egress_data: dict


# =========================
# ONLINE LEARNING
# =========================
# Every scan the extension makes gets logged (see record_scan calls below).
# Once enough new scans have piled up, we retrain in a background thread and
# hot-swap the model in memory — so the model keeps learning from real
# traffic without any manual step, and without blocking live predictions
# while it retrains.
_retrain_lock = threading.Lock()
_retraining = False


def _maybe_trigger_retrain():
    global _retraining, model

    with _retrain_lock:
        if _retraining:
            return
        if pending_count() < MIN_NEW_ROWS:
            return
        _retraining = True

    def _run():
        global _retraining, model
        try:
            result = subprocess.run(
                [sys.executable, "online_retrain.py"],
                cwd=BASE_DIR,
                capture_output=True,
                text=True,
            )
            print(result.stdout)
            if result.returncode == 0:
                model = joblib.load(MODEL_PATH)  # hot-reload the freshly retrained model
                print("PhishGuard: retrained model loaded.")
            else:
                print("PhishGuard: retrain failed:", result.stderr)
        finally:
            with _retrain_lock:
                _retraining = False

    threading.Thread(target=_run, daemon=True).start()


def is_valid_url(url: str) -> bool:
    if not url or not isinstance(url, str):
        return False
    clean = url.strip()
    if not clean or any(c.isspace() for c in clean):
        return False
    to_parse = clean if "://" in clean else f"https://{clean}"
    try:
        parsed = urlparse(to_parse)
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        if host == "localhost":
            return True
        ipv4_match = re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host)
        if ipv4_match:
            parts = [int(p) for p in host.split(".")]
            return all(0 <= p <= 255 for p in parts)
        if host.startswith("[") and host.endswith("]"):
            return True
        domain_pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
        return bool(re.match(domain_pattern, host))
    except Exception:
        return False


@app.post("/predict")
def predict_url(data: URLRequest):
    url = (data.url or "").strip()

    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    if not is_valid_url(url):
        raise HTTPException(
            status_code=400,
            detail="Invalid URL format: Please enter a valid website link or domain (e.g., https://example.com or domain.com)",
        )

    # Layer 1: Whitelist (Static + Adaptive)
    if is_whitelisted(url):
        return {
            "prediction": "Legitimate",
            "risk_score": 0.0,
            "confidence": 100.0,
            "risk_level": "Low",
            "reason": "Trusted domain (Whitelist)",
        }

    # Layer 2: Google Safe Browsing threat intelligence
    try:
        sb_match = check_safe_browsing(url)
        if sb_match is True:
            return {
                "prediction": "Phishing",
                "risk_score": 100.0,
                "confidence": 100.0,
                "risk_level": "High",
                "reason": "Identified as malicious by Google Safe Browsing",
            }
    except Exception as e:
        print(f"PhishGuard: Safe Browsing check error: {e}")

    # Layer 3: Feature Extraction & Machine Learning
    try:
        feat_dict = extract_url_features_dict(url)
        features = list(feat_dict.values())
        X = np.array([features], dtype=np.float32)
        prob = float(model.predict_proba(X)[0][1])

        # Layer 4: Real-time Heuristics & Additive Threat Intelligence
        reason = None

        # 4A: Brand Masquerading (e.g. paypal.com.attacker.xyz)
        if feat_dict.get("brand_spoofing") == 1:
            prob = max(prob, 0.85)
            reason = "Brand impersonation detected in URL"

        # 4B: WHOIS Domain Age
        try:
            norm = url if "://" in url else "https://" + url
            host = (urlparse(norm).hostname or "").lower()
            if host.startswith("www."):
                host = host[4:]
            age = domain_age_days(host)
            if age is not None and age < 30:
                prob = min(1.0, prob + 0.25)
                if not reason:
                    reason = f"Newly registered domain ({age} days old)"
        except Exception as e:
            print(f"PhishGuard: domain_age check error: {e}")

        # 4C: Dynamic Browser Egress & Network Payload Chunking
        network_eval = None
        if data.network_telemetry:
            try:
                network_eval = evaluate_network_egress(url, data.network_telemetry)
                egress_penalty = network_eval.get("egress_risk_penalty", 0.0)
                if egress_penalty > 0:
                    prob = min(1.0, prob + egress_penalty)
                    if network_eval.get("reasons"):
                        egress_reason = network_eval["reasons"][0]
                        reason = f"{reason} | {egress_reason}" if reason else egress_reason
            except Exception as e:
                print(f"PhishGuard: network_telemetry check error: {e}")

        # Final verdict determination
        prediction = "Phishing" if prob >= 0.40 else "Legitimate"
        confidence = max(prob, 1.0 - prob)

        # Auto-learning (gated to non-whitelisted URLs)
        if confidence >= AUTO_LABEL_CONFIDENCE and not is_whitelisted(url):
            record_scan(
                url,
                "phishing" if prediction == "Phishing" else "legitimate",
                confidence,
                source="auto",
            )
            _maybe_trigger_retrain()

        response = {
            "prediction": prediction,
            "risk_score": round(prob * 100, 2),
            "confidence": round(confidence * 100, 2),
            "risk_level": "High" if prob >= 0.80 else "Medium" if prob >= 0.40 else "Low",
        }
        if reason:
            response["reason"] = reason
        if network_eval:
            response["network_telemetry"] = network_eval
            response["network_egress"] = network_eval
        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Feature extraction/prediction failed: {e}")


@app.post("/telemetry/network-egress")
def analyze_egress(data: NetworkEgressRequest):
    """
    Receives real-time browser network chunking and data egress telemetry
    from the Chrome extension or headless analyzer.
    """
    url = (data.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    evaluation = evaluate_network_egress(url, data.egress_data)
    return {
        "success": True,
        "url": url,
        "tab_id": data.tab_id,
        "evaluation": evaluation
    }


class FeedbackRequest(BaseModel):
    url: str
    is_phishing: bool  # the user's confirmed/corrected verdict for this URL


@app.post("/feedback")
def submit_feedback(data: FeedbackRequest):
    url = (data.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    if not is_valid_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL format: Please provide a valid website link or domain")

    # Update adaptive whitelist (promotes domain after multiple uncontested confirmations)
    try:
        register_feedback(url, data.is_phishing)
    except Exception as e:
        print(f"PhishGuard: adaptive whitelist update error: {e}")

    record_scan(
        url,
        "phishing" if data.is_phishing else "legitimate",
        confidence=1.0,
        source="user_feedback",
    )
    _maybe_trigger_retrain()

    return {"success": True, "message": "Thanks — this will be folded into the next training pass."}


# =========================
# HEALTH CHECK (useful for Render/uptime monitors)
# =========================
@app.get("/health")
@app.head("/health")
def health():
    return {"status": "ok"}


# =========================
# STATIC ASSETS (css/js) — mounted at a dedicated prefix
# so page routes below never collide with it
# =========================
app.mount("/assets", StaticFiles(directory=FRONTEND_DIR), name="assets")

@app.get("/style.css")
def get_style():
    return FileResponse(os.path.join(FRONTEND_DIR, "style.css"), media_type="text/css")

@app.get("/script.js")
def get_script():
    return FileResponse(os.path.join(FRONTEND_DIR, "script.js"), media_type="application/javascript")

@app.get("/favicon.ico")
@app.get("/favicon.png")
def get_favicon():
    fav = os.path.join(FRONTEND_DIR, "favicon.png")
    return FileResponse(fav, media_type="image/png")

@app.get("/logo.png")
@app.get("/logo_trans.png")
def get_logo():
    logo = os.path.join(FRONTEND_DIR, "logo_trans.png")
    return FileResponse(logo, media_type="image/png")


# =========================
# PAGE ROUTES (clean, consistent URLs)
# =========================
@app.get("/")
@app.head("/")
def home():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


@app.get("/login")
def login_page():
    return FileResponse(os.path.join(FRONTEND_DIR, "login.html"))


@app.get("/dashboard")
def dashboard_page():
    return FileResponse(os.path.join(FRONTEND_DIR, "dashboard.html"))
