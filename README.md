# 🛡️ PhishGuard AI

An AI-powered phishing website detection system that identifies malicious URLs using Machine Learning and provides real-time security analysis through a web interface.

## 🚀 Overview

Phishing attacks remain one of the most common cybersecurity threats, tricking users into revealing sensitive information through fake websites. Traditional blacklist-based detection systems often fail to detect newly created phishing websites.

PhishGuard AI addresses this problem by leveraging Machine Learning to analyze URL characteristics and classify websites as **Phishing** or **Legitimate** in real time.

---

## ✨ Features

- Real-time URL phishing detection
- Machine Learning-based classification
- FastAPI backend for high-performance API handling
- User-friendly web interface
- Feature extraction from URLs
- Detection of previously unseen phishing URLs
- High accuracy using XGBoost
- Scalable architecture for future enhancements

---

## 🏗️ System Architecture

User URL Input
↓
Feature Extraction
↓
Machine Learning Model (XGBoost)
↓
Prediction Engine
↓
Phishing / Legitimate Result

---

## 🛠️ Tech Stack

### Frontend
- HTML
- CSS
- JavaScript

### Backend
- FastAPI
- Python

### Machine Learning
- Scikit-learn
- XGBoost
- Pandas
- NumPy

### Database
- SQLite (Optional)

### Deployment
- GitHub
- Render (Planned)

---

## 📂 Project Structure

```text
PhishGuard-AI/
│
├── backend/
│   ├── app.py
│   ├── train_model.py
│   ├── feature_extractor.py
│   ├── phishing_dataset.csv
│   └── model/
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── requirements.txt
└── README.md
```















---

## ⚙️ Installation

### Clone Repository

```bash
git clone https://github.com/Siddharth-89-dev/PhishGuard-AI.git
cd PhishGuard-AI
```

### Create Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### ▶️ Running the Backend Server

```bash
cd backend
python -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

* **Web Application UI:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
* **Interactive API Documentation:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **Security Console / Dashboard:** [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)
* **Authentication:** [http://127.0.0.1:8000/login](http://127.0.0.1:8000/login)

---

## 🧩 Browser Extension (Network Chunking Egress Guard)

PhishGuard AI includes a Manifest V3 browser extension with real-time DOM mutation monitoring and client-side credential egress protection:

1. Open Chrome / Edge and navigate to `chrome://extensions`.
2. Enable **Developer mode** (top right toggle).
3. Click **Load unpacked** and select the `extension/` folder.
4. The extension will monitor active tab egress streams and provide inline phishing alerts.

---

## 🧠 Machine Learning & Multi-Tier Workflow

1. **Layer 1:** High-speed cache and domain reputation whitelist.
2. **Layer 2:** XGBoost ML model (30 structural URL features, unskewed www-invariance).
3. **Layer 3:** Real-time WHOIS age auditing and Safe Browsing fallback.
4. **Layer 4:** Client-side DOM mutation observer & Network Chunking egress guard (0.08 ms).
5. **Layer 5:** Backend deep threat telemetry and adaptive feedback retraining.

---

## 📊 Model Features

The XGBoost model analyzes 30 key URL and structural indicators:
* URL length, token entropy, and character distributions
* Domain depth, subdomain count, and multi-TLD patterns
* Lexical keyword presence (login, verify, secure, banking, auth tokens)
* HTTPS certificate consistency and IP-host formatting
* Suspicious Unicode/Punycoding and delimiter counts

---

## 👨‍💻 Author

**Siddharth Sharma**  
*B.Tech Computer Science & Engineering*  
Cybersecurity & Machine Learning Enthusiast  
GitHub: [https://github.com/Siddharth-89-dev](https://github.com/Siddharth-89-dev)

