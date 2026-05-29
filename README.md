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
PhishGuard-AI/
│
├── backend/
│ ├── app.py
│ ├── train_model.py
│ ├── feature_extractor.py
│ ├── phishing_dataset.csv
│ └── model/
│
├── frontend/
│ ├── index.html
│ ├── style.css
│ └── script.js
│
├── requirements.txt
└── README.md


---

## ⚙️ Installation

### Clone Repository

```bash
git clone https://github.com/Siddharth-89-dev/PhishGuard-AI.git
cd PhishGuard-AI
```
Create Virtual Environment
python -m venv venv
Activate Environment

Windows:

venv\Scripts\activate

Linux/Mac:

source venv/bin/activate
Install Dependencies
pip install -r requirements.txt
▶️ Running the Backend

Navigate to backend directory:

cd backend

Start FastAPI server:

uvicorn app:app --reload

Server will be available at:

http://127.0.0.1:8000

API Documentation:

http://127.0.0.1:8000/docs
🧠 Machine Learning Workflow
Collect phishing and legitimate URL datasets.
Preprocess and clean data.
Extract URL-based features.
Train multiple ML models.
Evaluate performance metrics.
Select XGBoost as the final model.
Deploy model through FastAPI.
📊 Model Features

The model analyzes features such as:

URL Length
Number of Dots
Presence of HTTPS
Number of Subdomains
Suspicious Keywords
Special Characters
Domain Structure
🎯 Future Enhancements
Browser Extension Integration
Email Phishing Detection
Domain Reputation Analysis
WHOIS Information Lookup
Deep Learning-Based Detection
Real-Time Threat Intelligence Integration
📈 Project Objectives

The primary objective of PhishGuard AI is to provide an intelligent and proactive phishing detection system capable of identifying malicious websites before users become victims of cyberattacks.

👨‍💻 Author

Siddharth Sharma

B.Tech Computer Science & Engineering

Cybersecurity & Machine Learning Enthusiast

GitHub: https://github.com/Siddharth-89-dev
