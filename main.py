from fastapi import FastAPI
from pydantic import BaseModel
import re
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# --- LAYER 2: Feature Extraction ---
def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_at_symbols'] = url.count('@')
    features['num_underscores'] = url.count('_')
    
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features['has_ip_address'] = 1 if re.search(ip_pattern, url) else 0
    
    suspicious_words = ['login', 'secure', 'verify', 'update', 'bank', 'account', 'confirm']
    url_lower = url.lower()
    features['suspicious_word_count'] = sum(1 for word in suspicious_words if word in url_lower)
    
    features['uses_https'] = 1 if url.startswith('https://') else 0
    return features

# --- LAYER 3: Model Inference (Trains on startup for this demo) ---
def train_model():
    np.random.seed(42)
    safe_data = {
        'url_length': np.random.randint(15, 40, 1000), 'num_dots': np.random.randint(1, 3, 1000),
        'num_hyphens': np.random.randint(0, 1, 1000), 'num_at_symbols': np.zeros(1000),
        'num_underscores': np.zeros(1000), 'has_ip_address': np.zeros(1000),
        'suspicious_word_count': np.random.randint(0, 1, 1000), 'uses_https': np.ones(1000),
        'is_phishing': np.zeros(1000)
    }
    phishing_data = {
        'url_length': np.random.randint(40, 80, 1000), 'num_dots': np.random.randint(3, 6, 1000),
        'num_hyphens': np.random.randint(1, 4, 1000), 'num_at_symbols': np.random.randint(0, 2, 1000),
        'num_underscores': np.random.randint(0, 2, 1000), 'has_ip_address': np.random.randint(0, 2, 1000),
        'suspicious_word_count': np.random.randint(1, 4, 1000), 'uses_https': np.random.randint(0, 2, 1000),
        'is_phishing': np.ones(1000)
    }
    df = pd.concat([pd.DataFrame(safe_data), pd.DataFrame(phishing_data)]).sample(frac=1).reset_index(drop=True)
    feature_cols = ['url_length', 'num_dots', 'num_hyphens', 'num_at_symbols', 'num_underscores', 'has_ip_address', 'suspicious_word_count', 'uses_https']
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(df[feature_cols], df['is_phishing'])
    return model

# Load the model when the app starts
rf_model = train_model()

# --- LAYER 4: Response Layer ---
def generate_response(url, features, score):
    level = "PHISHING" if score >= 0.8 else ("SUSPICIOUS" if score >= 0.5 else "SAFE")
    summary = "High probability of phishing detected." if score >= 0.8 else ("Moderate risk detected." if score >= 0.5 else "No significant phishing indicators found.")
    
    risk_factors = []
    if features['has_ip_address'] == 1: risk_factors.append("URL uses an IP address instead of a valid domain name.")
    if features['uses_https'] == 0: risk_factors.append("Connection is not secure (missing HTTPS).")
    if features['suspicious_word_count'] >= 2: risk_factors.append(f"Contains {features['suspicious_word_count']} suspicious keywords.")
    if features['num_hyphens'] >= 2: risk_factors.append("Excessive use of hyphens.")
    if not risk_factors: risk_factors.append("URL follows standard, safe formatting.")
    
    return {"status": "success", "data": {"url": url, "score": score, "level": level, "explanation": {"summary": summary, "top_risk_factors": risk_factors}}}

# --- LAYER 1: Client Layer (API Gateway) ---
app = FastAPI(title="CloudPhish API", description="4-Layer Phishing Detection System")

class ScanRequest(BaseModel):
    url: str

@app.post("/api/v1/scan")
async def scan_url(request: ScanRequest):
    # Layer 2
    features = extract_features(request.url)
    # Layer 3
    features_df = pd.DataFrame([features])
    score = round(rf_model.predict_proba(features_df)[0][1], 4)
    # Layer 4
    return generate_response(request.url, features, score)
