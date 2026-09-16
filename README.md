# 🛡️ CloudPhish

**CloudPhish** is a scalable, cloud-hosted microservice architecture designed for real-time phishing URL detection. By analyzing lexical and host-based URL features, it provides ultra-low latency predictions without the need to download or parse web page content. 

The system is powered by a **Random Forest Classifier** and is strictly designed around a 4-layer architectural model.

![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)

---

## 🏗️ System Architecture

CloudPhish is built on a strict 4-layer architecture to ensure separation of concerns, scalability, and maintainability.

### The 4 Layers
1. **Client Layer:** Entry points (Browser extensions, Mobile apps, Email gateways) that intercept URLs and send them to the cloud API.
2. **Feature Extraction Layer:** Parses raw URLs and extracts numerical features (length, entropy, IP presence, suspicious TLDs, etc.).
3. **Model Inference Layer:** The core engine hosting the pre-trained Random Forest Classifier on cloud compute (e.g., AWS SageMaker, GCP Vertex AI, or containerized FastAPI).
4. **Response Layer:** Translates raw model probabilities into actionable verdicts (`SAFE`, `SUSPICIOUS`, `PHISHING`) and generates human-readable explanations using SHAP values.

---

## 📂 Repository Structure

```text
CloudPhish/
├── client_layer/             # Mock clients, browser extension boilerplate, API wrappers
├── feature_extraction_layer/ # URL parsing, regex, and numeric feature engineering
├── model_inference_layer/    # Random Forest model loading, SHAP explainer, prediction logic
├── response_layer/           # Threshold mapping, JSON formatting, explanation generation
├── training/                 # Scripts to train, evaluate, and export the Random Forest model
├── infrastructure/           # Dockerfiles, Terraform/CloudFormation scripts, CI/CD pipelines
├── tests/                    # Unit and integration tests for all layers
├── models/                   # Directory to store the serialized .joblib/.pkl model files
├── main.py                   # FastAPI entry point orchestrating the cloud layers
├── requirements.txt          # Python dependencies
└── README.md                 # You are here!
