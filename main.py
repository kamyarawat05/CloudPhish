from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CloudPhish API", description="4-Layer Phishing Detection")

class ScanRequest(BaseModel):
    url: str
    client_id: str = "default_client"

@app.post("/api/v1/scan")
async def scan_url(request: ScanRequest):
    # --- LAYER 2: Feature Extraction (Placeholder) ---
    # In reality, this calls your feature_extraction_layer module
    features = {"url_length": len(request.url), "has_ip": 1} 
    
    # --- LAYER 3: Model Inference (Placeholder) ---
    # In reality, this calls your model_inference_layer module
    score = 0.96 
    
    # --- LAYER 4: Response Layer (Placeholder) ---
    # In reality, this calls your response_layer module
    level = "PHISHING" if score > 0.8 else "SAFE"
    
    return {
        "status": "success",
        "data": {
            "url": request.url,
            "score": score,
            "level": level,
            "explanation": {"summary": "Placeholder: High risk features detected."}
        }
    }
