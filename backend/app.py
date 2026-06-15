"""
====================================
  Phishing Detector - Backend API
====================================
FastAPI server that receives a URL and returns a prediction
"""

import csv
from contextlib import asynccontextmanager
import os
import pickle
import sys
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add src directory to system path to enable feature_extractor import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from feature_extractor import extract_features

BASE_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.pkl")
MODEL_FALLBACKS = (
    os.path.join(BASE_DIR, "models", "phishing_model_new.pkl"),
)


# Dictionary to store models in memory (preferred over global variables)
ml_models = {}


def _resolve_model_path() -> Optional[str]:
    for path in (MODEL_PATH, *MODEL_FALLBACKS):
        if os.path.exists(path):
            return path
    return None


def _accuracy_fraction(model_data: dict) -> Optional[float]:
    if not model_data:
        return None
    if "test_accuracy" in model_data:
        return float(model_data["test_accuracy"])
    if "accuracy" in model_data:
        return float(model_data["accuracy"])
    return None


# Recommended lifespan handler for model loading and cleanup
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup logic ---
    resolved = _resolve_model_path()
    if resolved:
        with open(resolved, "rb") as f:
            ml_models["model_data"] = pickle.load(f)
        ml_models["model_path"] = resolved
        acc = _accuracy_fraction(ml_models["model_data"])
        if acc is not None:
            print(f"Model loaded from {resolved} — test accuracy: {acc * 100:.1f}%")
        else:
            print(f"Model loaded from {resolved}")
    else:
        print("WARNING: Model not found. Run src/train_model.py first.")

    yield  # Server is now ready to receive requests

    # --- Shutdown logic ---
    ml_models.clear()
    print("Cleaned up loaded models.")


# Register lifespan handler with FastAPI
app = FastAPI(
    title="Phishing Website Detector API",
    description="Detects whether a URL is phishing or legitimate",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class URLRequest(BaseModel):
    url: str


class PredictionResponse(BaseModel):
    url: str
    status: str
    confidence: str
    is_phishing: bool
    risk_level: str
    features_summary: dict


@app.get("/")
def home():
    return {
        "message": "Phishing Detector API is running",
        "endpoints": {
            "POST /predict": "Analyze a URL",
            "GET /health": "Server status",
        },
    }


@app.get("/health")
def health_check():
    model_data = ml_models.get("model_data")
    acc = _accuracy_fraction(model_data) if model_data else None
    return {
        "status": "healthy",
        "model_loaded": model_data is not None,
        "model_path": ml_models.get("model_path"),
        "model_accuracy": f"{acc * 100:.1f}%" if acc is not None else "N/A",
    }


@app.get("/api/dataset")
def get_dataset():
    dataset_path = os.path.join(os.path.dirname(__file__), "data", "dataset.csv")
    if not os.path.exists(dataset_path):
        raise HTTPException(status_code=404, detail="Dataset not found")
    try:
        data = []
        with open(dataset_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                data.append([row["url"], int(row["label"])])
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading dataset: {str(e)}")


@app.post("/predict", response_model=PredictionResponse)
def predict(request: URLRequest):
    model_data = ml_models.get("model_data")

    if not model_data:
        raise HTTPException(status_code=503, detail="Model not loaded.")

    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is empty.")

    # Extract features from the URL
    features = extract_features(url)
    feature_names = model_data["feature_names"]
    X = [[features[name] for name in feature_names]]

    # Make prediction
    model = model_data["model"]
    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0]
    confidence = max(probability) * 100

    # Determine risk level
    if prediction == 1:
        risk_level = (
            "High"
            if confidence >= 90
            else "Medium" if confidence >= 70 else "Low"
        )
    else:
        risk_level = "Safe"

    return PredictionResponse(
        url=url,
        status="Phishing" if prediction == 1 else "Legitimate",
        confidence=f"{confidence:.1f}%",
        is_phishing=bool(prediction == 1),
        risk_level=risk_level,
        features_summary={
            "url_length": features["url_length"],
            "is_https": bool(features["is_https"]),
            "has_at_symbol": bool(features["has_at_symbol"]),
            "has_ip_address": bool(features["has_ip_address"]),
            "suspicious_keywords": features["suspicious_keyword_count"],
            "num_subdomains": features["num_subdomains"],
            "has_hyphen_domain": bool(features["has_hyphen_domain"]),
            # Lookalike / typosquat signals (v3)
            "is_lookalike_domain": bool(features.get("is_lookalike_domain", 0)),
            "brand_similarity_score": float(features.get("brand_similarity_score", 0.0)),
            "brand_obfuscated_match": bool(features.get("brand_obfuscated_match", 0)),
        },
    )


if __name__ == "__main__":
    import uvicorn

    print("Starting server at http://localhost:8000")
    print("API docs at   http://localhost:8000/docs")
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)