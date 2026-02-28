from fastapi import FastAPI
from pydantic import BaseModel
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

app = FastAPI()

MODEL_PATH = "model.joblib"

class FeatureInput(BaseModel):
    total_packets: float
    total_bytes: float
    tcp_ratio: float
    udp_ratio: float
    unknown_ratio: float
    dns_ratio: float
    unique_app_count: float
    active_connections: float
    drop_rate: float
    packets_per_connection: float

def load_or_train_model():
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)

    # Train dummy baseline model
    normal_data = np.random.normal(loc=0.5, scale=0.1, size=(500, 10))
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(normal_data)
    joblib.dump(model, MODEL_PATH)
    return model

model = load_or_train_model()

@app.post("/predict")
def predict(features: FeatureInput):
    raw = np.array([[ 
        features.total_packets,
        features.total_bytes,
        features.tcp_ratio,
        features.udp_ratio,
        features.unknown_ratio,
        features.dns_ratio,
        features.unique_app_count,
        features.active_connections,
        features.drop_rate,
        features.packets_per_connection
    ]])

    # Basic normalization to align with training distribution (~0-1 range)
    scaled = raw.copy()
    scaled[:, 0] /= 10000.0      # total_packets
    scaled[:, 1] /= 1000000.0    # total_bytes
    scaled[:, 6] /= 50.0         # unique_app_count
    scaled[:, 7] /= 5000.0       # active_connections
    scaled[:, 9] /= 100.0        # packets_per_connection

    X = scaled

    score = model.decision_function(X)[0]
    anomaly = model.predict(X)[0]  # -1 = anomaly

    risk_score = float(1 - score)
    risk_score = max(0.0, min(1.0, risk_score))

    risk_level = "Low"
    if risk_score > 0.7:
        risk_level = "High"
    elif risk_score > 0.4:
        risk_level = "Medium"

    explanations = []

    if features.unknown_ratio > 0.4:
        explanations.append("High unknown application ratio")

    if features.dns_ratio > 0.2:
        explanations.append("Elevated DNS activity")

    if features.active_connections > 100:
        explanations.append("High connection count spike")

    confidence = float(abs(score))

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "anomalies": explanations
    }


# Health endpoint
@app.get("/health")
def health():
    return {"status": "ok"}