from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

app = FastAPI()

# This service is only meant to be reachable from the control plane, so the
# default origin allowlist is empty -- browsers get no cross-origin access.
ALLOWED_ORIGINS = [
    o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type", "x-api-key"],
)

# Optional shared secret; when set, the control plane must present it.
API_KEY = os.environ.get("API_KEY", "")

# Resolve relative to this file so the model does not land in whatever the
# process working directory happens to be.
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.joblib")


def require_api_key(provided: str | None) -> None:
    if API_KEY and provided != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

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

    # Train dummy baseline model. The seed matters: model.joblib is a generated
    # artifact and is no longer committed, so without it every rebuild would
    # produce a subtly different scorer.
    rng = np.random.default_rng(42)
    normal_data = rng.normal(loc=0.5, scale=0.1, size=(500, 10))
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(normal_data)
    joblib.dump(model, MODEL_PATH)
    return model

model = load_or_train_model()

@app.post("/predict")
def predict(features: FeatureInput, x_api_key: str | None = Header(default=None)):
    require_api_key(x_api_key)

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