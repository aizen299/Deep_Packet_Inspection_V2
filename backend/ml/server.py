from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import numpy as np
import joblib
import os

from features import FEATURE_NAMES, preprocess

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

# Shared secret; when set, the control plane must present it.
API_KEY = os.environ.get("API_KEY", "")

# An unset key disables auth entirely, which is only survivable when nothing can
# reach this port but the control plane. Deployed topologies that expose it
# publicly have to opt into that state by name rather than fall into it.
if not API_KEY and os.environ.get("ALLOW_UNAUTHENTICATED") != "true":
    raise RuntimeError(
        "API_KEY is unset, which leaves /predict unauthenticated. Set API_KEY, "
        "or set ALLOW_UNAUTHENTICATED=true to run without auth on purpose."
    )

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
    """Load the fitted artifact, building it on first run if absent.

    model.joblib is generated, not committed, so a clean image has to be able to
    produce one. train_model.py owns the definition of "normal" -- keeping it in
    one place is what stopped the served model and the training corpus from
    drifting apart.
    """
    if os.path.exists(MODEL_PATH):
        artifact = joblib.load(MODEL_PATH)
        if isinstance(artifact, dict) and "pipeline" in artifact:
            return artifact
        # A pre-calibration artifact from an older image. Rebuild rather than
        # serve it: the bare estimator has no training-score distribution, and
        # scoring against it is what produced a constant High verdict.
        print("[WARN] stale model.joblib without calibration data; retraining")

    import train_model

    rng = np.random.default_rng(train_model.SEED)
    artifact = train_model.build(train_model.training_set(rng))
    joblib.dump(artifact, MODEL_PATH)
    return artifact


_artifact = load_or_train_model()
model = _artifact["pipeline"]
TRAIN_SCORES = _artifact["train_scores"]

# Target false-positive rates on benign traffic. See the note in predict().
HIGH_THRESHOLD = float(os.environ.get("ML_HIGH_THRESHOLD", 0.99))
MEDIUM_THRESHOLD = float(os.environ.get("ML_MEDIUM_THRESHOLD", 0.95))

@app.post("/predict")
def predict(features: FeatureInput, x_api_key: str | None = Header(default=None)):
    require_api_key(x_api_key)

    raw = np.array([[getattr(features, name) for name in FEATURE_NAMES]], dtype=float)

    # Same transform the pipeline was fitted through; the StandardScaler inside
    # it handles per-column centring, so there are no hand-tuned divisors here.
    X = preprocess(raw)

    score = float(model.decision_function(X)[0])

    # decision_function is an unbounded margin (positive = inlier) whose useful
    # range depends on the training data, so it cannot be mapped to 0-1 by
    # arithmetic alone. Expressing it as a percentile of the training scores
    # gives a bounded, interpretable number: the fraction of known-benign
    # traffic that looks *less* anomalous than this sample.
    #
    # The previous `1 - score` treated the margin as a probability. Real inlier
    # margins top out around 0.13, so risk_score never fell below 0.87 and every
    # verdict came back High -- Low and Medium were unreachable.
    risk_score = float(np.searchsorted(TRAIN_SCORES, score) / len(TRAIN_SCORES))
    risk_score = max(0.0, min(1.0, 1.0 - risk_score))

    # Because risk_score is a percentile of the benign training distribution, it
    # is uniform over benign traffic -- so each threshold *is* its own false
    # positive rate. High at 0.99 means roughly 1 benign capture in 100 gets
    # flagged; at the more intuitive-looking 0.9 it would be 1 in 10.
    risk_level = "Low"
    if risk_score > HIGH_THRESHOLD:
        risk_level = "High"
    elif risk_score > MEDIUM_THRESHOLD:
        risk_level = "Medium"

    # Rule-based reasons shown next to the verdict. These thresholds sit above
    # the observed benign range (backend/ml/corpus/benign.jsonl), because a
    # reason that fires on ordinary traffic trains the reader to ignore it.
    # Benign captures run unknown ~0.33, dns ~0.33 and up to ~230 connections,
    # so the previous 0.4/0.2/100 cutoffs annotated essentially every capture.
    explanations = []

    if features.unknown_ratio > 0.5:
        explanations.append("High unknown application ratio")

    if features.dns_ratio > 0.55:
        explanations.append("Elevated DNS activity")

    if features.active_connections > 500:
        explanations.append("High connection count spike")

    if features.drop_rate > 20:
        explanations.append("Elevated filter drop rate")

    # Volume alone is not suspicious; volume spread over connections that carry
    # almost nothing is the shape a scan or flood actually makes.
    if features.packets_per_connection < 2 and features.active_connections > 50:
        explanations.append("Many near-empty connections (scan-like)")

    # How far outside the training spread this sample sits, in units of that
    # spread -- 0 for a typical benign capture, approaching 1 for a clear outlier.
    spread = float(TRAIN_SCORES[-1] - TRAIN_SCORES[0]) or 1.0
    confidence = float(min(1.0, abs(score - float(np.median(TRAIN_SCORES))) / spread))

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