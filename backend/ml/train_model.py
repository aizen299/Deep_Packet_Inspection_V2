"""Fit the anomaly scorer and write model.joblib.

Run directly to regenerate the artifact:

    python train_model.py                           # synthetic + shipped corpus
    python train_model.py --corpus captures.jsonl   # substitute your own

corpus/benign.jsonl ships with the repo and is loaded by default: one JSON
object per line using the FEATURE_NAMES keys, which is exactly the body the
control plane POSTs to /predict. Regenerate it with:

    python3 generate_benign_pcap.py --out b.pcap --seed N     # for several N
    node backend/ml/collect_corpus.mjs --out corpus/benign.jsonl b*.pcap

The synthetic corpus exists so a clean clone still produces a scorer that
discriminates; the real vectors exist because the synthetic ranges were wrong
until they were checked against actual engine output.

The previous baseline trained on N(0.5, 0.1) noise while real features arrive
unscaled, so every input landed far outside the training distribution and the
scorer returned High for everything. The corpus below is generated in real
units instead, with the correlations that actually hold in capture data
(bytes track packets, connections track packets).
"""

import argparse
import json
import os

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from features import FEATURE_NAMES, N_FEATURES, preprocess

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.joblib")

# Feature vectors from real engine runs over generate_benign_pcap.py captures.
# Loaded by default: the synthetic ranges were calibrated against these, and
# training without them drifts back toward assumptions nothing checks.
DEFAULT_CORPUS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "corpus", "benign.jsonl"
)

SEED = 42
N_SAMPLES = 4000


def synthesise_normal(n: int, rng: np.random.Generator) -> np.ndarray:
    """Plausible benign captures, in the units the engine actually reports."""

    # Captures range from a handful of packets to a busy session; log-uniform
    # so small and large captures are both well represented.
    total_packets = np.exp(rng.uniform(np.log(40), np.log(60_000), n))

    # Bytes follow packets through a realistic mean frame size.
    avg_frame = rng.uniform(80, 1200, n)
    total_bytes = total_packets * avg_frame

    # These three were originally guessed, and the guesses were wrong. Scoring
    # real engine output against a model fitted to them put 0% of benign
    # captures in Low and 42% in High -- the corpus, not the traffic, was the
    # outlier. The ranges below were widened to cover what the engine actually
    # reports (collect_corpus.mjs), while still allowing the shapes the first
    # version assumed, so the model is tolerant of both rather than newly
    # overfitted to one sample.
    #
    # observed on real captures: tcp ~0.96, udp ~0.04, unknown ~0.33, dns ~0.33
    # The 0.6 ceiling on unknown_ratio was measured, not picked: at 0.8 a
    # capture with 48% unknown reads as ordinary and test_dpi.pcap drops to
    # Low, while 0.6 keeps benign at 100% Low and every attack fixture above
    # it with no overlap.
    udp_ratio = rng.beta(1.5, 12, n) * 0.6
    other_l4 = rng.beta(1, 30, n) * 0.2
    tcp_ratio = np.clip(1 - udp_ratio - other_l4, 0, 1)

    # unknown_ratio and dns_ratio are shares of *classified connections*, not of
    # packets, so short DNS flows weigh as much as long TLS ones and both sit
    # far higher than packet-share intuition suggests.
    unknown_ratio = rng.beta(2.5, 5, n) * 0.6
    dns_ratio = rng.beta(2, 5, n) * 0.7

    # Reported apps are capped at top-8 plus "Other".
    unique_app_count = rng.integers(3, 10, n).astype(float)

    # Benign flows carry several packets each, so connections track packets
    # without approaching one-packet-per-connection.
    packets_per_connection = np.exp(rng.uniform(np.log(2.5), np.log(60), n))
    active_connections = np.maximum(1.0, total_packets / packets_per_connection)

    # Nothing is dropped unless a rule matched; a small tail covers light filtering.
    drop_rate = np.where(rng.random(n) < 0.85, 0.0, rng.uniform(0, 8, n))

    return np.column_stack(
        [
            total_packets,
            total_bytes,
            tcp_ratio,
            udp_ratio,
            unknown_ratio,
            dns_ratio,
            unique_app_count,
            active_connections,
            drop_rate,
            packets_per_connection,
        ]
    )


def load_corpus(path: str) -> np.ndarray:
    rows = []
    with open(path) as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            missing = [k for k in FEATURE_NAMES if k not in obj]
            if missing:
                raise SystemExit(f"{path}:{line_no}: missing keys {missing}")
            rows.append([float(obj[k]) for k in FEATURE_NAMES])
    if not rows:
        raise SystemExit(f"{path}: no usable rows")
    return np.array(rows, dtype=float)


def training_set(rng: np.random.Generator, corpus_path: str | None = None) -> np.ndarray:
    """Synthetic baseline plus whatever real vectors are available.

    Used by main() and by the server's first-run bootstrap, so a model built on
    a clean image matches one built here rather than quietly omitting the real
    corpus.
    """
    X = synthesise_normal(N_SAMPLES, rng)

    path = corpus_path or (DEFAULT_CORPUS if os.path.exists(DEFAULT_CORPUS) else None)
    if path:
        real = load_corpus(path)
        X = np.vstack([X, real])
    return X


def build(train_X: np.ndarray) -> dict:
    pipeline = Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "iso",
                IsolationForest(
                    n_estimators=200,
                    contamination=0.02,
                    random_state=SEED,
                ),
            ),
        ]
    )
    pipeline.fit(preprocess(train_X))

    # Calibration: the raw decision_function is an unbounded margin whose useful
    # range depends on the data, so thresholds cannot be hardcoded. Storing the
    # training scores lets the server express a verdict as a percentile --
    # "more anomalous than N% of known-benign traffic" -- which is both bounded
    # and interpretable.
    train_scores = pipeline.decision_function(preprocess(train_X))

    return {
        "pipeline": pipeline,
        "train_scores": np.sort(train_scores),
        "feature_names": list(FEATURE_NAMES),
        "seed": SEED,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", help="JSONL of real feature vectors to include")
    args = ap.parse_args()

    rng = np.random.default_rng(SEED)
    X = training_set(rng, args.corpus)
    print(f"training samples: {len(X)} ({N_SAMPLES} synthetic)")

    assert X.shape[1] == N_FEATURES, X.shape
    artifact = build(X)

    import joblib

    joblib.dump(artifact, MODEL_PATH)
    print(f"wrote {MODEL_PATH}  ({len(X)} training samples)")


if __name__ == "__main__":
    main()
