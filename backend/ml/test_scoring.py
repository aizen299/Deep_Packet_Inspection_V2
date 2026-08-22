"""Tests for the anomaly scorer.

Run from backend/ml:

    python -m unittest discover -p 'test_*.py' -v

Stdlib unittest rather than pytest so the ML image needs no extra dependency
to run its own tests.
"""

import unittest

import numpy as np

from features import FEATURE_NAMES, N_FEATURES, preprocess
import train_model

# Kept in step with server.py. risk_score is a percentile of the benign training
# distribution, so it is uniform over benign traffic and each threshold is its
# own false-positive rate.
HIGH_THRESHOLD = 0.99
MEDIUM_THRESHOLD = 0.95


def vector(**overrides) -> dict:
    """A benign baseline capture, with named fields overridden per test."""
    base = dict(
        total_packets=4200,
        total_bytes=3_100_000,
        tcp_ratio=0.86,
        udp_ratio=0.12,
        unknown_ratio=0.08,
        dns_ratio=0.04,
        unique_app_count=7,
        active_connections=210,
        drop_rate=0.0,
        packets_per_connection=20.0,
    )
    base.update(overrides)
    return base


class ScorerHarness:
    """Fits the real artifact once and scores dicts through the real mapping."""

    def __init__(self):
        rng = np.random.default_rng(train_model.SEED)
        # training_set(), not synthesise_normal(), so the tests exercise the
        # model the service actually serves -- shipped real corpus included.
        artifact = train_model.build(train_model.training_set(rng))
        self.pipeline = artifact["pipeline"]
        self.train_scores = artifact["train_scores"]

    def risk(self, features: dict) -> tuple[float, str]:
        raw = np.array([[features[name] for name in FEATURE_NAMES]], dtype=float)
        score = float(self.pipeline.decision_function(preprocess(raw))[0])

        pct = float(np.searchsorted(self.train_scores, score) / len(self.train_scores))
        risk_score = max(0.0, min(1.0, 1.0 - pct))

        level = "Low"
        if risk_score > HIGH_THRESHOLD:
            level = "High"
        elif risk_score > MEDIUM_THRESHOLD:
            level = "Medium"
        return risk_score, level


HARNESS = ScorerHarness()


class TestFeatureContract(unittest.TestCase):
    def test_feature_count_matches_names(self):
        self.assertEqual(N_FEATURES, 10)
        self.assertEqual(len(FEATURE_NAMES), N_FEATURES)

    def test_names_are_unique(self):
        self.assertEqual(len(set(FEATURE_NAMES)), len(FEATURE_NAMES))

    def test_synthetic_corpus_matches_feature_width(self):
        rng = np.random.default_rng(0)
        self.assertEqual(train_model.synthesise_normal(16, rng).shape, (16, N_FEATURES))


class TestPreprocess(unittest.TestCase):
    def test_zeros_survive(self):
        out = preprocess(np.zeros((1, N_FEATURES)))
        self.assertFalse(np.isnan(out).any(), "zero capture must not produce NaN")

    def test_negative_is_clamped_not_nan(self):
        # Malformed payloads should degrade, not poison the model with NaN.
        bad = np.zeros((1, N_FEATURES))
        bad[0, 0] = -5
        self.assertFalse(np.isnan(preprocess(bad)).any())

    def test_ratio_columns_pass_through(self):
        X = np.zeros((1, N_FEATURES))
        tcp = FEATURE_NAMES.index("tcp_ratio")
        X[0, tcp] = 0.86
        self.assertAlmostEqual(preprocess(X)[0, tcp], 0.86)

    def test_count_columns_are_compressed(self):
        X = np.zeros((1, N_FEATURES))
        col = FEATURE_NAMES.index("total_bytes")
        X[0, col] = 1_000_000
        self.assertLess(preprocess(X)[0, col], 20, "counts should be log-compressed")


class TestDiscrimination(unittest.TestCase):
    """The regression that motivated this suite.

    risk_score was `1 - decision_function`, which treats a signed margin as a
    probability. Every input scored above the High threshold, so these are the
    assertions that would have caught it.
    """

    def test_benign_traffic_scores_low(self):
        _, level = HARNESS.risk(vector())
        self.assertEqual(level, "Low")

    def test_small_quiet_capture_scores_low(self):
        _, level = HARNESS.risk(
            vector(
                total_packets=300,
                total_bytes=180_000,
                active_connections=25,
                packets_per_connection=12,
            )
        )
        self.assertEqual(level, "Low")

    def test_scan_pattern_is_flagged(self):
        """Asserts the band, not the exact label.

        This vector sits around the 98.7th percentile, so it lands in Medium
        under a 1%-false-positive High threshold. Pinning the exact enum here
        would make the test fail on any threshold tuning without anything
        actually being wrong -- what matters is that it is not dismissed as Low.
        """
        score, level = HARNESS.risk(
            vector(
                total_packets=50_000,
                total_bytes=3_000_000,
                unknown_ratio=0.97,
                unique_app_count=1,
                active_connections=49_000,
                packets_per_connection=1.02,
            )
        )
        self.assertIn(level, ("Medium", "High"), f"scan scored {score:.4f}")

    def test_flood_with_heavy_drop_scores_high(self):
        _, level = HARNESS.risk(
            vector(
                total_packets=900_000,
                total_bytes=900_000_000,
                unknown_ratio=0.98,
                unique_app_count=1,
                active_connections=500_000,
                drop_rate=95,
                packets_per_connection=1.8,
            )
        )
        self.assertEqual(level, "High")

    def test_verdict_is_not_constant(self):
        """Directly guards the old bug: High for literally everything."""
        benign, _ = HARNESS.risk(vector())
        scan, _ = HARNESS.risk(
            vector(
                unknown_ratio=0.97,
                active_connections=49_000,
                packets_per_connection=1.02,
            )
        )
        self.assertLess(
            benign,
            scan,
            "benign traffic must score below scan traffic; a constant verdict "
            "means the score mapping is broken again",
        )

    def test_false_positive_rate_matches_threshold(self):
        """`Low` was unreachable code; now it must be the common case.

        risk_score is uniform over benign traffic, so the High threshold sets
        the false-positive rate directly. Asserting the observed rate rather
        than a vague "most" is what makes a threshold regression visible.
        """
        rng = np.random.default_rng(7)
        sample = train_model.synthesise_normal(600, rng)
        levels = [HARNESS.risk(dict(zip(FEATURE_NAMES, row)))[1] for row in sample]

        false_high = levels.count("High") / len(levels)
        low_fraction = levels.count("Low") / len(levels)

        expected_fp = 1 - HIGH_THRESHOLD
        self.assertLess(
            false_high,
            expected_fp * 3,
            f"{false_high:.1%} of benign traffic flagged High, expected "
            f"about {expected_fp:.1%}",
        )
        self.assertGreater(
            low_fraction,
            0.9,
            f"only {low_fraction:.0%} of benign traffic scored Low",
        )

    def test_risk_score_stays_in_unit_range(self):
        for features in (
            vector(),
            vector(total_packets=0, total_bytes=0, active_connections=0,
                   packets_per_connection=0, tcp_ratio=0, udp_ratio=0,
                   unknown_ratio=0, dns_ratio=0, unique_app_count=0),
            vector(total_packets=10**9, total_bytes=10**12),
        ):
            score, _ = HARNESS.risk(features)
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 1.0)


class TestDeterminism(unittest.TestCase):
    def test_same_seed_gives_same_corpus(self):
        a = train_model.synthesise_normal(64, np.random.default_rng(train_model.SEED))
        b = train_model.synthesise_normal(64, np.random.default_rng(train_model.SEED))
        np.testing.assert_array_equal(a, b)


if __name__ == "__main__":
    unittest.main()


def _reasons(row: dict) -> list:
    """Mirrors the rule-based explanations in server.py.

    Duplicated rather than imported because importing server executes its
    fail-closed API_KEY check and loads the model artifact.
    """
    out = []
    if row["unknown_ratio"] > 0.5:
        out.append("unknown")
    if row["dns_ratio"] > 0.55:
        out.append("dns")
    if row["active_connections"] > 500:
        out.append("conns")
    if row["drop_rate"] > 20:
        out.append("drop")
    if row["packets_per_connection"] < 2 and row["active_connections"] > 50:
        out.append("scan")
    return out


def _corpus_rows() -> list:
    import json
    with open(train_model.DEFAULT_CORPUS) as fh:
        return [json.loads(line) for line in fh if line.strip()]


class TestRealCorpus(unittest.TestCase):
    """Guards the miscalibration that shipping real vectors exposed.

    The synthetic corpus was written by guessing at tcp_ratio, unknown_ratio and
    dns_ratio. Scored against it, 0% of real captures came back Low and 42% came
    back High -- the corpus was the outlier, not the traffic. Nothing caught that
    until real engine output was compared against it.
    """

    def test_corpus_is_shipped(self):
        import os
        self.assertTrue(
            os.path.exists(train_model.DEFAULT_CORPUS),
            "the real corpus must ship; without it training silently drifts back "
            "to unchecked assumptions",
        )

    def test_training_set_includes_the_corpus(self):
        rng = np.random.default_rng(train_model.SEED)
        self.assertGreater(
            len(train_model.training_set(rng)),
            train_model.N_SAMPLES,
            "training_set() must fold in the shipped corpus",
        )

    def test_real_benign_captures_score_low(self):
        rows = _corpus_rows()
        levels = [HARNESS.risk(r)[1] for r in rows]
        low = levels.count("Low") / len(levels)
        self.assertGreater(
            low,
            0.95,
            f"only {low:.0%} of real benign captures scored Low; the synthetic "
            f"ranges have drifted away from what the engine emits",
        )

    def test_explanations_stay_quiet_on_benign_traffic(self):
        # Benign captures run unknown ~0.33, dns ~0.33 and up to ~230
        # connections. The original 0.4/0.2/100 cutoffs annotated every one of
        # them, and a reason that always fires is one the reader learns to skip.
        noisy = [r for r in _corpus_rows() if _reasons(r)]
        self.assertEqual(
            noisy,
            [],
            f"{len(noisy)} benign captures triggered an anomaly reason",
        )

    def test_scan_shape_still_explained(self):
        self.assertIn(
            "scan",
            _reasons(vector(packets_per_connection=1.0, active_connections=2000)),
        )
