"""Canonical feature layout shared by training and serving.

The control plane builds this vector in `buildFeatureVector` (server.js) and the
scorer consumes it positionally, so the order here is a contract across two
languages and two processes. Keeping it in one module means training and serving
cannot silently disagree about which column is which.
"""

import numpy as np

# Order matters and must match buildFeatureVector() in backend/api/server.js.
FEATURE_NAMES = (
    "total_packets",
    "total_bytes",
    "tcp_ratio",
    "udp_ratio",
    "unknown_ratio",
    "dns_ratio",
    "unique_app_count",
    "active_connections",
    "drop_rate",
    "packets_per_connection",
)

N_FEATURES = len(FEATURE_NAMES)

# Counts spanning several orders of magnitude (a 78-packet sample and a
# 900k-packet flood are both legitimate inputs). Compressing them keeps one
# feature from dominating the distance metric purely by unit scale.
_LOG_COLUMNS = (
    FEATURE_NAMES.index("total_packets"),
    FEATURE_NAMES.index("total_bytes"),
    FEATURE_NAMES.index("active_connections"),
    FEATURE_NAMES.index("packets_per_connection"),
)


def preprocess(X: np.ndarray) -> np.ndarray:
    """Compress the heavy-tailed count columns. Ratios pass through unchanged.

    Applied identically at fit time and predict time; the StandardScaler inside
    the saved pipeline handles the remaining per-column centring, so there are
    no hand-tuned divisors to drift out of sync with the data.
    """
    out = np.asarray(X, dtype=float).copy()
    for col in _LOG_COLUMNS:
        # log1p keeps 0 mapping to 0; negatives cannot occur but are clamped
        # rather than producing NaN if a malformed payload arrives.
        out[:, col] = np.log1p(np.clip(out[:, col], 0, None))
    return out
