"""Isolation-forest anomaly detector (optional ``ml`` extra).

Requires numpy and scikit-learn. Loaded lazily via
``sentinel_v.ThreatDetector`` so the base package never imports sklearn.
"""

from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest


class ThreatDetector:
    """Unsupervised anomaly detector over numeric feature vectors."""

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        self.model = IsolationForest(
            contamination=contamination, random_state=random_state
        )

    def train(self, data: Any) -> None:
        """Fit the detector on baseline feature rows (numpy array)."""
        self.model.fit(data)

    def detect(self, new_data: Any) -> Any:
        """Score rows: returns -1 for anomalies, 1 for normal."""
        return self.model.predict(new_data)


if __name__ == "__main__":
    normal_data = np.random.normal(100, 20, (100, 1))
    anomalous_data = np.random.normal(500, 100, (10, 1))
    train_data = np.vstack([normal_data, anomalous_data])
    detector = ThreatDetector()
    detector.train(train_data)
    test_data = np.array([[150], [600]])
    print(detector.detect(test_data))  # e.g., [ 1 -1]
