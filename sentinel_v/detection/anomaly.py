"""ML anomaly detector. REFERENCE IMPLEMENTATION — sets the quality bar.

Contrast with the scrapped stub that trained IsolationForest on np.random. This
one: (1) takes a real feature extractor, (2) fits on a caller-supplied baseline
dataset or a persisted model, (3) refuses to fabricate training data, (4)
persists/loads the fitted model, (5) is typed and testable.

Claude Code: swap sklearn's IsolationForest for PyOD models per docs/RND.md if
they score better on real data. The interface stays the same.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from sentinel_v.detection.base import Detector
from sentinel_v.models import Alert, Event, Severity

# Feature extractor: Event -> fixed-length numeric vector. Provided by the
# caller so the model is decoupled from the (evolving) feature engineering.
FeatureFn = Callable[[Event], Sequence[float]]


class AnomalyDetector(Detector):
    name = "anomaly.isoforest"

    def __init__(
        self,
        feature_fn: FeatureFn,
        *,
        contamination: float = 0.02,
        model_path: Path | None = None,
        kinds: set[str] | None = None,
    ) -> None:
        self._feat = feature_fn
        self._contamination = contamination
        self._model_path = model_path
        # Only score events whose kind the model was built for; a flow model has
        # nothing meaningful to say about, e.g., a DNS or alert event. None = all.
        self._kinds = kinds
        self._model: object | None = None
        if model_path is not None and model_path.exists():
            self.load(model_path)

    def fit(self, baseline: Iterable[Event]) -> None:
        """Fit on REAL baseline traffic. Raises if given nothing.

        We do not synthesize training data. If you have no baseline, capture one
        (your own network at rest, or CIC-IDS2017 'benign' rows) — see RND.md.
        """
        from sklearn.ensemble import IsolationForest  # local import: optional dep

        X = [list(self._feat(e)) for e in baseline]
        if not X:
            raise ValueError(
                "AnomalyDetector.fit received no baseline events. Supply real "
                "baseline traffic; this class will not train on fabricated data."
            )
        model = IsolationForest(
            contamination=self._contamination,
            random_state=42,
            n_estimators=200,
        )
        model.fit(X)
        self._model = model
        if self._model_path is not None:
            self.save(self._model_path)

    def detect(self, events: Iterable[Event]) -> Iterable[Alert]:
        if self._model is None:
            raise RuntimeError("AnomalyDetector not fitted/loaded. Call fit() or pass model_path.")
        for e in events:
            if self._kinds is not None and e.kind not in self._kinds:
                continue
            x = [list(self._feat(e))]
            # IsolationForest: predict() -> -1 anomaly, 1 normal
            pred = self._model.predict(x)[0]  # type: ignore[attr-defined]
            if pred == -1:
                score = float(self._model.score_samples(x)[0])  # type: ignore[attr-defined]
                yield Alert(
                    title="Anomalous event flagged by ML baseline",
                    severity=Severity.MEDIUM,
                    detector=self.name,
                    attack_technique=None,  # anomaly = unknown-unknown, no fixed TTP
                    event_ids=[e.id],
                    detail={"anomaly_score": score, "kind": e.kind, "src_ip": e.src_ip},
                )

    def save(self, path: Path) -> None:
        import joblib

        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._model, path)

    def load(self, path: Path) -> None:
        import joblib

        self._model = joblib.load(path)
