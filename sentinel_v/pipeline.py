"""Ingest pipeline: Event -> detectors -> persisted Alerts.

Wires the detection layer onto the store so a single ingested Event is persisted
and run past every configured detector, with any resulting Alerts saved and
returned. This is the seam the API's ``POST /events`` sits on and the join point
the Phase-1 acceptance test exercises (rules + ML both landing in ``/alerts``).

A detector that raises is isolated so one bad detector cannot drop ingestion.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable

from sentinel_v.config import Settings
from sentinel_v.detection.anomaly import AnomalyDetector
from sentinel_v.detection.base import Detector
from sentinel_v.detection.features import flow_features
from sentinel_v.detection.rules import SigmaRuleDetector
from sentinel_v.models import Alert, Event
from sentinel_v.storage import Store

log = logging.getLogger(__name__)


class Pipeline:
    def __init__(self, store: Store, detectors: Iterable[Detector]) -> None:
        self.store = store
        self.detectors: list[Detector] = list(detectors)

    def ingest(self, event: Event) -> tuple[Event, list[Alert]]:
        """Persist one Event, run detectors, persist and return its Alerts."""
        self.store.add_event(event)
        alerts: list[Alert] = []
        for detector in self.detectors:
            try:
                fired = list(detector.detect([event]))
            except Exception:  # noqa: BLE001 - isolate a misbehaving detector
                log.exception("detector %s failed on event %s", detector.name, event.id)
                continue
            for alert in fired:
                self.store.add_alert(alert)
                alerts.append(alert)
        return event, alerts

    def ingest_many(self, events: Iterable[Event]) -> tuple[int, list[Alert]]:
        n = 0
        alerts: list[Alert] = []
        for event in events:
            _, fired = self.ingest(event)
            alerts.extend(fired)
            n += 1
        return n, alerts


def build_pipeline(settings: Settings, store: Store) -> Pipeline:
    """Construct the default pipeline from settings.

    The Sigma detector always loads. The anomaly detector joins only when a
    fitted model already exists on disk — it will not train itself on ingest,
    and an unfitted detector must never be wired in (it would raise per event).
    """
    detectors: list[Detector] = [SigmaRuleDetector(settings.rules_dir)]
    if settings.model_path.exists():
        detectors.append(
            AnomalyDetector(flow_features, model_path=settings.model_path, kinds={"flow"})
        )
    return Pipeline(store, detectors)
