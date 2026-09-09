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
from dataclasses import dataclass, field

from sentinel_v.config import Settings
from sentinel_v.correlation import Correlator
from sentinel_v.detection.anomaly import AnomalyDetector
from sentinel_v.detection.base import Detector
from sentinel_v.detection.features import flow_features
from sentinel_v.detection.rules import SigmaRuleDetector
from sentinel_v.models import Action, Alert, Event, Incident
from sentinel_v.response.playbooks import PlaybookRunner
from sentinel_v.storage import Store

log = logging.getLogger(__name__)


@dataclass
class IngestResult:
    """Everything one ingested Event produced, across the whole pipeline."""

    event: Event
    alerts: list[Alert] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)

    def as_tuple(self) -> tuple[Event, list[Alert]]:
        return self.event, self.alerts


class Pipeline:
    def __init__(
        self,
        store: Store,
        detectors: Iterable[Detector],
        *,
        correlator: Correlator | None = None,
        runner: PlaybookRunner | None = None,
    ) -> None:
        self.store = store
        self.detectors: list[Detector] = list(detectors)
        self.correlator = correlator
        self.runner = runner

    def ingest(self, event: Event) -> tuple[Event, list[Alert]]:
        """Persist Event → detect → correlate → respond. Returns (event, alerts).

        The full result (incidents + actions) is available via :meth:`ingest_full`;
        this method keeps the original 2-tuple shape for existing callers.
        """
        return self.ingest_full(event).as_tuple()

    def ingest_full(self, event: Event) -> IngestResult:
        self.store.add_event(event)
        result = IngestResult(event=event)
        for detector in self.detectors:
            try:
                fired = list(detector.detect([event]))
            except Exception:  # noqa: BLE001 - isolate a misbehaving detector
                log.exception("detector %s failed on event %s", detector.name, event.id)
                continue
            for alert in fired:
                self.store.add_alert(alert)
                result.alerts.append(alert)
                self._correlate_and_respond(alert, event, result)
        return result

    def _correlate_and_respond(self, alert: Alert, event: Event, result: IngestResult) -> None:
        if self.correlator is None:
            return
        try:
            incident = self.correlator.correlate(alert, event)
        except Exception:  # noqa: BLE001 - correlation must not drop ingestion
            log.exception("correlation failed on alert %s", alert.id)
            return
        if incident is None:
            return
        result.incidents.append(incident)
        if self.runner is not None:
            try:
                result.actions.extend(self.runner.run_for_incident(incident))
            except Exception:  # noqa: BLE001 - response must not drop ingestion
                log.exception("response failed on incident %s", incident.id)

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
    Correlation and the gated response runner are always wired.
    """
    detectors: list[Detector] = [SigmaRuleDetector(settings.rules_dir)]
    if settings.model_path.exists():
        detectors.append(
            AnomalyDetector(flow_features, model_path=settings.model_path, kinds={"flow"})
        )
    correlator = Correlator(
        store,
        window_seconds=settings.correlation.window_seconds,
        brute_force_threshold=settings.correlation.brute_force_threshold,
    )
    runner = PlaybookRunner(store, settings)
    return Pipeline(store, detectors, correlator=correlator, runner=runner)
