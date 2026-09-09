"""Correlation: dedupe + time/asset grouping of Alerts into Incidents.

Phase 3. NIST CSF: Detect (analysis). This is what turns a stream of per-event
Alerts into the higher-level truth an analyst acts on. Critically, it is where
*threshold* detections live: a single failed SSH login is not a brute force —
N failures from one source inside a window is (ATT&CK T1110). The Sigma rule
fires per event; the Correlator is what escalates the pattern to an Incident.

Design (deliberately simple, honest, and deterministic):

* **Deception or CRITICAL alerts escalate immediately** — a honeypot hit is
  near-zero-FP (see models.Event.is_deception), so one is enough.
* **Everything else is grouped by (technique-or-detector, asset)** inside a
  sliding time window; when the count crosses ``brute_force_threshold`` an
  Incident is opened, and further alerts in the window update it rather than
  spawning duplicates (dedupe).

Correlation working-state is in-memory (the live window); Incidents are durable
in the store. That split is intentional — the window is ephemeral analysis
state, the Incident is the record.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from sentinel_v.models import Alert, Event, Incident, Severity
from sentinel_v.storage import Store


@dataclass
class _Bucket:
    # (timestamp, alert_id) pairs inside the current window
    hits: list = field(default_factory=list)
    incident_id: str | None = None  # open incident for this key, if any


class Correlator:
    def __init__(
        self,
        store: Store,
        *,
        window_seconds: int = 60,
        brute_force_threshold: int = 5,
    ) -> None:
        self.store = store
        self.window = timedelta(seconds=window_seconds)
        self.threshold = brute_force_threshold
        self._buckets: dict[str, _Bucket] = defaultdict(_Bucket)

    def correlate(self, alert: Alert, event: Event | None = None) -> Incident | None:
        """Feed one Alert through correlation.

        Returns the Incident that was opened or updated by this alert, or None if
        the alert did not (yet) cross a threshold.
        """
        src_ip = self._asset(alert, event)
        is_deception = bool(event and event.is_deception())

        # High-confidence single signals escalate on their own.
        if is_deception or alert.severity is Severity.CRITICAL:
            key = f"deception:{src_ip}" if is_deception else f"critical:{alert.detector}:{src_ip}"
            title = (
                f"Honeypot interaction from {src_ip}"
                if is_deception
                else f"Critical detection from {src_ip}: {alert.title}"
            )
            return self._open_or_update(
                key, alert, src_ip,
                severity=Severity.HIGH if is_deception else Severity.CRITICAL,
                title=title,
            )

        # Threshold path: group by technique (or detector) + asset over the window.
        key = f"{alert.attack_technique or alert.detector}:{src_ip}"
        bucket = self._buckets[key]
        self._prune(bucket, alert)
        bucket.hits.append((alert.ts, alert.id))

        if len(bucket.hits) < self.threshold:
            return None

        count = len(bucket.hits)
        severity = Severity.CRITICAL if count >= 3 * self.threshold else Severity.HIGH
        title = self._threshold_title(alert, src_ip, count)
        return self._open_or_update(key, alert, src_ip, severity=severity, title=title)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _asset(alert: Alert, event: Event | None) -> str:
        if event is not None and event.src_ip:
            return event.src_ip
        detail_ip = alert.detail.get("src_ip")
        return str(detail_ip) if detail_ip else "unknown"

    def _prune(self, bucket: _Bucket, alert: Alert) -> None:
        cutoff = alert.ts - self.window
        bucket.hits = [(ts, aid) for ts, aid in bucket.hits if ts >= cutoff]
        # If the previously-open incident's window has fully elapsed, start fresh.
        if not bucket.hits:
            bucket.incident_id = None

    def _open_or_update(
        self,
        key: str,
        alert: Alert,
        src_ip: str,
        *,
        severity: Severity,
        title: str,
    ) -> Incident:
        bucket = self._buckets[key]
        alert_ids = [aid for _, aid in bucket.hits] or [alert.id]
        if alert.id not in alert_ids:
            alert_ids.append(alert.id)

        if bucket.incident_id is not None:
            existing = self.store.get_incident(bucket.incident_id)
            if existing is not None and existing.status == "open":
                merged = sorted(set(existing.alert_ids) | set(alert_ids))
                existing.alert_ids = merged
                existing.severity = severity
                existing.attack_technique = alert.attack_technique or existing.attack_technique
                existing.detail = {
                    **existing.detail,
                    "key": key,
                    "src_ip": src_ip,
                    "alert_count": len(merged),
                    "window_seconds": int(self.window.total_seconds()),
                }
                existing.title = title
                self.store.add_incident(existing)  # merge() upsert
                return existing

        incident = Incident(
            ts=alert.ts,
            title=title,
            severity=severity,
            attack_technique=alert.attack_technique,
            alert_ids=sorted(set(alert_ids)),
            status="open",
            detail={
                "key": key,
                "src_ip": src_ip,
                "alert_count": len(set(alert_ids)),
                "window_seconds": int(self.window.total_seconds()),
            },
        )
        self.store.add_incident(incident)
        bucket.incident_id = incident.id
        return incident

    @staticmethod
    def _threshold_title(alert: Alert, src_ip: str, count: int) -> str:
        if alert.attack_technique == "T1110":
            return f"Brute-force from {src_ip} ({count} alerts)"
        label = alert.attack_technique or alert.detector
        return f"Repeated {label} from {src_ip} ({count} alerts)"
