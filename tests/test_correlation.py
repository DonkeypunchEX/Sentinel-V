"""P0 item 1: correlation groups alerts into incidents with real thresholds."""
from __future__ import annotations

from datetime import timedelta

from sentinel_v.correlation import Correlator
from sentinel_v.models import Alert, Event, Severity, _utcnow
from sentinel_v.storage import Store


def _alert(ts, src_ip="9.9.9.9", tech="T1110", detector="rules.sigma", sev=Severity.LOW):
    return Alert(ts=ts, title="failed auth", severity=sev, detector=detector,
                 attack_technique=tech, detail={"src_ip": src_ip})


def _event(src_ip="9.9.9.9", source="auth.log"):
    return Event(source=source, kind="auth_fail", src_ip=src_ip)


def test_below_threshold_no_incident():
    c = Correlator(Store("sqlite://"), window_seconds=60, brute_force_threshold=5)
    now = _utcnow()
    incs = [c.correlate(_alert(now + timedelta(seconds=i)), _event()) for i in range(4)]
    assert all(i is None for i in incs)


def test_threshold_opens_brute_force_incident():
    store = Store("sqlite://")
    c = Correlator(store, window_seconds=60, brute_force_threshold=5)
    now = _utcnow()
    result = None
    for i in range(5):
        result = c.correlate(_alert(now + timedelta(seconds=i)), _event())
    assert result is not None
    assert result.attack_technique == "T1110"
    assert result.severity is Severity.HIGH
    assert result.detail["src_ip"] == "9.9.9.9"
    assert store.counts()["incidents"] == 1


def test_updates_not_duplicates_within_window():
    store = Store("sqlite://")
    c = Correlator(store, window_seconds=60, brute_force_threshold=5)
    now = _utcnow()
    for i in range(8):
        c.correlate(_alert(now + timedelta(seconds=i)), _event())
    incidents = store.get_incidents()
    assert len(incidents) == 1  # one incident, updated — not eight
    assert incidents[0].detail["alert_count"] >= 5


def test_window_expiry_prevents_accumulation():
    store = Store("sqlite://")
    c = Correlator(store, window_seconds=60, brute_force_threshold=5)
    now = _utcnow()
    # one alert every 30s: never 5 inside any 60s window
    for i in range(6):
        c.correlate(_alert(now + timedelta(seconds=30 * i)), _event())
    assert store.counts()["incidents"] == 0


def test_deception_escalates_on_first_hit():
    store = Store("sqlite://")
    c = Correlator(store, window_seconds=60, brute_force_threshold=5)
    ev = _event(source="cowrie")  # is_deception() -> True
    alert = _alert(_utcnow(), tech=None, detector="deception.cowrie")
    incident = c.correlate(alert, ev)
    assert incident is not None
    assert incident.severity is Severity.HIGH
    assert "Honeypot" in incident.title
    assert store.counts()["incidents"] == 1


def test_distinct_sources_do_not_merge():
    store = Store("sqlite://")
    c = Correlator(store, window_seconds=60, brute_force_threshold=5)
    now = _utcnow()
    for i in range(5):
        c.correlate(_alert(now + timedelta(seconds=i), src_ip="1.1.1.1"), _event(src_ip="1.1.1.1"))
    for i in range(4):
        c.correlate(_alert(now + timedelta(seconds=i), src_ip="2.2.2.2"), _event(src_ip="2.2.2.2"))
    # only the source that crossed the threshold gets an incident
    assert store.counts()["incidents"] == 1
