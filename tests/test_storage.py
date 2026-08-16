"""Phase 0: storage round-trips the core schema and reports metrics counts."""
from __future__ import annotations

from sentinel_v.models import Action, Alert, Event, Incident, Severity
from sentinel_v.storage import Store


def _store() -> Store:
    return Store("sqlite://")  # shared in-memory (StaticPool)


def test_event_roundtrip_and_query():
    store = _store()
    e = Event(source="auth.log", kind="auth_fail", src_ip="1.2.3.4", fields={"user": "root"})
    store.add_event(e)

    got = store.get_event(e.id)
    assert got is not None
    assert got.source == "auth.log"
    assert got.fields["user"] == "root"
    assert got.ts.tzinfo is not None  # tz survives the SQLite round-trip

    assert len(store.get_events(source="auth.log")) == 1
    assert store.get_events(source="nope") == []
    assert store.get_events(src_ip="1.2.3.4")[0].id == e.id


def test_alert_severity_filter():
    store = _store()
    store.add_alert(Alert(title="a", detector="d", severity=Severity.LOW))
    store.add_alert(Alert(title="b", detector="d", severity=Severity.HIGH))
    assert len(store.get_alerts()) == 2
    highs = store.get_alerts(severity=Severity.HIGH)
    assert len(highs) == 1 and highs[0].title == "b"


def test_incident_and_audit_and_counts():
    store = _store()
    store.add_event(Event(source="s", kind="k"))
    store.add_alert(Alert(title="t", detector="d"))
    store.add_incident(Incident(title="i", severity=Severity.HIGH, status="open"))
    action = Action(playbook="brute_force", name="block_ip", destructive=True)
    store.record_action(action)

    got = store.get_audit()[0]
    assert got.name == "block_ip" and got.destructive is True
    assert store.counts() == {"events": 1, "alerts": 1, "incidents": 1, "audit": 1}
