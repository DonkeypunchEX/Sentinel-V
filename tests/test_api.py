"""Phase 0 acceptance: POST /events persists, GET /events returns it; plus
/health, /alerts and /metrics behave.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from sentinel_v.api.app import create_app
from sentinel_v.config import Settings


def _client() -> TestClient:
    # Isolated in-memory store per app; rules loaded from the repo's rules/.
    return TestClient(create_app(Settings(db_url="sqlite://", rules_dir="rules")))


def test_health():
    r = _client().get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_post_then_get_event():  # Phase 0 acceptance criterion
    c = _client()
    payload = {
        "source": "suricata.eve",
        "kind": "flow",
        "src_ip": "1.1.1.1",
        "fields": {"dest_port": 443},
    }
    posted = c.post("/events", json=payload)
    assert posted.status_code == 200
    event_id = posted.json()["event"]["id"]

    listed = c.get("/events", params={"source": "suricata.eve"})
    assert listed.status_code == 200
    assert event_id in [e["id"] for e in listed.json()]


def test_ingest_fires_rule_and_lands_in_alerts():
    c = _client()
    c.post(
        "/events",
        json={
            "source": "auth.log",
            "kind": "auth_fail",
            "src_ip": "1.2.3.4",
            "fields": {"service": "sshd", "user": "root"},
        },
    )
    alerts = c.get("/alerts").json()
    assert any(a["attack_technique"] == "T1110" for a in alerts)


def test_metrics_shape():
    m = _client().get("/metrics").json()
    assert "rules.sigma" in m["detectors"]
    assert m["rules_loaded"] >= 2
    assert set(m["counts"]) == {"events", "alerts", "incidents", "audit"}


def test_event_validation_rejects_empty_kind():
    r = _client().post("/events", json={"source": "s", "kind": "  "})
    assert r.status_code == 422  # pydantic validation on the Event body
