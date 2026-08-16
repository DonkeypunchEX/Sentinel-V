"""Phase 1 acceptance: replay attack + baseline traffic through the control
plane and confirm BOTH detectors surface via /alerts — rules fire on a known
attack (Suricata brute-force signature, T1110) and the ML detector flags an
injected outlier flow.
"""
from __future__ import annotations

import random

from fastapi.testclient import TestClient

from sentinel_v.api.app import create_app
from sentinel_v.config import Settings
from sentinel_v.detection.anomaly import AnomalyDetector
from sentinel_v.detection.features import flow_features
from sentinel_v.models import Event


def _baseline(n: int = 400) -> list[Event]:
    """A stable, non-random-labeled benign distribution (stands in for the
    CIC-IDS2017 'BENIGN' rows a real deployment would fit on)."""
    random.seed(0)
    events: list[Event] = []
    for _ in range(n):
        events.append(
            Event(
                source="dataset.baseline",
                kind="flow",
                fields={
                    "fwd_bytes": random.gauss(1000, 50),
                    "bwd_bytes": random.gauss(800, 40),
                    "fwd_pkts": random.gauss(10, 2),
                    "bwd_pkts": random.gauss(9, 2),
                    "duration_s": random.gauss(2.0, 0.3),
                    "dst_port": 443,
                    "proto": "tcp",
                },
            )
        )
    return events


def test_rules_and_ml_both_visible_in_alerts(tmp_path):
    # Fit + persist a real anomaly model so build_pipeline wires it in.
    model_path = tmp_path / "anomaly.joblib"
    det = AnomalyDetector(flow_features, contamination=0.02, model_path=model_path, kinds={"flow"})
    det.fit(_baseline())
    assert model_path.exists()

    settings = Settings(db_url="sqlite://", rules_dir="rules", model_path=model_path)
    app = create_app(settings)
    assert "anomaly.isoforest" in [d.name for d in app.state.pipeline.detectors]
    c = TestClient(app)

    # (1) Known attack: Suricata IDS brute-force signature -> Sigma rule fires.
    c.post(
        "/events",
        json={
            "source": "suricata.eve",
            "kind": "alert",
            "src_ip": "9.9.9.9",
            "fields": {"alert": {"signature": "ET SCAN SSH BruteForce"}},
        },
    )
    # (2) Benign flow that resembles the baseline -> should NOT be flagged.
    c.post(
        "/events",
        json={
            "source": "suricata.eve",
            "kind": "flow",
            "fields": {
                "flow": {"bytes_toserver": 1000, "bytes_toclient": 800,
                         "pkts_toserver": 10, "pkts_toclient": 9, "age": 2},
                "dest_port": 443, "proto": "tcp",
            },
        },
    )
    # (3) Injected outlier flow -> anomaly detector fires.
    c.post(
        "/events",
        json={
            "source": "suricata.eve",
            "kind": "flow",
            "fields": {
                "flow": {"bytes_toserver": 5_000_000, "bytes_toclient": 9000,
                         "pkts_toserver": 9000, "pkts_toclient": 10, "age": 600},
                "dest_port": 31337, "proto": "tcp",
            },
        },
    )

    alerts = c.get("/alerts").json()
    detectors = {a["detector"] for a in alerts}
    assert "rules.sigma" in detectors, alerts
    assert "anomaly.isoforest" in detectors, alerts
    assert any(a["attack_technique"] == "T1110" for a in alerts)
