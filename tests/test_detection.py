"""Tests set the contract. The anomaly detector must (a) refuse empty baselines,
(b) flag genuine outliers after fitting on a real distribution.
"""
from __future__ import annotations

import random

import pytest

from sentinel_v.models import Event


def _feat(e: Event):
    # toy but honest: one numeric feature off the event
    return [float(e.fields.get("value", 0.0))]


def _make(value: float) -> Event:
    return Event(source="test", kind="flow", fields={"value": value})


def test_refuses_empty_baseline():
    from sentinel_v.detection.anomaly import AnomalyDetector

    det = AnomalyDetector(_feat)
    with pytest.raises(ValueError):
        det.fit([])  # will not fabricate training data


def test_flags_outlier_after_real_fit():
    from sentinel_v.detection.anomaly import AnomalyDetector

    random.seed(0)
    baseline = [_make(random.gauss(100, 5)) for _ in range(500)]
    det = AnomalyDetector(_feat, contamination=0.02)
    det.fit(baseline)

    normal = _make(101.0)
    outlier = _make(900.0)
    alerts = list(det.detect([normal, outlier]))
    flagged = {a.event_ids[0] for a in alerts}
    assert outlier.id in flagged
    assert normal.id not in flagged


def test_gate_logic():
    from sentinel_v.models import Action

    benign = Action(playbook="p", name="notify", destructive=False)
    assert benign.requires_gate() is False

    block = Action(playbook="p", name="block_ip", destructive=True)
    assert block.requires_gate() is True

    earned = Action(playbook="p", name="block_ip", destructive=True, auto=True, reversible=True)
    assert earned.requires_gate() is False
