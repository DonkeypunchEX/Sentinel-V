"""Phase 1: canonical flow features + CIC-IDS2017 baseline loader."""
from __future__ import annotations

import pytest

from sentinel_v.detection.datasets import load_cic_ids2017_benign
from sentinel_v.detection.features import FEATURE_NAMES, flow_features
from sentinel_v.models import Event


def test_features_from_canonical_keys():
    e = Event(
        source="dataset.cic-ids2017",
        kind="flow",
        fields={"fwd_bytes": 100, "bwd_bytes": 200, "fwd_pkts": 2,
                "bwd_pkts": 3, "duration_s": 1.5, "dst_port": 443, "proto": "tcp"},
    )
    vec = list(flow_features(e))
    assert len(vec) == len(FEATURE_NAMES)
    assert vec == [100.0, 200.0, 2.0, 3.0, 1.5, 443.0, 6.0]


def test_features_from_suricata_nested_flow():
    e = Event(
        source="suricata.eve",
        kind="flow",
        fields={"flow": {"bytes_toserver": 500, "bytes_toclient": 50,
                         "pkts_toserver": 5, "pkts_toclient": 1, "age": 3},
                "dest_port": 80, "proto": "UDP"},
    )
    fwd_bytes, bwd_bytes, fwd_pkts, bwd_pkts, dur, dst_port, proto = flow_features(e)
    assert (fwd_bytes, bwd_bytes, fwd_pkts, bwd_pkts) == (500.0, 50.0, 5.0, 1.0)
    assert dst_port == 80.0 and proto == 17.0


def test_cic_loader_filters_benign(tmp_path):
    csv = tmp_path / "cic.csv"
    csv.write_text(
        " Destination Port, Flow Duration, Total Fwd Packets, Label\n"
        "443,1000,10,BENIGN\n"
        "22,50,3,DoS\n"
        "80,2000,20,BENIGN\n"
    )
    events = list(load_cic_ids2017_benign(csv))
    assert len(events) == 2  # the DoS row is excluded
    assert {e.fields["dst_port"] for e in events} == {443.0, 80.0}


def test_cic_loader_refuses_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        list(load_cic_ids2017_benign(tmp_path / "absent.csv"))
