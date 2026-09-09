"""Item 8: `sentinel-v fit` trains + persists the anomaly model from a baseline."""
from __future__ import annotations

import pytest

from sentinel_v.cli import main
from sentinel_v.detection.anomaly import AnomalyDetector
from sentinel_v.detection.features import flow_features
from sentinel_v.models import Event


def _write_cic(path, n: int = 60) -> None:
    header = (
        " Destination Port, Flow Duration, Total Fwd Packets,"
        " Total Backward Packets, Total Length of Fwd Packets,"
        " Total Length of Bwd Packets, Label\n"
    )
    rows = []
    for i in range(n):
        # Deterministic benign-looking flows + a couple of non-benign rows to drop.
        label = "BENIGN" if i % 20 else "DDoS"
        rows.append(f"443,{1000 + i},{10 + i % 3},{9 + i % 2},{800 + i},{700 + i},{label}\n")
    path.write_text(header + "".join(rows))


def test_fit_trains_and_persists_model(tmp_path):
    csv = tmp_path / "cic.csv"
    model = tmp_path / "anomaly.joblib"
    _write_cic(csv)

    rc = main(["fit", "--dataset", str(csv), "--model-path", str(model), "--contamination", "0.05"])
    assert rc == 0
    assert model.exists()

    # The persisted model loads and scores a live flow event without error.
    det = AnomalyDetector(flow_features, model_path=model, kinds={"flow"})
    event = Event(source="suricata.eve", kind="flow", fields={
        "flow": {"bytes_toserver": 800, "bytes_toclient": 700,
                 "pkts_toserver": 10, "pkts_toclient": 9, "age": 1},
        "dest_port": 443, "proto": "tcp"})
    list(det.detect([event]))  # no raise → model is usable


def test_fit_missing_dataset_errors(tmp_path):
    with pytest.raises(FileNotFoundError):
        main(["fit", "--dataset", str(tmp_path / "nope.csv"), "--model-path", str(tmp_path / "m")])


@pytest.mark.parametrize("bad", ["0", "0.6", "1.0", "-0.1"])
def test_fit_rejects_out_of_range_contamination(tmp_path, bad):
    csv = tmp_path / "cic.csv"
    _write_cic(csv)
    with pytest.raises(SystemExit):  # argparse rejects the type before running
        main(["fit", "--dataset", str(csv), "--model-path", str(tmp_path / "m"),
              "--contamination", bad])


def test_fit_accepts_boundary_contamination(tmp_path):
    csv = tmp_path / "cic.csv"
    model = tmp_path / "m.joblib"
    _write_cic(csv)
    assert main(["fit", "--dataset", str(csv), "--model-path", str(model),
                 "--contamination", "0.5"]) == 0
