"""Baseline dataset loaders for fitting the anomaly detector on REAL data.

The quality bar (CLAUDE.md): the ML detector never trains on fabricated data. It
fits on a captured baseline or a labeled public dataset. This module turns such a
dataset into normalized benign Events in the canonical feature space (see
features.py) so ``AnomalyDetector.fit`` sees the same shape it will score live.

First-pass dataset: **CIC-IDS2017** (Canadian Institute for Cybersecurity). Point
``load_cic_ids2017_benign`` at a flow CSV; it yields only the ``BENIGN`` rows.
The dataset is not vendored (licensing + size) — supply your own path.
"""
from __future__ import annotations

import csv
from collections.abc import Iterator, Sequence
from pathlib import Path

from sentinel_v.models import Event

# CIC-IDS2017 column headers (whitespace-normalized) -> canonical feature keys.
_CIC_MAP = {
    "total length of fwd packets": "fwd_bytes",
    "total length of bwd packets": "bwd_bytes",
    "total fwd packets": "fwd_pkts",
    "total backward packets": "bwd_pkts",
    "flow duration": "duration_s",
    "destination port": "dst_port",
}


def load_cic_ids2017_benign(csv_path: str | Path, *, limit: int | None = None) -> Iterator[Event]:
    """Yield benign flow Events from a CIC-IDS2017 CSV.

    Raises FileNotFoundError with a clear message if the path is missing — we do
    not silently fall back to synthetic data.
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(
            f"CIC-IDS2017 baseline not found at {path}. Download the flow CSVs "
            "from the Canadian Institute for Cybersecurity, or capture your own "
            "baseline — this loader will not fabricate training data."
        )

    count = 0
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        header_map = _build_header_map(reader.fieldnames or [])
        label_col = _find_label_column(reader.fieldnames or [])
        if label_col is None:
            # Refuse to fit on unlabeled rows: without a Label column we cannot
            # tell benign from attack traffic, and letting attacks into the
            # baseline would quietly poison the model. Same loud posture as a
            # missing file.
            raise ValueError(
                f"No 'Label' column in {path}; refusing to fit on unlabeled rows "
                "(attack traffic would enter the benign baseline)."
            )
        for row in reader:
            if str(row.get(label_col, "")).strip().upper() != "BENIGN":
                continue
            fields: dict[str, object] = {
                canonical: _to_number(row.get(original))
                for original, canonical in header_map.items()
            }
            # CIC-IDS2017 records flow duration in MICROSECONDS; the live
            # Suricata extractor uses seconds. Normalize to seconds so the model
            # fits and scores on the same unit (see detection/features.py).
            if "duration_s" in fields:
                fields["duration_s"] = _to_number(fields["duration_s"]) / 1_000_000.0
            yield Event(source="dataset.cic-ids2017", kind="flow", fields=fields)
            count += 1
            if limit is not None and count >= limit:
                return


def _build_header_map(fieldnames: Sequence[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for name in fieldnames:
        key = name.strip().lower()
        if key in _CIC_MAP:
            mapping[name] = _CIC_MAP[key]
    return mapping


def _find_label_column(fieldnames: Sequence[str]) -> str | None:
    for name in fieldnames:
        if name.strip().lower() == "label":
            return name
    return None


def _to_number(value: object) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return 0.0
