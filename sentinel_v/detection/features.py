"""Feature engineering for the ML anomaly detector.

Feature engineering matters more than model choice (docs/RND.md). We use a small
canonical **flow feature** vector so the *same* extractor works on two inputs:

* a live Suricata ``flow`` Event (nested ``flow.bytes_toserver`` etc.), and
* a baseline row loaded from CIC-IDS2017 (mapped onto the same canonical keys).

That symmetry is the whole point: fit on a real baseline, score live traffic in
the identical feature space. No fabricated features — a missing field is 0.0,
never random.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sentinel_v.models import Event

# Canonical, fixed-order feature space. Keep this stable alongside any persisted
# model; changing the order invalidates a saved model.
FEATURE_NAMES: tuple[str, ...] = (
    "fwd_bytes",
    "bwd_bytes",
    "fwd_pkts",
    "bwd_pkts",
    "duration_s",
    "dst_port",
    "proto",
)

_PROTO_CODE = {"tcp": 6.0, "udp": 17.0, "icmp": 1.0}


def _num(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool) or value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _proto_code(value: Any) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        return _PROTO_CODE.get(value.strip().lower(), 0.0)
    return 0.0


def flow_features(event: Event) -> Sequence[float]:
    """Extract the canonical flow feature vector from an Event.

    Reads canonical keys first (dataset rows), then falls back to Suricata's
    nested ``flow`` structure so a single feature_fn serves fit and detect.
    """
    f = event.fields
    raw_flow = f.get("flow")
    flow: dict[str, Any] = raw_flow if isinstance(raw_flow, dict) else {}

    def pick(canonical: str, *fallbacks: Any) -> float:
        if canonical in f:
            return _num(f[canonical])
        for fb in fallbacks:
            if fb is not None:
                return _num(fb)
        return 0.0

    fwd_bytes = pick("fwd_bytes", flow.get("bytes_toserver"))
    bwd_bytes = pick("bwd_bytes", flow.get("bytes_toclient"))
    fwd_pkts = pick("fwd_pkts", flow.get("pkts_toserver"))
    bwd_pkts = pick("bwd_pkts", flow.get("pkts_toclient"))
    # duration_s is defined in SECONDS for every producer. Suricata flow.age is
    # already seconds; the CIC-IDS2017 loader converts its microseconds to
    # seconds before it ever reaches this slot (see detection/datasets.py).
    duration = pick("duration_s", flow.get("age"))
    dst_port = pick("dst_port", f.get("dest_port"))
    proto = _proto_code(f.get("proto")) if "proto" in f else 0.0

    return [fwd_bytes, bwd_bytes, fwd_pkts, bwd_pkts, duration, dst_port, proto]
