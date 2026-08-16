#!/usr/bin/env python3
"""Minimal end-to-end usage of the Sentinel-V pipeline.

Runs entirely in-memory (no server, no external services):

    pip install -e ".[ml]"
    python examples/basic_usage.py

It builds a store, wires the Sigma rule detector, and ingests two Events — a
failed SSH login and a Suricata brute-force alert — printing the Alerts that
fire. This is the same seam the API's ``POST /events`` sits on.
"""
from __future__ import annotations

from pathlib import Path

from sentinel_v.collectors import AuthLogCollector, SuricataEveCollector
from sentinel_v.detection.rules import SigmaRuleDetector
from sentinel_v.pipeline import Pipeline
from sentinel_v.storage import Store


def main() -> None:
    store = Store("sqlite://")  # in-memory
    pipeline = Pipeline(store, [SigmaRuleDetector(Path("rules"))])

    auth = AuthLogCollector.parse_line(
        "Jan  1 12:00:00 host sshd[1234]: Failed password for invalid user "
        "admin from 1.2.3.4 port 22 ssh2"
    )
    suri = SuricataEveCollector.parse_line(
        '{"event_type":"alert","src_ip":"9.9.9.9","dest_ip":"10.0.0.1",'
        '"alert":{"signature":"ET SCAN SSH BruteForce"}}'
    )

    for event in (auth, suri):
        if event is None:
            continue
        _, alerts = pipeline.ingest(event)
        for alert in alerts:
            print(f"[{alert.severity}] {alert.title} "
                  f"(ATT&CK {alert.attack_technique}) src={event.src_ip}")

    print("store counts:", store.counts())


if __name__ == "__main__":
    main()
