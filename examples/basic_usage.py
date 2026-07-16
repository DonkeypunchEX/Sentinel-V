#!/usr/bin/env python3
"""Basic Sentinel-V usage: stand up a system and feed it events.

Run with only the base install:

    pip install -e .
    python examples/basic_usage.py
"""

import json

from sentinel_v import SentinelVSystem


def main() -> None:
    """Process a benign and a hostile event, then print system status."""
    sentinel = SentinelVSystem(
        {
            "system_mode": "test",
            "deception_network": "198.51.100.0/24",
            "decoy_count": 3,
        }
    )

    benign = {
        "source_ip": "192.168.1.10",
        "dest_ip": "192.168.1.1",
        "dest_port": 443,
        "protocol": "tcp",
    }
    hostile = {
        "source_ip": "203.0.113.66",
        "dest_ip": sentinel.deception_net.decoys[0],
        "dest_port": 22,
        "protocol": "tcp",
        "failed_auth": True,
        "payload_suspicious": True,
    }

    for event in (benign, hostile):
        assessment = sentinel.process_event(event)
        print(
            f"{event['source_ip']} -> {event['dest_ip']}:{event['dest_port']}  "
            f"level={assessment['threat_level']}  "
            f"score={assessment['anomaly_score']:.2f}  "
            f"decoy={assessment['is_decoy_interaction']}"
        )

    print("\nSystem status:")
    print(json.dumps(sentinel.get_system_status()["event_counts"], indent=2))

    sentinel.shutdown()


if __name__ == "__main__":
    main()
