"""Phase 1: collectors normalize source-native telemetry into Events."""
from __future__ import annotations

import json

from sentinel_v.collectors import AuthLogCollector, SuricataEveCollector


def test_suricata_parses_alert_with_nested_signature():
    rec = {
        "timestamp": "2024-01-01T12:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "9.9.9.9",
        "dest_ip": "10.0.0.1",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {"signature": "ET SCAN SSH BruteForce", "signature_id": 2001219},
    }
    e = SuricataEveCollector.parse_line(json.dumps(rec))
    assert e is not None
    assert e.source == "suricata.eve"
    assert e.kind == "alert"
    assert e.src_ip == "9.9.9.9"
    assert e.dst_ip == "10.0.0.1"
    assert e.fields["alert"]["signature"] == "ET SCAN SSH BruteForce"
    assert e.fields["dest_port"] == 22
    assert e.ts.year == 2024


def test_suricata_skips_blank_and_bad_json():
    assert SuricataEveCollector.parse_line("") is None
    assert SuricataEveCollector.parse_line("not json") is None
    assert SuricataEveCollector.parse_line("[1,2,3]") is None


def test_suricata_stream_from_file(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text(
        '{"event_type": "flow", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2"}\n'
        "\n"  # blank line ignored
        '{"event_type": "dns", "src_ip": "1.1.1.1"}\n'
    )
    events = list(SuricataEveCollector(eve).stream())
    assert [e.kind for e in events] == ["flow", "dns"]


def test_authlog_failed_password():
    line = (
        "Jan  1 12:00:00 host sshd[1234]: Failed password for invalid user "
        "admin from 1.2.3.4 port 22 ssh2"
    )
    e = AuthLogCollector.parse_line(line)
    assert e is not None
    assert e.kind == "auth_fail"
    assert e.src_ip == "1.2.3.4"
    assert e.host == "host"
    assert e.fields["user"] == "admin"
    assert e.fields["service"] == "sshd"
    assert e.fields["port"] == 22


def test_authlog_accepted_and_nonmatch():
    accepted = (
        "Feb 10 03:11:59 srv sshd[9]: Accepted password for deploy "
        "from 10.0.0.5 port 40100 ssh2"
    )
    e = AuthLogCollector.parse_line(accepted)
    assert e is not None and e.kind == "auth_success" and e.fields["user"] == "deploy"

    assert AuthLogCollector.parse_line("Jan  1 00:00:00 host cron[1]: session opened") is None
    assert AuthLogCollector.parse_line("garbage line") is None
