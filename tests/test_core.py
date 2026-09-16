"""Tests for the SentinelVSystem orchestrator."""

import json
from typing import Any, Dict

from sentinel_v import SentinelVSystem, create_sentinel_system
from sentinel_v.core import SystemMode
from sentinel_v.paths import status_file


def _benign_event() -> Dict[str, Any]:
    return {
        "source_ip": "192.168.1.10",
        "dest_ip": "192.168.1.1",
        "dest_port": 443,
        "protocol": "tcp",
    }


def _hostile_event(port: int = 22) -> Dict[str, Any]:
    return {
        "source_ip": "203.0.113.66",
        "dest_ip": "198.51.100.7",
        "dest_port": port,
        "protocol": "tcp",
        "failed_auth": True,
        "payload_suspicious": True,
    }


def test_system_initializes_operational(system: SentinelVSystem) -> None:
    assert system.status == "operational"
    assert system.mode == SystemMode.PRODUCTION
    assert len(system.system_id) == 16


def test_benign_event_produces_assessment(system: SentinelVSystem) -> None:
    assessment = system.process_event(_benign_event())
    assert "error" not in assessment
    assert assessment["threat_level"] == "BENIGN"
    assert 0.0 <= assessment["anomaly_score"] <= 1.0
    assert assessment["event"]["event_id"]
    assert system.metrics.events_processed == 1
    assert system.metrics.threats_detected == 0


def test_hostile_event_detected_and_responded(system: SentinelVSystem) -> None:
    assessment = system.process_event(_hostile_event())
    assert assessment["threat_level"] in ("MALICIOUS", "CRITICAL")
    assert system.metrics.threats_detected == 1
    # production mode runs the (simulation-safe) autonomous response
    assert assessment["response_executed"]["simulated"] is True
    assert "log_event" in assessment["response_executed"]["executed_actions"]


def test_decoy_interaction_is_flagged(system: SentinelVSystem) -> None:
    decoy = system.deception_net.decoys[0]
    event = _hostile_event()
    event["dest_ip"] = decoy
    assessment = system.process_event(event)
    assert assessment["is_decoy_interaction"] is True


def test_benign_decoy_contact_still_escalates(system: SentinelVSystem) -> None:
    # A single, otherwise unremarkable request scores BENIGN on its own —
    # but any contact with a decoy has no legitimate explanation, so it
    # must still escalate through the response engine.
    decoy = system.deception_net.decoys[0]
    event = {
        "source_ip": "8.8.8.8",
        "dest_ip": decoy,
        "dest_port": 443,
        "protocol": "tcp",
    }
    assessment = system.process_event(event)
    assert assessment["threat_level"] == "BENIGN"
    assert assessment["is_decoy_interaction"] is True
    assert "response_executed" in assessment
    assert assessment["response_details"]["escalation_step"] >= 1
    assert system.metrics.threats_detected == 1


def test_sustained_scan_escalates_to_critical_and_shares(
    system: SentinelVSystem,
) -> None:
    # fan out across ports, then hammer a sensitive service (SMB)
    for port in range(1000, 1014):
        system.process_event(_hostile_event(port=port))
    last = system.process_event(_hostile_event(port=445))
    assert last["threat_level"] == "CRITICAL"
    # CRITICAL threats are queued for the federation with minimized fields
    assert system.federation.outbox
    shared = system.federation.outbox[-1]
    assert shared["origin_node"] == system.system_id
    assert "event" not in shared


def test_event_validation_normalizes(system: SentinelVSystem) -> None:
    validated = system._validate_event({"source_ip": "localhost"})
    assert validated["source_ip"] == "127.0.0.1"
    assert validated["event_id"]
    assert validated["timestamp"]


def test_external_ip_classification(system: SentinelVSystem) -> None:
    assert system._is_external_ip("8.8.8.8") is True
    assert system._is_external_ip("10.1.2.3") is False
    assert system._is_external_ip("172.20.0.1") is False
    assert system._is_external_ip("192.168.0.9") is False
    assert system._is_external_ip("127.0.0.1") is False
    assert system._is_external_ip("not-an-ip") is True


def test_external_ip_classification_ipv6(system: SentinelVSystem) -> None:
    assert system._is_external_ip("2001:4860:4860::8888") is True  # public
    assert system._is_external_ip("::1") is False  # loopback
    assert system._is_external_ip("fc00::1") is False  # unique local
    assert system._is_external_ip("fe80::1") is False  # link-local


def test_external_ip_classification_link_local(system: SentinelVSystem) -> None:
    assert system._is_external_ip("169.254.1.5") is False
    assert system._is_external_ip("169.254.255.255") is False


def test_external_ip_classification_cgnat(system: SentinelVSystem) -> None:
    # 100.64.0.0/10 (RFC 6598 shared address space / carrier-grade NAT)
    assert system._is_external_ip("100.64.0.1") is False
    assert system._is_external_ip("100.100.0.1") is False
    assert system._is_external_ip("100.127.255.255") is False
    # just outside the /10 on either side stays external
    assert system._is_external_ip("100.63.255.255") is True
    assert system._is_external_ip("100.128.0.0") is True


def test_external_ip_classification_multicast(system: SentinelVSystem) -> None:
    assert system._is_external_ip("224.0.0.1") is False  # IPv4 multicast
    assert system._is_external_ip("239.255.255.250") is False  # SSDP
    assert system._is_external_ip("ff02::1") is False  # IPv6 multicast


def test_normalize_ip_handles_ipv6_loopback(system: SentinelVSystem) -> None:
    assert system._normalize_ip("::1") == "::1"
    # fully expanded form collapses to the canonical compressed form
    assert system._normalize_ip("0:0:0:0:0:0:0:1") == "::1"


def test_normalize_ip_passes_through_invalid_input(system: SentinelVSystem) -> None:
    assert system._normalize_ip("not-an-ip") == "not-an-ip"
    assert system._normalize_ip("") == ""
    assert system._normalize_ip("999.999.999.999") == "999.999.999.999"


def test_status_report_structure(system: SentinelVSystem) -> None:
    system.process_event(_benign_event())
    status = system.get_system_status()
    assert status["system_id"] == system.system_id
    assert status["components"]["deception_network"]["active_decoys"] == 3
    assert status["event_counts"]["total_processed"] == 1
    assert status["components"]["federation"]["enabled"] is True


def test_shutdown_is_clean(system: SentinelVSystem) -> None:
    assert system.monitor_thread.is_alive()
    system.shutdown()
    assert system.status == "shutdown"
    assert system.shutdown_flag.is_set()
    assert system.federation.joined is False
    assert not system.monitor_thread.is_alive()

    # Shutdown is safe to call again after all lifecycle resources are closed.
    system.shutdown()
    assert not system.monitor_thread.is_alive()


def test_create_from_yaml_and_json(tmp_path: Any) -> None:
    yaml_file = tmp_path / "config.yaml"
    yaml_file.write_text("system_mode: test\ndecoy_count: 2\n")
    sentinel = create_sentinel_system(str(yaml_file))
    assert sentinel.mode == SystemMode.TESTING
    assert len(sentinel.deception_net.decoys) == 2
    sentinel.shutdown()

    json_file = tmp_path / "config.json"
    json_file.write_text(json.dumps({"system_mode": "dev"}))
    sentinel = create_sentinel_system(str(json_file), overrides={"decoy_count": 4})
    assert sentinel.mode == SystemMode.DEVELOPMENT
    assert len(sentinel.deception_net.decoys) == 4
    sentinel.shutdown()


def test_heartbeat_written_and_removed_on_shutdown(
    tmp_path: Any, monkeypatch: Any
) -> None:
    monkeypatch.setenv("SENTINEL_V_STATE_DIR", str(tmp_path))

    sentinel = create_sentinel_system(write_status_file=True)
    sentinel._write_heartbeat()

    payload = json.loads(status_file().read_text())
    assert payload["system_id"] == sentinel.system_id
    assert payload["pid"] > 0
    assert "last_updated" in payload

    sentinel.shutdown()
    assert not status_file().exists()


def test_no_heartbeat_without_write_status_file_flag(
    tmp_path: Any, monkeypatch: Any
) -> None:
    monkeypatch.setenv("SENTINEL_V_STATE_DIR", str(tmp_path))

    sentinel = create_sentinel_system()
    sentinel.shutdown()

    assert not status_file().exists()
