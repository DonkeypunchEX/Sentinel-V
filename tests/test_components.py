"""Unit tests for the individual defense components."""

from typing import Any

import pytest

from sentinel_v.crypto import QuantumResistantCrypto
from sentinel_v.deception import DeceptionNetwork
from sentinel_v.federation import FederatedDefenseNode
from sentinel_v.monitoring import AdaptiveThreatMatrix, ThreatLevel
from sentinel_v.response import AutonomousResponseEngine


class TestAdaptiveThreatMatrix:
    def test_benign_traffic_scores_low(self) -> None:
        matrix = AdaptiveThreatMatrix()
        score, level = matrix.analyze(
            {"source_ip": "192.168.1.5", "dest_port": 443, "protocol": "tcp"}
        )
        assert score < 0.3
        assert level == ThreatLevel.BENIGN

    def test_hostile_signals_raise_level(self) -> None:
        matrix = AdaptiveThreatMatrix()
        score, level = matrix.analyze(
            {
                "source_ip": "203.0.113.9",
                "dest_port": 22,
                "protocol": "tcp",
                "failed_auth": True,
                "payload_suspicious": True,
            }
        )
        assert score >= 0.6
        assert level in (ThreatLevel.MALICIOUS, ThreatLevel.CRITICAL)

    def test_port_scan_fan_out_escalates(self) -> None:
        matrix = AdaptiveThreatMatrix()
        level = ThreatLevel.BENIGN
        for port in range(1000, 1012):
            _, level = matrix.analyze(
                {"source_ip": "203.0.113.9", "dest_port": port, "protocol": "tcp"}
            )
        assert level.value >= ThreatLevel.SUSPICIOUS.value

    def test_memory_stays_bounded(self) -> None:
        matrix = AdaptiveThreatMatrix(memory_size=100)
        for i in range(500):
            matrix.analyze({"source_ip": f"10.0.{i % 50}.1", "dest_port": i % 65535})
        assert len(matrix.attack_memory) <= 100
        assert len(matrix.patterns) <= 101

    def test_garbage_port_is_tolerated(self) -> None:
        matrix = AdaptiveThreatMatrix()
        score, level = matrix.analyze({"source_ip": "x", "dest_port": "not-a-port"})
        assert 0.0 <= score <= 1.0


class TestResponseEngine:
    def _assessment(self, level: str, decoy: bool = False) -> dict:
        return {
            "threat_id": "t-1",
            "threat_level": level,
            "is_decoy_interaction": decoy,
            "event": {"source_ip": "203.0.113.9"},
        }

    def test_response_is_proportional(self) -> None:
        engine = AutonomousResponseEngine()
        benign = engine.evaluate_threat(self._assessment("BENIGN"))
        critical = engine.evaluate_threat(self._assessment("CRITICAL"))
        assert benign["actions"] == ["log_event"]
        assert "recommend_isolation" in critical["actions"]

    def test_decoy_interaction_escalates_one_step(self) -> None:
        engine = AutonomousResponseEngine()
        plain = engine.evaluate_threat(self._assessment("SUSPICIOUS"))
        decoy = engine.evaluate_threat(self._assessment("SUSPICIOUS", decoy=True))
        assert decoy["escalation_step"] == plain["escalation_step"] + 1

    def test_escalation_is_capped(self) -> None:
        engine = AutonomousResponseEngine(max_escalation=1)
        response = engine.evaluate_threat(self._assessment("CRITICAL", decoy=True))
        assert response["escalation_step"] == 1

    def test_execution_is_simulation_only_and_recorded(self) -> None:
        engine = AutonomousResponseEngine()
        response = engine.evaluate_threat(self._assessment("MALICIOUS"))
        receipt = engine.execute_response(response)
        assert receipt["simulated"] is True
        assert receipt["executed_actions"] == response["actions"]
        assert engine.response_history[-1] is receipt


class TestDeceptionNetwork:
    def test_decoys_are_allocated_in_range(self) -> None:
        net = DeceptionNetwork("198.51.100.0/24", decoy_count=5)
        assert len(net.decoys) == 5
        assert all(ip.startswith("198.51.100.") for ip in net.decoys)

    def test_inactive_network_detects_nothing(self) -> None:
        net = DeceptionNetwork("198.51.100.0/24", decoy_count=2)
        assert net.detect_interaction("203.0.113.1", net.decoys[0]) is False

    def test_active_network_flags_decoy_contact(self) -> None:
        net = DeceptionNetwork("198.51.100.0/24", decoy_count=2)
        net.active = True
        assert net.detect_interaction("203.0.113.1", net.decoys[0], 22) is True
        assert net.detect_interaction("203.0.113.1", "198.51.100.250", 22) is False
        stats = net.get_statistics()
        assert stats["interactions_recorded"] == 1
        assert stats["active_decoys"] == 2

    def test_invalid_range_falls_back(self) -> None:
        net = DeceptionNetwork("not-a-network", decoy_count=2)
        assert len(net.decoys) == 2


class TestCrypto:
    def test_key_agreement_and_roundtrip(self) -> None:
        alice = QuantumResistantCrypto()
        bob = QuantumResistantCrypto()
        k1 = alice.derive_shared_key(bob.public_key_bytes)
        k2 = bob.derive_shared_key(alice.public_key_bytes)
        assert k1 == k2

        nonce, ciphertext = alice.encrypt(k1, b"threat intel payload")
        assert bob.decrypt(k2, nonce, ciphertext) == b"threat intel payload"

    def test_tampering_is_detected(self) -> None:
        alice = QuantumResistantCrypto()
        bob = QuantumResistantCrypto()
        key = alice.derive_shared_key(bob.public_key_bytes)
        nonce, ciphertext = alice.encrypt(key, b"payload")
        with pytest.raises(Exception):
            bob.decrypt(key, nonce, ciphertext[:-1] + b"\x00")

    def test_unknown_algorithm_falls_back(self) -> None:
        crypto = QuantumResistantCrypto(algorithm="unobtainium")
        assert crypto.algorithm == "lattice"


class TestFederation:
    def test_join_share_leave(self) -> None:
        node = FederatedDefenseNode("node-a")
        assert node.join_network() is True
        record = node.share_threat_intelligence(
            {
                "threat_id": "t-9",
                "threat_level": "CRITICAL",
                "anomaly_score": 0.91,
                "timestamp": "2026-01-01T00:00:00",
                "event": {"source_ip": "203.0.113.9", "secret": "internal"},
            }
        )
        assert record["origin_node"] == "node-a"
        assert "event" not in record  # raw events never leave the node
        assert node.outbox == [record]
        node.leave_network()
        assert node.joined is False
        assert node.connected_nodes == []

    def test_share_ioc_queues_and_dedupes(self) -> None:
        node = FederatedDefenseNode("node-a")
        assert node.share_ioc("ip", "203.0.113.9", "scanner", 0.9) is True
        assert node.share_ioc("ip", "203.0.113.9", "scanner", 0.9) is False
        assert len(node.get_shared_iocs()) == 1

    def test_share_ioc_rejects_unknown_type(self) -> None:
        node = FederatedDefenseNode("node-a")
        assert node.share_ioc("mac_address", "aa:bb", "n/a", 0.5) is False

    def test_receive_ioc_rejects_invalid_type_or_empty_value(self) -> None:
        node = FederatedDefenseNode("node-a")
        assert node.receive_ioc({"ioc_type": "bogus", "value": "x"}) is False
        assert node.receive_ioc({"ioc_type": "ip", "value": ""}) is False

    def test_sync_with_peer_exchanges_iocs(self) -> None:
        alice = FederatedDefenseNode("alice")
        bob = FederatedDefenseNode("bob")
        alice.join_network()
        bob.join_network()

        alice.share_ioc("ip", "203.0.113.9", "scanner", 0.9)
        bob.share_ioc("domain", "evil.example", "c2", 0.8)

        # sync_with_peer is bidirectional: alice pushes her IoC to bob
        # and pulls bob's IoC back, so 2 IoCs change hands total.
        exchanged = alice.sync_with_peer(bob)
        assert exchanged == 2
        assert any(ioc["value"] == "evil.example" for ioc in alice.get_received_iocs())
        assert any(ioc["value"] == "203.0.113.9" for ioc in bob.get_received_iocs())

    def test_peer_trust_starts_neutral_and_updates_on_receive(self) -> None:
        node = FederatedDefenseNode("node-a")
        assert node.get_peer_trust("unknown-peer") == 0.0
        node.receive_ioc(
            {
                "ioc_type": "ip",
                "value": "203.0.113.9",
                "origin_node": "peer-b",
                "confidence": 0.9,
            }
        )
        assert node.get_peer_trust("peer-b") > 0.0

    def test_save_and_load_state_round_trips(self, tmp_path: Any) -> None:
        node = FederatedDefenseNode("node-a")
        node.state_dir = tmp_path
        node.share_ioc("ip", "203.0.113.9", "scanner", 0.9)

        assert node.save_state() is True

        restored = FederatedDefenseNode("node-a")
        restored.state_dir = tmp_path
        assert restored.load_state() is True
        assert "ip:203.0.113.9" in restored.shared_iocs


class TestDeceptionEnhancements:
    def test_canary_tokens_are_unique_and_tracked(self) -> None:
        net = DeceptionNetwork("198.51.100.0/24", decoy_count=1)
        tokens = net.generate_canary_tokens(5)
        assert len(tokens) == 5
        assert len(set(tokens)) == 5
        assert all(net.check_canary_token(t) for t in tokens)
        assert net.check_canary_token("not-a-real-token") is False

    def test_deploy_honey_files_creates_files_with_canary_tokens(
        self, tmp_path: Any
    ) -> None:
        net = DeceptionNetwork("198.51.100.0/24", decoy_count=1)
        created = net.deploy_honey_files(str(tmp_path), count=3)

        assert len(created) == 3
        for path in created:
            assert path.exists()
            token = net.check_honey_file_access(str(path))
            assert token is not None
            assert net.check_canary_token(token)

    def test_honey_file_access_check_is_none_for_unknown_path(
        self, tmp_path: Any
    ) -> None:
        net = DeceptionNetwork("198.51.100.0/24", decoy_count=1)
        net.deploy_honey_files(str(tmp_path), count=1)
        assert (
            net.check_honey_file_access(str(tmp_path / "not_a_honeyfile.txt")) is None
        )

    def test_statistics_include_new_counters(self, tmp_path: Any) -> None:
        net = DeceptionNetwork("198.51.100.0/24", decoy_count=1)
        net.deploy_honey_files(str(tmp_path), count=2)
        stats = net.get_statistics()
        assert stats["honey_files_count"] == 2
        assert stats["canary_tokens_count"] >= 2
