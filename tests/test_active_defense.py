"""Tests for ActiveDefenseEngine.

Covers the safety-critical contract: simulation by default, real
commands only under enforce_mode, and the injection-gate that rejects
any value that doesn't round-trip through ipaddress validation before
it can reach a subprocess argument or a firewall config file.
"""

from pathlib import Path
from typing import Any

import pytest

from sentinel_v.active_defense import ActiveDefenseEngine


@pytest.fixture()
def engine(tmp_path: Path) -> ActiveDefenseEngine:
    return ActiveDefenseEngine(log_file=str(tmp_path / "active_defense.log"))


class TestValidation:
    def test_malformed_ip_is_rejected(self, engine: ActiveDefenseEngine) -> None:
        # A crafted value containing a newline plus a firewall directive
        # must never be treated as "not internal, safe to proceed".
        payload = "1.2.3.4\npass in all\n#"
        assert engine.block_ip(payload) is False
        assert payload not in engine.blocked_ips

    def test_malformed_ip_rejected_by_isolate_host(
        self, engine: ActiveDefenseEngine
    ) -> None:
        engine.auto_isolate = True
        assert engine.isolate_host("1.2.3.4\nblock all\n#") is False

    def test_malformed_source_rejected_by_rate_limit(
        self, engine: ActiveDefenseEngine
    ) -> None:
        assert engine.rate_limit("1.2.3.4\n#", port=80) is False

    def test_rate_limit_rejects_bad_port(self, engine: ActiveDefenseEngine) -> None:
        assert engine.rate_limit("203.0.113.5", port=70000) is False
        assert engine.rate_limit("203.0.113.5", port=0) is False

    def test_rate_limit_rejects_bad_protocol(self, engine: ActiveDefenseEngine) -> None:
        assert engine.rate_limit("203.0.113.5", port=80, protocol="icmp") is False

    def test_block_network_rejects_invalid_cidr(
        self, engine: ActiveDefenseEngine
    ) -> None:
        assert engine.block_network("not-a-network") is False

    def test_internal_ip_is_never_blocked(self, engine: ActiveDefenseEngine) -> None:
        assert engine.block_ip("192.168.1.10") is False
        assert "192.168.1.10" not in engine.blocked_ips


class TestSimulationMode:
    """enforce_mode defaults to False: state is tracked, nothing runs."""

    def test_block_ip_never_shells_out_when_not_enforced(
        self, engine: ActiveDefenseEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _boom(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("subprocess.run must not be called in simulation mode")

        monkeypatch.setattr("sentinel_v.active_defense.subprocess.run", _boom)
        engine.block_ip("203.0.113.5", reason="test")

    def test_actions_are_logged_regardless_of_enforcement(
        self, engine: ActiveDefenseEngine
    ) -> None:
        engine.block_ip("203.0.113.5", reason="test")
        assert engine.action_history[-1]["action"] == "block_ip"
        assert engine.action_history[-1]["enforce_mode"] is False


class TestBookkeeping:
    def test_duplicate_block_is_idempotent(self, engine: ActiveDefenseEngine) -> None:
        engine.enforce_mode = True
        engine.blocked_ips.add("203.0.113.5")
        assert engine.block_ip("203.0.113.5") is True

    def test_unblock_unknown_ip_is_a_no_op_success(
        self, engine: ActiveDefenseEngine
    ) -> None:
        assert engine.unblock_ip("203.0.113.99") is True

    def test_statistics_reflect_state(self, engine: ActiveDefenseEngine) -> None:
        engine.enforce_mode = True
        engine.blocked_ips.add("203.0.113.5")
        stats = engine.get_statistics()
        assert stats["total_blocked_ips"] == 1
        assert stats["enforce_mode"] is True

    def test_reset_clears_all_state(self, engine: ActiveDefenseEngine) -> None:
        engine.blocked_ips.add("203.0.113.5")
        engine.action_history.append({"action": "block_ip"})
        engine.reset()
        assert engine.blocked_ips == set()
        assert engine.action_history == []

    def test_action_history_is_bounded(self, engine: ActiveDefenseEngine) -> None:
        for i in range(10001):
            engine._save_action("block_ip", f"203.0.113.{i % 250}", "flood", False)
        assert len(engine.action_history) <= 10000


class TestLoggerHandlers:
    def test_same_log_file_does_not_add_duplicate_handlers(
        self, tmp_path: Path
    ) -> None:
        # "sentinel_v.active_defense" is a process-global named logger, so
        # this only asserts the same (engine, log_file) pair doesn't pile
        # up handlers - not that the logger has exactly one handler total
        # (other tests/log files in this session may have added their own).
        log_file = str(tmp_path / "shared.log")
        first = ActiveDefenseEngine(log_file=log_file)
        before = len(first.logger.handlers)
        ActiveDefenseEngine(log_file=log_file)
        after = len(first.logger.handlers)
        assert after == before
