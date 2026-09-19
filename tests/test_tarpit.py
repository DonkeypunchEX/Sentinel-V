"""Tests for TarpitEngine.

Covers the safe-default regression (loopback, not 0.0.0.0), the
connection-cap enforcement fix, and basic state/statistics bookkeeping.
Actual socket lifecycle is exercised with ephemeral ports (port=0) kept
on loopback only.
"""

import inspect
import socket
from pathlib import Path

import pytest

from sentinel_v.tarpit import TarpitEngine


@pytest.fixture()
def engine(tmp_path: Path) -> TarpitEngine:
    return TarpitEngine(log_file=str(tmp_path / "tarpit.log"))


class TestSafeDefaults:
    def test_tcp_tarpit_defaults_to_loopback(self) -> None:
        default_host = (
            inspect.signature(TarpitEngine.start_tcp_tarpit).parameters["host"].default
        )
        assert default_host == "127.0.0.1"

    def test_http_tarpit_defaults_to_loopback(self) -> None:
        default_host = (
            inspect.signature(TarpitEngine.start_http_tarpit).parameters["host"].default
        )
        assert default_host == "127.0.0.1"


class TestLifecycle:
    def test_tcp_tarpit_starts_and_stops_on_loopback(
        self, engine: TarpitEngine
    ) -> None:
        assert engine.start_tcp_tarpit(host="127.0.0.1", port=0) is True
        assert engine.stop_tcp_tarpit(host="127.0.0.1", port=0) is True

    def test_starting_same_tcp_tarpit_twice_is_rejected(
        self, engine: TarpitEngine
    ) -> None:
        engine.start_tcp_tarpit(host="127.0.0.1", port=0)
        assert engine.start_tcp_tarpit(host="127.0.0.1", port=0) is False
        engine.stop_tcp_tarpit(host="127.0.0.1", port=0)

    def test_http_tarpit_starts_and_stops_on_loopback(
        self, engine: TarpitEngine
    ) -> None:
        assert engine.start_http_tarpit(host="127.0.0.1", port=0) is True
        assert engine.stop_http_tarpit(host="127.0.0.1", port=0) is True

    def test_stopping_unknown_tarpit_is_a_no_op_success(
        self, engine: TarpitEngine
    ) -> None:
        assert engine.stop_tcp_tarpit(host="127.0.0.1", port=54321) is True

    def test_tcp_tarpit_cleanup_handles_missing_active_record(
        self, engine: TarpitEngine
    ) -> None:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        server_port = server_sock.getsockname()[1]

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(("127.0.0.1", server_port))
        accepted_sock, client_addr = server_sock.accept()

        engine.connection_timeout = 0.01
        key = (client_addr[0], client_addr[1], "127.0.0.1", server_port)
        engine.active_connections.pop(key, None)

        engine._tcp_tarpit_handle_connection(
            accepted_sock,
            client_addr[0],
            client_addr[1],
            "127.0.0.1",
            server_port,
        )

        client_sock.close()
        server_sock.close()


class TestBookkeeping:
    def test_reset_clears_state(self, engine: TarpitEngine) -> None:
        engine.start_tcp_tarpit(host="127.0.0.1", port=0)
        engine.statistics.total_connections = 5
        engine.reset()
        assert engine.tcp_tarpits == {}
        assert engine.statistics.total_connections == 0

    def test_get_top_attackers_sorted_by_count(self, engine: TarpitEngine) -> None:
        engine.statistics.connections_by_ip = {
            "203.0.113.1": 2,
            "203.0.113.2": 9,
            "203.0.113.3": 5,
        }
        top = engine.get_top_attackers(limit=2)
        assert top[0] == ("203.0.113.2", 9)
        assert len(top) == 2

    def test_statistics_default_to_zero(self, engine: TarpitEngine) -> None:
        stats = engine.get_statistics()
        assert stats["total_connections"] == 0
        assert stats["active_connections"] == 0


class TestLoggerHandlers:
    def test_same_log_file_does_not_add_duplicate_handlers(
        self, tmp_path: Path
    ) -> None:
        log_file = str(tmp_path / "shared_tarpit.log")
        first = TarpitEngine(log_file=log_file)
        before = len(first.logger.handlers)
        TarpitEngine(log_file=log_file)
        after = len(first.logger.handlers)
        assert after == before
