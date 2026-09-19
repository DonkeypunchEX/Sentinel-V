"""Tests for ThreatHunter.

Includes a regression test for the constructor crash found in review:
the state_dir parameter shadowed the module-level state_dir import, so
plain ThreatHunter() raised TypeError on every default instantiation.
"""

from pathlib import Path

import pytest

from sentinel_v.threat_hunting import ThreatHunter

# EICAR test file's real MD5 - already in KNOWN_MALWARE_HASHES as a
# built-in example.
EICAR_MD5 = "d41d8cd98f00b204e9800998ecf8427e"


@pytest.fixture()
def hunter(tmp_path: Path) -> ThreatHunter:
    return ThreatHunter(state_dir_override=str(tmp_path / "hunter"))


class TestConstruction:
    def test_default_instantiation_does_not_crash(self, tmp_path: Path) -> None:
        # Regression test: ThreatHunter() used to raise
        # TypeError: 'NoneType' object is not callable.
        hunter = ThreatHunter(state_dir_override=str(tmp_path / "default"))
        assert hunter.iocs  # builtin IoCs loaded

    def test_builtin_iocs_are_loaded(self, hunter: ThreatHunter) -> None:
        matched, ioc = hunter.check_ioc("ip", "1.1.1.1")
        assert matched is True
        assert ioc is not None
        assert ioc.description == "Known C2 Server"


class TestIocManagement:
    def test_add_and_check_custom_ioc(self, hunter: ThreatHunter) -> None:
        hunter.add_ioc(
            ioc_type="domain",
            value="bad.example",
            description="test feed",
            confidence=0.7,
            source="unit-test",
        )
        matched, ioc = hunter.check_ioc("domain", "bad.example")
        assert matched is True
        assert ioc.source == "unit-test"

    def test_unknown_value_does_not_match(self, hunter: ThreatHunter) -> None:
        matched, ioc = hunter.check_ioc("ip", "203.0.113.99")
        assert matched is False
        assert ioc is None


class TestFilesystemScan:
    def test_known_hash_is_flagged(self, hunter: ThreatHunter, tmp_path: Path) -> None:
        target_dir = tmp_path / "scan_target"
        target_dir.mkdir()
        # MD5(b"") == EICAR_MD5 in KNOWN_MALWARE_HASHES
        (target_dir / "empty.bin").write_bytes(b"")

        result = hunter.scan_filesystem([str(target_dir)])
        assert result.total_items_scanned == 1
        hash_matches = [f for f in result.findings if f["type"] == "malware_hash_match"]
        assert any(f["hash_value"] == EICAR_MD5 for f in hash_matches)

    def test_clean_file_produces_no_findings(
        self, hunter: ThreatHunter, tmp_path: Path
    ) -> None:
        target_dir = tmp_path / "scan_target"
        target_dir.mkdir()
        (target_dir / "readme.txt").write_text("nothing suspicious here")

        result = hunter.scan_filesystem([str(target_dir)])
        assert result.total_findings == 0

    def test_scan_records_history(self, hunter: ThreatHunter, tmp_path: Path) -> None:
        hunter.scan_filesystem([str(tmp_path)])
        assert len(hunter.scan_history) == 1


class TestStatistics:
    def test_statistics_reflect_state(self, hunter: ThreatHunter) -> None:
        stats = hunter.get_statistics()
        assert stats["total_iocs"] == len(hunter.iocs)
        assert stats["total_scans"] == 0
