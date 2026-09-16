"""Tests for the sentinel-v command line interface."""

import json
from datetime import datetime, timedelta
from typing import Any

from click.testing import CliRunner

from sentinel_v.cli import cli
from sentinel_v.paths import status_file


def test_status_command_reports_not_running_with_no_daemon(
    tmp_path: Any, monkeypatch: Any
) -> None:
    monkeypatch.setenv("SENTINEL_V_STATE_DIR", str(tmp_path))

    result = CliRunner().invoke(cli, ["status"])

    assert result.exit_code == 0
    assert "not running" in result.output
    assert "System Status" not in result.output


def test_status_command_reports_stale_heartbeat_as_not_running(
    tmp_path: Any, monkeypatch: Any
) -> None:
    monkeypatch.setenv("SENTINEL_V_STATE_DIR", str(tmp_path))
    stale_time = datetime.now() - timedelta(minutes=5)
    status_file().write_text(
        json.dumps({"system_id": "abc123", "last_updated": stale_time.isoformat()})
    )

    result = CliRunner().invoke(cli, ["status"])

    assert result.exit_code == 0
    assert "not running" in result.output
    assert "stale heartbeat" in result.output


def test_status_command_reports_live_daemon(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("SENTINEL_V_STATE_DIR", str(tmp_path))
    status_file().write_text(
        json.dumps(
            {
                "system_id": "abc123",
                "status": "operational",
                "pid": 4242,
                "uptime": 12.5,
                "last_updated": datetime.now().isoformat(),
                "metrics": {
                    "events_processed": 7,
                    "threats_detected": 2,
                    "resource_usage": {"cpu": 0.1, "memory": 0.2},
                },
            }
        )
    )

    result = CliRunner().invoke(cli, ["status"])

    assert result.exit_code == 0
    assert "Sentinel-V System Status" in result.output
    assert "abc123" in result.output
    assert "PID: 4242" in result.output
    assert "Events Processed: 7" in result.output


def test_analyze_command(tmp_path: Any) -> None:
    events = [{"source_ip": "192.168.1.4", "dest_port": 443}]
    event_file = tmp_path / "events.json"
    event_file.write_text(json.dumps(events))
    out_file = tmp_path / "results.json"

    result = CliRunner().invoke(
        cli, ["analyze", str(event_file), "--output", str(out_file)]
    )
    assert result.exit_code == 0
    results = json.loads(out_file.read_text())
    assert len(results) == 1
    assert results[0]["threat_level"] == "BENIGN"


def test_deploy_decoys_command() -> None:
    result = CliRunner().invoke(
        cli, ["deploy-decoys", "--network", "198.51.100.0/28", "--count", "3"]
    )
    assert result.exit_code == 0
    assert result.output.count("Deployed decoy") == 3
    assert "3 active decoys" in result.output


def test_validate_config(tmp_path: Any) -> None:
    good = tmp_path / "good.yaml"
    good.write_text("system_mode: production\ndefense_level: standard\n")
    result = CliRunner().invoke(cli, ["validate-config", str(good)])
    assert result.exit_code == 0
    assert "valid" in result.output

    bad = tmp_path / "bad.yaml"
    bad.write_text("system_mode: production\n")
    result = CliRunner().invoke(cli, ["validate-config", str(bad)])
    assert result.exit_code == 1
    assert "defense_level" in result.output


def test_export_sbom(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli, ["export-sbom"])
    assert result.exit_code == 0
    sbom = json.loads((tmp_path / "sbom.json").read_text())
    names = [c["name"].lower() for c in sbom["components"]]
    assert "sentinel-v" in names or "sentinel_v" in names
