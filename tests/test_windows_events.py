"""Tests for the Windows Sysmon/Security event collector.

These exercise the pure shaping logic and the collector's poll loop
against a stubbed ``_query`` - they never touch a real event log or spawn
PowerShell, so they run on any platform, not just Windows.
"""

import subprocess
from datetime import datetime, timedelta
from typing import Any, Dict, List

from sentinel_v import SentinelVSystem
from sentinel_v.windows_events import (
    WindowsEventCollector,
    shape_dns_query,
    shape_event,
    shape_failed_logon,
    shape_network_connect,
    shape_process_create,
)


def test_shape_process_create_maps_sysmon_fields() -> None:
    event = shape_process_create(
        {
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ParentImage": r"C:\Windows\explorer.exe",
            "User": "DESKTOP\\alice",
        }
    )
    assert event["event_type"] == "process_create"
    assert event["process_name"] == r"C:\Windows\System32\cmd.exe"
    assert event["command_line"] == "cmd.exe /c whoami"
    assert event["dest_port"] == 0
    assert event["source_ip"]  # some local IP, exact value is host-dependent


def test_shape_network_connect_maps_and_coerces_port() -> None:
    event = shape_network_connect(
        {
            "SourceIp": "10.0.0.5",
            "DestinationIp": "203.0.113.9",
            "DestinationPort": "445",
            "Protocol": "TCP",
            "Image": r"C:\malware.exe",
        }
    )
    assert event["source_ip"] == "10.0.0.5"
    assert event["dest_ip"] == "203.0.113.9"
    assert event["dest_port"] == 445
    assert event["protocol"] == "tcp"


def test_shape_network_connect_defaults_unparseable_port_to_zero() -> None:
    event = shape_network_connect({"DestinationPort": "not-a-port"})
    assert event["dest_port"] == 0


def test_shape_dns_query_extracts_resolved_ip() -> None:
    event = shape_dns_query(
        {
            "QueryName": "evil.example.com",
            "QueryResults": "type: 5 evil.cdn.example.com;::ffff:198.51.100.7;",
        }
    )
    assert event["domain"] == "evil.example.com"
    assert event["dest_ip"] == "198.51.100.7"
    assert event["dest_port"] == 53
    assert event["protocol"] == "dns"


def test_shape_dns_query_handles_no_resolved_ip() -> None:
    event = shape_dns_query({"QueryName": "nxdomain.example.com", "QueryResults": ""})
    assert event["dest_ip"] == ""


def test_shape_failed_logon_maps_ip_and_marks_failed_auth() -> None:
    event = shape_failed_logon(
        {
            "IpAddress": "198.51.100.23",
            "TargetUserName": "administrator",
            "LogonType": "10",
        }
    )
    assert event["source_ip"] == "198.51.100.23"
    assert event["failed_auth"] is True
    assert event["dest_port"] == 3389  # RDP, from LogonType
    assert event["user"] == "administrator"


def test_shape_failed_logon_defaults_missing_ip_to_local() -> None:
    event = shape_failed_logon({"IpAddress": "-", "LogonType": "2"})
    assert event["source_ip"] == "127.0.0.1"
    assert event["dest_port"] == 0  # LogonType 2 (Interactive) has no port mapping


def test_shape_event_dispatches_on_log_and_id() -> None:
    record = {
        "LogName": "Microsoft-Windows-Sysmon/Operational",
        "EventId": 3,
        "TimeCreated": "2026-09-15T12:00:00Z",
        "Data": {"SourceIp": "10.0.0.1", "DestinationPort": "22"},
    }
    event = shape_event(record)
    assert event is not None
    assert event["event_type"] == "network_connect"
    assert event["timestamp"] == "2026-09-15T12:00:00Z"


def test_shape_event_returns_none_for_unhandled_ids() -> None:
    record = {"LogName": "Application", "EventId": 1000, "Data": {}}
    assert shape_event(record) is None


def _stub_collector(
    sentinel: SentinelVSystem, records_by_call: List[List[Dict[str, Any]]]
) -> WindowsEventCollector:
    collector = WindowsEventCollector(sentinel)
    calls = iter(records_by_call)
    collector._query = lambda since: next(calls, [])  # type: ignore[method-assign]
    return collector


def test_poll_once_feeds_events_into_sentinel_and_advances_bookmark(
    system: SentinelVSystem,
) -> None:
    collector = _stub_collector(
        system,
        [
            [
                {
                    "LogName": "Microsoft-Windows-Sysmon/Operational",
                    "EventId": 3,
                    "TimeCreated": "2026-09-15T12:00:00",
                    "Data": {
                        "SourceIp": "203.0.113.9",
                        "DestinationIp": "10.0.0.1",
                        "DestinationPort": "22",
                        "Protocol": "tcp",
                    },
                },
                {
                    "LogName": "Security",
                    "EventId": 4625,
                    "TimeCreated": "2026-09-15T12:00:05",
                    "Data": {"IpAddress": "203.0.113.9", "LogonType": "10"},
                },
            ]
        ],
    )
    collector._since = datetime(2026, 1, 1)
    before = collector._since

    assessments = collector.poll_once()

    assert len(assessments) == 2
    assert all("error" not in a for a in assessments)
    assert collector._since == datetime(2026, 9, 15, 12, 0, 5)
    assert collector._since > before


def test_poll_once_skips_unrecognized_records_without_erroring(
    system: SentinelVSystem,
) -> None:
    collector = _stub_collector(
        system, [[{"LogName": "Application", "EventId": 999, "Data": {}}]]
    )

    assessments = collector.poll_once()

    assert assessments == []


def test_poll_once_survives_query_failure(system: SentinelVSystem) -> None:
    collector = WindowsEventCollector(system)

    def _raise(since: datetime) -> List[Dict[str, Any]]:
        raise subprocess.TimeoutExpired(cmd="powershell", timeout=60)

    collector._query = _raise  # type: ignore[method-assign]

    assert collector.poll_once() == []


def test_run_forever_stops_when_event_is_set(system: SentinelVSystem) -> None:
    import threading

    collector = _stub_collector(system, [[], [], []])
    stop_event = threading.Event()
    collector.poll_interval = 0

    poll_count = {"n": 0}
    original_poll_once = collector.poll_once

    def _counted_poll_once() -> List[Dict[str, Any]]:
        poll_count["n"] += 1
        if poll_count["n"] >= 2:
            stop_event.set()
        return original_poll_once()

    collector.poll_once = _counted_poll_once  # type: ignore[method-assign]
    collector.run_forever(stop_event)

    assert poll_count["n"] == 2
