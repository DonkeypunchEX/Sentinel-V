import json
from datetime import datetime

from sentinel_v.dashboard import (
    read_dashboard_status,
    read_recent_logs,
    serve_dashboard,
)
from sentinel_v.paths import main_log_file, status_file


def test_dashboard_returns_offline_without_heartbeat(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_V_STATE_DIR", str(tmp_path))

    status = read_dashboard_status()

    assert status["status"] == "offline"
    assert status["metrics"]["events_processed"] == 0


def test_dashboard_reads_heartbeat_and_recent_logs(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_V_STATE_DIR", str(tmp_path))
    status_file().write_text(
        json.dumps(
            {
                "status": "operational",
                "system_id": "node-1",
                "last_updated": datetime.now().isoformat(),
                "metrics": {"events_processed": 4},
            }
        ),
        encoding="utf-8",
    )
    main_log_file().write_text("one\ntwo\nthree\n", encoding="utf-8")

    assert read_dashboard_status()["system_id"] == "node-1"
    assert read_recent_logs(2) == ["two", "three"]


def test_browser_opens_only_after_server_socket_is_bound(monkeypatch):
    # Regression test: opening the browser before the HTTP server exists
    # risks a connection-refused on the very first page load. Track call
    # order via a shared list rather than call order isn't observable
    # by patching serve_forever separately.
    events = []

    class _FakeServer:
        def __init__(self, addr, handler):
            events.append("bound")

        def serve_forever(self):
            events.append("serve_forever")

        def server_close(self):
            pass

    monkeypatch.setattr("sentinel_v.dashboard.ThreadingHTTPServer", _FakeServer)
    monkeypatch.setattr(
        "webbrowser.open", lambda url: events.append("browser_open")
    )

    serve_dashboard(open_browser=True)

    assert events == ["bound", "browser_open", "serve_forever"]
