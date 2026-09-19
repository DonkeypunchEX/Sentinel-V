"""Small dependency-free web dashboard for Sentinel-V."""

from __future__ import annotations

import json
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .paths import main_log_file, status_file


def _offline_status() -> dict[str, Any]:
    return {
        "status": "offline",
        "system_id": None,
        "mode": "unknown",
        "defense_level": "unknown",
        "uptime": 0,
        "metrics": {
            "events_processed": 0,
            "threats_detected": 0,
            "false_positives": 0,
            "resource_usage": {},
        },
        "components": {},
        "last_updated": None,
    }


def read_dashboard_status() -> dict[str, Any]:
    """Return the latest heartbeat, or a safe offline status payload."""
    try:
        payload = json.loads(status_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _offline_status()

    if not isinstance(payload, dict):
        return _offline_status()

    last_updated = payload.get("last_updated")
    if last_updated:
        try:
            age = (
                datetime.now() - datetime.fromisoformat(last_updated)
            ).total_seconds()
            if age > 90:
                payload["status"] = "offline"
        except ValueError:
            payload["status"] = "offline"
    return payload


def read_recent_logs(limit: int = 30) -> list[str]:
    """Read the most recent log lines without failing the dashboard request."""
    try:
        log_path = main_log_file()
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    keep = max(1, min(limit, 100))
    return lines[-keep:]


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve the dashboard shell and its tiny JSON API."""

    server_version = "SentinelVDashboard/1.0"

    def do_GET(self) -> None:  # noqa: N802
        route = urlparse(self.path).path
        if route == "/":
            self._send(200, "text/html; charset=utf-8", DASHBOARD_HTML.encode())
        elif route == "/api/status":
            self._send_json(read_dashboard_status())
        elif route == "/api/logs":
            self._send_json({"lines": read_recent_logs()})
        else:
            self._send_json({"error": "Not found"}, 404)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self._send(status, "application/json; charset=utf-8", body)

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve_dashboard(
    host: str = "127.0.0.1", port: int = 8765, open_browser: bool = False
) -> None:
    """Run the dashboard server until interrupted.

    ``open_browser`` is handled here, after the socket is bound (the
    ThreadingHTTPServer constructor calls bind()/listen()), rather than
    by the caller beforehand - opening the browser before the server
    exists risks a connection-refused on the very first page load.
    """
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    url = f"http://{host}:{port}"
    try:
        print(f"Sentinel-V dashboard available at {url}")
        if open_browser:
            import webbrowser

            webbrowser.open(url)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard.")
    finally:
        server.server_close()


DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel-V / Command Center</title>
<style>
:root{color-scheme:dark;--bg:#07111f;--panel:#0d1b2d;--panel2:#11243a;--line:#1d3853;
--text:#e7f0f7;--muted:#8ea5b8;--cyan:#63e6e2;--green:#6ee7a1;--amber:#f4c56b;--red:#ff7f8e}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 85% 0,#123b53 0,transparent 33%),var(--bg);
color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,sans-serif}
.shell{max-width:1320px;
margin:auto;padding:28px 28px 44px}.top{display:flex;align-items:center;justify-content:space-between;
gap:24px;margin-bottom:30px}
.brand{display:flex;align-items:center;gap:14px}.mark{width:42px;
height:42px;border:1px solid var(--cyan);border-radius:13px;display:grid;place-items:center;
color:var(--cyan);font-size:21px;box-shadow:0 0 28px #37d9d433}.eyebrow{color:var(--cyan);
font-size:11px;font-weight:700;letter-spacing:.18em;text-transform:uppercase}.title{font-size:24px;
font-weight:750;letter-spacing:-.03em}.subtitle{color:var(--muted);font-size:12px}
.status{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:12px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--red);box-shadow:0 0 12px currentColor}
.online .dot{background:var(--green);color:var(--green)}
.hero{display:grid;grid-template-columns:1.6fr 1fr;
gap:18px;margin-bottom:18px}.panel{border:1px solid var(--line);background:linear-gradient(145deg,#10243aee,#0b1727ee);
border-radius:18px;padding:22px;box-shadow:0 18px 50px #0003}.hero-main{min-height:210px;
display:flex;flex-direction:column;justify-content:space-between}.label{color:var(--muted);
font-size:11px;letter-spacing:.13em;text-transform:uppercase}.hero h1{font-size:42px;
line-height:1.05;margin:10px 0 8px;letter-spacing:-.05em}.hero p{color:var(--muted);
max-width:550px;margin:0}.pill{display:inline-flex;align-items:center;gap:8px;border:1px solid #2c6173;
border-radius:999px;padding:6px 10px;color:var(--cyan);font-size:12px}.pill:before{content:"";
width:6px;height:6px;background:currentColor;border-radius:50%}
.grid{display:grid;
grid-template-columns:repeat(4,1fr);gap:18px;margin-bottom:18px}.metric{min-height:125px}
.metric .value{font-size:34px;font-weight:740;letter-spacing:-.05em;margin-top:18px}
.metric .hint{color:var(--muted);font-size:12px}.accent{color:var(--cyan)}.warn{color:var(--amber)}
.danger{color:var(--red)}
.lower{display:grid;grid-template-columns:1.1fr 1.9fr;
gap:18px}.panel-head{display:flex;justify-content:space-between;align-items:center;
margin-bottom:18px}.panel-title{font-weight:700;font-size:15px}.tiny{color:var(--muted);
font-size:12px}.resources{display:grid;gap:15px}.resource{display:grid;grid-template-columns:72px 1fr 42px;
align-items:center;gap:12px;color:var(--muted);font-size:12px}.bar{height:7px;background:#183049;
border-radius:99px;overflow:hidden}.fill{height:100%;width:0;background:linear-gradient(90deg,var(--cyan),#8d9cff);
border-radius:inherit;transition:width .4s}.logs{height:230px;overflow:auto;background:#07111c;
border:1px solid #142a40;border-radius:12px;padding:14px;font:12px/1.7 ui-monospace,SFMono-Regular,Consolas,monospace;
color:#a9bfd0;white-space:pre-wrap}.empty{color:var(--muted);font-family:inherit}
@media(max-width:900px){.hero,.lower{grid-template-columns:1fr}.grid{grid-template-columns:repeat(2,1fr)}
}@media(max-width:560px){.shell{padding:18px 14px}.top{align-items:flex-start;flex-direction:column}
.grid{grid-template-columns:1fr 1fr}.hero h1{font-size:34px}}
</style></head>
<body><main class="shell">
<header class="top"><div class="brand"><div class="mark">✦</div><div><div class="eyebrow">Sentinel-V / Command Center</div><div class="title">Autonomous defense, at a glance.</div><div class="subtitle">Live telemetry from the local Sentinel-V daemon</div></div></div><div id="connection" class="status"><span class="dot"></span><span>Connecting…</span></div></header>
<section class="hero"><div class="panel hero-main"><div><span class="pill" id="mode">Mode unknown</span><h1 id="headline">System offline</h1><p id="description">Start the Sentinel-V daemon to stream health, threat, and resource data into this view.</p></div><div class="subtitle" id="updated">Waiting for heartbeat</div></div><div class="panel"><div class="panel-head"><span class="panel-title">Defense posture</span><span class="tiny" id="system-id">No node</span></div><div class="label">Current level</div><div class="value accent" id="defense">—</div><div class="subtitle" style="margin-top:12px">Adaptive response engine is monitoring the node and adjusting to threat volume.</div></div></section>
<section class="grid"><div class="panel metric"><div class="label">Events processed</div><div class="value" id="events">—</div><div class="hint">all telemetry</div></div><div class="panel metric"><div class="label">Threats detected</div><div class="value danger" id="threats">—</div><div class="hint">requiring attention</div></div><div class="panel metric"><div class="label">Active decoys</div><div class="value accent" id="decoys">—</div><div class="hint">deception network</div></div><div class="panel metric"><div class="label">Uptime</div><div class="value" id="uptime">—</div><div class="hint">daemon runtime</div></div></section>
<section class="lower"><div class="panel"><div class="panel-head"><span class="panel-title">Resource health</span><span class="tiny">host telemetry</span></div><div class="resources" id="resources"><div class="empty">No heartbeat data yet.</div></div></div><div class="panel"><div class="panel-head"><span class="panel-title">Recent activity</span><span class="tiny">auto-refresh · 5s</span></div><div class="logs" id="logs"><span class="empty">No log activity yet.</span></div></div></section>
</main><script>
const $=id=>document.getElementById(id), fmt=n=>Number(n||0).toLocaleString(), duration=s=>{s=Number(s||0);
if(s<60)return `${Math.round(s)}s`;if(s<3600)return `${Math.floor(s/60)}m ${Math.floor(s%60)}s`;
return `${Math.floor(s/3600)}h ${Math.floor(s%3600/60)}m`};
async function refresh(){try{const [sr,lr]=await Promise.all([fetch('/api/status'),fetch('/api/logs')]),s=await sr.json(),l=await lr.json(),m=s.metrics||{},r=m.resource_usage||{},online=s.status!=='offline';
$('connection').className='status '+(online?'online':'');$('connection').lastElementChild.textContent=online?'Daemon online':'Daemon offline';
$('headline').textContent=online?'System operational':'System offline';$('description').textContent=online?'Telemetry is flowing. The response engine is watching for behavioral anomalies.':'Start the Sentinel-V daemon to stream health, threat, and resource data into this view.';
$('mode').textContent=`Mode ${s.mode||'unknown'}`;$('defense').textContent=s.defense_level||'—';
$('system-id').textContent=s.system_id?`Node ${s.system_id}`:'No node';$('updated').textContent=s.last_updated?`Last heartbeat · ${new Date(s.last_updated).toLocaleTimeString()}`:'Waiting for heartbeat';
$('events').textContent=fmt(m.events_processed);$('threats').textContent=fmt(m.threats_detected);
$('decoys').textContent=fmt((s.event_counts||{}).active_decoys);$('uptime').textContent=duration(s.uptime);
$('resources').innerHTML=['cpu','memory','disk','bandwidth'].map(k=>{const v=Math.round(Number(r[k]||0)*100);
return `<div class="resource"><span>${k}</span><div class="bar"><div class="fill" style="width:${Math.min(v,100)}%"></div></div><b>${v}%</b></div>`}).join('');
$('logs').textContent=l.lines?.join('\n')||'No log activity yet.'}catch(e){$('connection').lastElementChild.textContent='Dashboard API unavailable'}}refresh();
setInterval(refresh,5000);
</script></body></html>"""
