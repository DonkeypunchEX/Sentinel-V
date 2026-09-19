"""Tarpit Module - Waste attacker time and resources.

Provides capabilities to:
- Create TCP tarpits that accept connections but never complete
- Create HTTP tarpits that serve fake content very slowly
- Create DNS tarpits that delay responses
- Create fake services that appear vulnerable but are harmless

Tarpits are designed to:
- Slow down automated scanners
- Waste attacker time and resources
- Provide fake vulnerability signatures
- Log all attacker interactions

All tarpit actions are passive and do not initiate connections
to external systems.
"""

import json
import logging
import random
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .paths import tarpit_log_file

# Cap on a single POST body the HTTP tarpit will buffer in memory,
# regardless of the client-declared Content-Length.
MAX_POST_BODY_BYTES = 10 * 1024 * 1024


@dataclass
class TarpitConnection:
    """Represents an active tarpit connection."""

    source_ip: str
    source_port: int
    target_ip: str
    target_port: int
    protocol: str
    start_time: str
    end_time: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "duration": self.get_duration(),
        }

    def get_duration(self) -> Optional[float]:
        """Get connection duration in seconds."""
        if self.end_time:
            start = datetime.fromisoformat(self.start_time)
            end = datetime.fromisoformat(self.end_time)
            return (end - start).total_seconds()
        return None


@dataclass
class TarpitStatistics:
    """Statistics for tarpit operations."""

    total_connections: int = 0
    active_connections: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    total_time_wasted: float = 0.0  # seconds
    connections_by_ip: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_connections": self.total_connections,
            "active_connections": self.active_connections,
            "total_bytes_sent": self.total_bytes_sent,
            "total_bytes_received": self.total_bytes_received,
            "total_time_wasted": self.total_time_wasted,
            "connections_by_ip": self.connections_by_ip,
        }


class TarpitEngine:
    """Manages tarpit services to waste attacker time.

    Provides multiple types of tarpits:
    - TCP: Accepts connections but never sends data
    - HTTP: Serves fake content very slowly
    - SMB: Fake SMB server that delays responses
    - RDP: Fake RDP server that appears to negotiate but stalls

    All tarpits are designed to:
    - Appear legitimate to automated scanners
    - Waste attacker time and resources
    - Log all interactions for analysis
    - Be completely passive (no outbound connections)
    """

    def __init__(
        self,
        log_file: Optional[str] = None,
        max_connections: int = 100,
        connection_timeout: int = 300,  # 5 minutes
    ):
        """Initialize the Tarpit Engine.

        Args:
            log_file: Path to log file
            max_connections: Maximum number of concurrent connections
            connection_timeout: Timeout in seconds for tarpit connections
        """
        self.log_file = log_file or str(tarpit_log_file())
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout

        # State tracking
        self.active_connections: Dict[Tuple[str, int, str, int], TarpitConnection] = {}
        self.connection_history: List[TarpitConnection] = []
        self.statistics = TarpitStatistics()

        # Tarpit servers
        self.tcp_tarpits: Dict[Tuple[str, int], socket.socket] = {}
        self.http_tarpits: Dict[Tuple[str, int], HTTPServer] = {}
        self.http_tarpit_threads: Dict[Tuple[str, int], threading.Thread] = {}

        # Setup logging
        self._setup_logging()

        logging.info(
            f"TarpitEngine initialized (max_connections={self.max_connections}, "
            f"connection_timeout={self.connection_timeout})"
        )

    def _setup_logging(self) -> None:
        """Configure logging for tarpit operations."""
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)

        # Create a dedicated logger
        self.logger = logging.getLogger("sentinel_v.tarpit")
        self.logger.setLevel(logging.INFO)

        # self.logger is a module-level named logger, so constructing more
        # than one TarpitEngine in the same process must not pile up
        # duplicate handlers - that would both leak file descriptors and
        # duplicate every log line (see the same fix in active_defense.py).
        resolved_log_file = str(Path(self.log_file).resolve())
        if not any(
            isinstance(h, logging.FileHandler) and h.baseFilename == resolved_log_file
            for h in self.logger.handlers
        ):
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(logging.INFO)
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def start_tcp_tarpit(
        self,
        host: str = "127.0.0.1",
        port: int = 9000,
    ) -> bool:
        """Start a TCP tarpit on the specified host and port.

        The tarpit accepts connections but never sends any data,
        keeping the attacker waiting indefinitely (or until timeout).

        Args:
            host: Host to bind to. Defaults to loopback - exposing a
                tarpit on a routable interface is an explicit operator
                decision, not a default (same convention as
                DynamicHoneypot in deception.py).
            port: Port to listen on

        Returns:
            True if tarpit started successfully, False otherwise
        """
        if (host, port) in self.tcp_tarpits:
            logging.warning(f"TCP tarpit already running on {host}:{port}")
            return False

        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(self.max_connections)

            # Store socket
            self.tcp_tarpits[(host, port)] = sock

            # Start accept thread
            threading.Thread(
                target=self._tcp_tarpit_accept_loop,
                args=(host, port, sock),
                daemon=True,
            ).start()

            logging.info(f"TCP tarpit started on {host}:{port}")
            return True
        except Exception as e:
            logging.error(f"Failed to start TCP tarpit on {host}:{port}: {e}")
            return False

    def _tcp_tarpit_accept_loop(
        self,
        host: str,
        port: int,
        sock: socket.socket,
    ) -> None:
        """Accept loop for TCP tarpit."""
        while (host, port) in self.tcp_tarpits:
            try:
                client_sock, client_addr = sock.accept()
                client_ip = client_addr[0]
                client_port = client_addr[1]

                # Enforce the configured connection cap here - passing
                # max_connections to listen() only bounds the kernel's
                # pending-accept backlog, not how many connections this
                # loop goes on to track and hand a thread to.
                if len(self.active_connections) >= self.max_connections:
                    logging.warning(
                        f"TCP tarpit: rejecting {client_ip}:{client_port}, "
                        f"at max_connections={self.max_connections}"
                    )
                    client_sock.close()
                    continue

                logging.info(f"TCP tarpit: connection from {client_ip}:{client_port}")

                # Track connection
                conn = TarpitConnection(
                    source_ip=client_ip,
                    source_port=client_port,
                    target_ip=host,
                    target_port=port,
                    protocol="tcp",
                    start_time=datetime.now().isoformat(),
                )
                self.active_connections[(client_ip, client_port, host, port)] = conn
                self.statistics.active_connections += 1
                self.statistics.total_connections += 1
                self.statistics.connections_by_ip[client_ip] = (
                    self.statistics.connections_by_ip.get(client_ip, 0) + 1
                )

                # Handle connection in a separate thread
                threading.Thread(
                    target=self._tcp_tarpit_handle_connection,
                    args=(client_sock, client_ip, client_port, host, port),
                    daemon=True,
                ).start()

            except Exception as e:
                if (host, port) in self.tcp_tarpits:
                    logging.error(f"Error in TCP tarpit accept loop: {e}")
                break

    def _tcp_tarpit_handle_connection(
        self,
        client_sock: socket.socket,
        client_ip: str,
        client_port: int,
        host: str,
        port: int,
    ) -> None:
        """Handle a single TCP tarpit connection."""
        try:
            # Set timeout
            client_sock.settimeout(self.connection_timeout)

            # Just hold the connection open without sending anything.
            # This wastes the attacker's time. No inner catch-all here:
            # socket.timeout is the only expected exception (handled
            # below) and anything else should reach the outer handler's
            # logging rather than vanish silently.
            while True:
                # Try to receive data (but don't respond)
                try:
                    data = client_sock.recv(1024)
                    if not data:
                        break
                    # Update statistics
                    key = (client_ip, client_port, host, port)
                    if key in self.active_connections:
                        self.active_connections[key].bytes_received += len(data)
                        self.statistics.total_bytes_received += len(data)
                except socket.timeout:
                    # Connection timed out
                    break

                # Sleep briefly to avoid busy waiting
                time.sleep(0.1)

        except Exception as e:
            logging.error(f"Error handling TCP tarpit connection: {e}")
        finally:
            # Close connection - already broken/closing, nothing to act on
            try:
                client_sock.close()
            except Exception:  # nosec B110
                pass

            # Update connection end time
            key = (client_ip, client_port, host, port)
            conn: Optional[TarpitConnection] = None
            if key in self.active_connections:
                conn = self.active_connections.pop(key)
                conn.end_time = datetime.now().isoformat()
                self.connection_history.append(conn)
                self.statistics.active_connections -= 1

                # Update time wasted
                duration = conn.get_duration()
                if duration:
                    self.statistics.total_time_wasted += duration

            duration = conn.get_duration() if conn else 0.0
            logging.info(
                f"TCP tarpit: connection closed from {client_ip}:{client_port} "
                f"(duration: {duration:.1f}s)"
            )

    def stop_tcp_tarpit(self, host: str, port: int) -> bool:
        """Stop a TCP tarpit.

        Args:
            host: Host the tarpit is bound to
            port: Port the tarpit is listening on

        Returns:
            True if tarpit stopped successfully, False otherwise
        """
        key = (host, port)
        if key not in self.tcp_tarpits:
            return True

        try:
            sock = self.tcp_tarpits.pop(key)
            sock.close()
            logging.info(f"TCP tarpit stopped on {host}:{port}")
            return True
        except Exception as e:
            logging.error(f"Failed to stop TCP tarpit on {host}:{port}: {e}")
            return False

    def start_http_tarpit(
        self,
        host: str = "127.0.0.1",
        port: int = 8081,
    ) -> bool:
        """Start an HTTP tarpit on the specified host and port.

        The tarpit serves fake content very slowly, wasting attacker time.

        Args:
            host: Host to bind to. Defaults to loopback - exposing a
                tarpit on a routable interface is an explicit operator
                decision, not a default.
            port: Port to listen on

        Returns:
            True if tarpit started successfully, False otherwise
        """
        if (host, port) in self.http_tarpits:
            logging.warning(f"HTTP tarpit already running on {host}:{port}")
            return False

        try:
            # Create HTTP server with custom handler
            def handler_class(*args: Any) -> "TarpitHTTPHandler":
                return TarpitHTTPHandler(*args, tarpit=self)

            server = HTTPServer((host, port), handler_class)

            # Store server
            self.http_tarpits[(host, port)] = server

            # Start server in a thread
            thread = threading.Thread(
                target=server.serve_forever,
                daemon=True,
            )
            self.http_tarpit_threads[(host, port)] = thread
            thread.start()

            logging.info(f"HTTP tarpit started on {host}:{port}")
            return True
        except Exception as e:
            logging.error(f"Failed to start HTTP tarpit on {host}:{port}: {e}")
            return False

    def stop_http_tarpit(self, host: str, port: int) -> bool:
        """Stop an HTTP tarpit.

        Args:
            host: Host the tarpit is bound to
            port: Port the tarpit is listening on

        Returns:
            True if tarpit stopped successfully, False otherwise
        """
        key = (host, port)
        if key not in self.http_tarpits:
            return True

        try:
            server = self.http_tarpits.pop(key)
            server.shutdown()

            # Thread will exit on its own once the server shuts down.
            self.http_tarpit_threads.pop(key, None)

            logging.info(f"HTTP tarpit stopped on {host}:{port}")
            return True
        except Exception as e:
            logging.error(f"Failed to stop HTTP tarpit on {host}:{port}: {e}")
            return False

    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Get list of currently active tarpit connections.

        Returns:
            List of active connection dictionaries
        """
        return [conn.to_dict() for conn in self.active_connections.values()]

    def get_connection_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent connection history.

        Args:
            limit: Maximum number of connections to return

        Returns:
            List of connection dictionaries
        """
        return [conn.to_dict() for conn in self.connection_history[-limit:]]

    def get_statistics(self) -> Dict[str, Any]:
        """Get tarpit statistics.

        Returns:
            Dictionary with tarpit statistics
        """
        return self.statistics.to_dict()

    def get_top_attackers(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top attacking IPs by connection count.

        Args:
            limit: Maximum number of IPs to return

        Returns:
            List of (ip, count) tuples sorted by count descending
        """
        sorted_ips = sorted(
            self.statistics.connections_by_ip.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        return sorted_ips[:limit]

    def reset(self) -> None:
        """Reset all tarpit state (for testing)."""
        # Stop all tarpits - best-effort close, state is being torn down
        for key, sock in self.tcp_tarpits.items():
            try:
                sock.close()
            except Exception:  # nosec B110
                pass
        self.tcp_tarpits.clear()

        for key, server in self.http_tarpits.items():
            try:
                server.shutdown()
            except Exception:  # nosec B110
                pass
        self.http_tarpits.clear()
        self.http_tarpit_threads.clear()

        # Clear connections
        self.active_connections.clear()
        self.connection_history.clear()
        self.statistics = TarpitStatistics()

        logging.info("TarpitEngine reset")


class TarpitHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the tarpit.

    Serves fake content very slowly to waste attacker time.
    """

    # Class-level storage for tarpit engine reference
    tarpit: Optional[TarpitEngine] = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.tarpit = kwargs.pop("tarpit", None)
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        """Override to use Python logging instead of print."""
        if self.tarpit:
            self.tarpit.logger.info(f"HTTP Tarpit: {format % args}")

    @staticmethod
    def _host_port(address: Any) -> Tuple[str, int]:
        """Extract (host, port) from a socket address.

        BaseServer.server_address / BaseRequestHandler.client_address are
        typed as a union that also covers AF_UNIX (str) addresses; this
        tarpit only ever binds AF_INET/AF_INET6 sockets, so narrowing
        here once keeps every call site simple.
        """
        return str(address[0]), int(address[1])

    def _track_connection(self, method: str, path: str) -> None:
        """Track an HTTP connection."""
        if not self.tarpit:
            return

        client_ip, client_port = self._host_port(self.client_address)
        target_ip, target_port = self._host_port(self.server.server_address)

        # Create connection record
        conn = TarpitConnection(
            source_ip=client_ip,
            source_port=client_port,
            target_ip=target_ip,
            target_port=target_port,
            protocol="http",
            start_time=datetime.now().isoformat(),
        )

        key = (client_ip, client_port, target_ip, target_port)
        self.tarpit.active_connections[key] = conn
        self.tarpit.statistics.active_connections += 1
        self.tarpit.statistics.total_connections += 1
        self.tarpit.statistics.connections_by_ip[client_ip] = (
            self.tarpit.statistics.connections_by_ip.get(client_ip, 0) + 1
        )

        logging.info(f"HTTP tarpit: {method} {path} from {client_ip}:{client_port}")

    def _update_connection(self, bytes_sent: int = 0, bytes_received: int = 0) -> None:
        """Update connection statistics."""
        if not self.tarpit:
            return

        client_ip, client_port = self._host_port(self.client_address)
        target_ip, target_port = self._host_port(self.server.server_address)
        key = (client_ip, client_port, target_ip, target_port)

        if key in self.tarpit.active_connections:
            conn = self.tarpit.active_connections[key]
            conn.bytes_sent += bytes_sent
            conn.bytes_received += bytes_received
            self.tarpit.statistics.total_bytes_sent += bytes_sent
            self.tarpit.statistics.total_bytes_received += bytes_received

    def _end_connection(self) -> None:
        """End connection tracking."""
        if not self.tarpit:
            return

        client_ip, client_port = self._host_port(self.client_address)
        target_ip, target_port = self._host_port(self.server.server_address)
        key = (client_ip, client_port, target_ip, target_port)

        if key in self.tarpit.active_connections:
            conn = self.tarpit.active_connections.pop(key)
            conn.end_time = datetime.now().isoformat()
            self.tarpit.connection_history.append(conn)
            self.tarpit.statistics.active_connections -= 1

            # Update time wasted
            duration = conn.get_duration()
            if duration:
                self.tarpit.statistics.total_time_wasted += duration

    def do_GET(self) -> None:
        """Handle GET requests with deliberate slowness."""
        self._track_connection("GET", self.path)

        # Parse URL
        parsed = urlparse(self.path)

        # Delay before sending response - timing jitter, not a security
        # value, so the standard (non-cryptographic) RNG is fine here.
        delay = random.uniform(5.0, 15.0)  # nosec B311 - 5-15 seconds
        time.sleep(delay)

        # Send very slow response
        if parsed.path == "/":
            self._send_slow_index()
        elif parsed.path.startswith("/api/"):
            self._send_slow_api_response()
        elif parsed.path.startswith("/admin/"):
            self._send_slow_admin_page()
        elif parsed.path.endswith(".php"):
            self._send_slow_php_response()
        else:
            self._send_slow_404()

        self._end_connection()

    def do_POST(self) -> None:
        """Handle POST requests with deliberate slowness."""
        self._track_connection("POST", self.path)

        # Read the body (slowly), capped so a declared multi-GB
        # Content-Length can't be used to exhaust the defender's own
        # memory - the whole point is wasting the attacker's time, not
        # the host running the tarpit.
        content_length = min(
            int(self.headers.get("Content-Length", 0)), MAX_POST_BODY_BYTES
        )
        body = b""
        if content_length > 0:
            # Read in small chunks with delays
            remaining = content_length
            while remaining > 0:
                chunk_size = min(1024, remaining)
                chunk = self.rfile.read(chunk_size)
                if not chunk:
                    break
                body += chunk
                remaining -= len(chunk)
                time.sleep(0.1)  # Delay between chunks

        self._update_connection(bytes_received=len(body))

        # Delay before sending response - timing jitter, not a security value
        delay = random.uniform(10.0, 30.0)  # nosec B311 - 10-30 seconds
        time.sleep(delay)

        # Send response
        self._send_slow_response(b"POST received\n")

        self._end_connection()

    def _send_slow_response(self, content: bytes, status_code: int = 200) -> None:
        """Send a response very slowly."""
        self.send_response(status_code)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()

        # Send data in small chunks with delays
        chunk_size = 100
        for i in range(0, len(content), chunk_size):
            end = i + chunk_size
            chunk = content[i:end]
            self.wfile.write(chunk)
            self.wfile.flush()
            time.sleep(0.1)  # Delay between chunks

        self._update_connection(bytes_sent=len(content))

    def _send_slow_index(self) -> None:
        """Send a fake index page very slowly."""
        html = b"""<!DOCTYPE html>
<html>
<head>
    <title>Welcome to the Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .vulnerable { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Welcome to the Server</h1>
    <p>This is a production server. Unauthorized access is prohibited.</p>
    <div class="vulnerable">
        <p>Warning: Outdated software detected!</p>
        <p>Apache/2.2.15 (Unix) PHP/5.3.10</p>
    </div>
    <p><a href="/admin/">Admin Login</a></p>
    <p><a href="/api/status">API Status</a></p>
    <p><a href="/phpinfo.php">PHP Info</a></p>
</body>
</html>"""
        self._send_slow_response(html)

    def _send_slow_admin_page(self) -> None:
        """Send a fake admin login page very slowly."""
        html = b"""<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .login-box { border: 1px solid #ccc; padding: 20px; width: 300px; }
        input { width: 100%; padding: 8px; margin: 5px 0; }
        button { width: 100%; padding: 10px; background: #4CAF50; color: white; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Admin Login</h2>
        <form method="POST" action="/admin/login">
            <label>Username:</label>
            <input type="text" name="username" placeholder="Enter username">
            <label>Password:</label>
            <input type="password" name="password" placeholder="Enter password">
            <button type="submit">Login</button>
        </form>
        <p>Default credentials: admin:admin123</p>
    </div>
</body>
</html>"""
        self._send_slow_response(html)

    def _send_slow_api_response(self) -> None:
        """Send a fake API response very slowly."""
        json_response = json.dumps(
            {
                "status": "success",
                "version": "1.0.0",
                "data": {
                    "users": [
                        {"id": 1, "username": "admin", "role": "administrator"},
                        {"id": 2, "username": "user1", "role": "user"},
                        {"id": 3, "username": "backup", "role": "user"},
                    ],
                    "databases": [
                        {"name": "production", "host": "localhost"},
                        {"name": "staging", "host": "localhost"},
                        {"name": "backup", "host": "localhost"},
                    ],
                    "config": {
                        "debug": True,
                        # Fake bait values served to attackers, not real
                        # secrets - not a hardcoded credential in this repo.
                        "secret_key": "sk-1234567890abcdef",  # nosec B105
                        "api_key": "ak-9876543210fedcba",
                    },
                },
                "timestamp": datetime.now().isoformat(),
            }
        ).encode()
        self._send_slow_response(json_response)

    def _send_slow_php_response(self) -> None:
        """Send a fake PHP response very slowly."""
        html = b"""<?php
// Database Configuration
$DB_HOST = 'localhost';
$DB_USER = 'root';
$DB_PASS = 'password123';
$DB_NAME = 'production';

// API Keys
$API_KEY = 'sk-1234567890abcdef';
$SECRET_KEY = 'super_secret_key_123';

// Don't modify below this line
// This is a critical system file
?>

<!--
Vulnerability: SQL Injection in line 42
Vulnerability: XSS in line 87
Vulnerability: RCE in line 123
-->
"""
        self._send_slow_response(html)

    def _send_slow_404(self) -> None:
        """Send a 404 Not Found response very slowly."""
        html = b"""<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
</head>
<body>
    <h1>404 Not Found</h1>
    <p>The requested URL was not found on this server.</p>
    <p>However, you might be interested in:</p>
    <ul>
        <li><a href="/">Home</a></li>
        <li><a href="/admin/">Admin</a></li>
        <li><a href="/api/">API</a></li>
    </ul>
</body>
</html>"""
        self._send_slow_response(html, 404)

    def do_PUT(self) -> None:
        """Handle PUT requests."""
        self._track_connection("PUT", self.path)
        time.sleep(5.0)
        self._send_slow_response(b"PUT received\n")
        self._end_connection()

    def do_DELETE(self) -> None:
        """Handle DELETE requests."""
        self._track_connection("DELETE", self.path)
        time.sleep(5.0)
        self._send_slow_response(b"DELETE received\n")
        self._end_connection()


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


"""Tarpit Module - Waste attacker time and resources.

Provides capabilities to:
- Create TCP tarpits that accept connections but never complete
- Create HTTP tarpits that serve fake content very slowly
- Create DNS tarpits that delay responses
- Create fake services that appear vulnerable but are harmless

Tarpits are designed to:
- Slow down automated scanners
- Waste attacker time and resources
- Provide fake vulnerability signatures
- Log all attacker interactions

All tarpit actions are passive and do not initiate connections
to external systems.
"""

import json
import logging
import random
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .paths import tarpit_log_file

# Cap on a single POST body the HTTP tarpit will buffer in memory,
# regardless of the client-declared Content-Length.
MAX_POST_BODY_BYTES = 10 * 1024 * 1024


@dataclass
class TarpitConnection:
    """Represents an active tarpit connection."""

    source_ip: str
    source_port: int
    target_ip: str
    target_port: int
    protocol: str
    start_time: str
    end_time: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "duration": self.get_duration(),
        }

    def get_duration(self) -> Optional[float]:
        """Get connection duration in seconds."""
        if self.end_time:
            start = datetime.fromisoformat(self.start_time)
            end = datetime.fromisoformat(self.end_time)
            return (end - start).total_seconds()
        return None


@dataclass
class TarpitStatistics:
    """Statistics for tarpit operations."""

    total_connections: int = 0
    active_connections: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    total_time_wasted: float = 0.0  # seconds
    connections_by_ip: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_connections": self.total_connections,
            "active_connections": self.active_connections,
            "total_bytes_sent": self.total_bytes_sent,
            "total_bytes_received": self.total_bytes_received,
            "total_time_wasted": self.total_time_wasted,
            "connections_by_ip": self.connections_by_ip,
        }


class TarpitEngine:
    """Manages tarpit services to waste attacker time.

    Provides multiple types of tarpits:
    - TCP: Accepts connections but never sends data
    - HTTP: Serves fake content very slowly
    - SMB: Fake SMB server that delays responses
    - RDP: Fake RDP server that appears to negotiate but stalls

    All tarpits are designed to:
    - Appear legitimate to automated scanners
    - Waste attacker time and resources
    - Log all interactions for analysis
    - Be completely passive (no outbound connections)
    """

    def __init__(
        self,
        log_file: Optional[str] = None,
        max_connections: int = 100,
        connection_timeout: int = 300,  # 5 minutes
    ):
        """Initialize the Tarpit Engine.

        Args:
            log_file: Path to log file
            max_connections: Maximum number of concurrent connections
            connection_timeout: Timeout in seconds for tarpit connections
        """
        self.log_file = log_file or str(tarpit_log_file())
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout

        # State tracking
        self.active_connections: Dict[Tuple[str, int, str, int], TarpitConnection] = {}
        self.connection_history: List[TarpitConnection] = []
        self.statistics = TarpitStatistics()

        # Tarpit servers
        self.tcp_tarpits: Dict[Tuple[str, int], socket.socket] = {}
        self.http_tarpits: Dict[Tuple[str, int], HTTPServer] = {}
        self.http_tarpit_threads: Dict[Tuple[str, int], threading.Thread] = {}

        # Setup logging
        self._setup_logging()

        logging.info(
            f"TarpitEngine initialized (max_connections={self.max_connections}, "
            f"connection_timeout={self.connection_timeout})"
        )

    def _setup_logging(self) -> None:
        """Configure logging for tarpit operations."""
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)

        # Create a dedicated logger
        self.logger = logging.getLogger("sentinel_v.tarpit")
        self.logger.setLevel(logging.INFO)

        # self.logger is a module-level named logger, so constructing more
        # than one TarpitEngine in the same process must not pile up
        # duplicate handlers - that would both leak file descriptors and
        # duplicate every log line (see the same fix in active_defense.py).
        resolved_log_file = str(Path(self.log_file).resolve())
        if not any(
            isinstance(h, logging.FileHandler) and h.baseFilename == resolved_log_file
            for h in self.logger.handlers
        ):
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(logging.INFO)
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def start_tcp_tarpit(
        self,
        host: str = "127.0.0.1",
        port: int = 9000,
    ) -> bool:
        """Start a TCP tarpit on the specified host and port.

        The tarpit accepts connections but never sends any data,
        keeping the attacker waiting indefinitely (or until timeout).

        Args:
            host: Host to bind to. Defaults to loopback - exposing a
                tarpit on a routable interface is an explicit operator
                decision, not a default (same convention as
                DynamicHoneypot in deception.py).
            port: Port to listen on

        Returns:
            True if tarpit started successfully, False otherwise
        """
        if (host, port) in self.tcp_tarpits:
            logging.warning(f"TCP tarpit already running on {host}:{port}")
            return False

        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(self.max_connections)

            # Store socket
            self.tcp_tarpits[(host, port)] = sock

            # Start accept thread
            threading.Thread(
                target=self._tcp_tarpit_accept_loop,
                args=(host, port, sock),
                daemon=True,
            ).start()

            logging.info(f"TCP tarpit started on {host}:{port}")
            return True
        except Exception as e:
            logging.error(f"Failed to start TCP tarpit on {host}:{port}: {e}")
            return False

    def _tcp_tarpit_accept_loop(
        self,
        host: str,
        port: int,
        sock: socket.socket,
    ) -> None:
        """Accept loop for TCP tarpit."""
        while (host, port) in self.tcp_tarpits:
            try:
                client_sock, client_addr = sock.accept()
                client_ip = client_addr[0]
                client_port = client_addr[1]

                # Enforce the configured connection cap here - passing
                # max_connections to listen() only bounds the kernel's
                # pending-accept backlog, not how many connections this
                # loop goes on to track and hand a thread to.
                if len(self.active_connections) >= self.max_connections:
                    logging.warning(
                        f"TCP tarpit: rejecting {client_ip}:{client_port}, "
                        f"at max_connections={self.max_connections}"
                    )
                    client_sock.close()
                    continue

                logging.info(f"TCP tarpit: connection from {client_ip}:{client_port}")

                # Track connection
                conn = TarpitConnection(
                    source_ip=client_ip,
                    source_port=client_port,
                    target_ip=host,
                    target_port=port,
                    protocol="tcp",
                    start_time=datetime.now().isoformat(),
                )
                self.active_connections[(client_ip, client_port, host, port)] = conn
                self.statistics.active_connections += 1
                self.statistics.total_connections += 1
                self.statistics.connections_by_ip[client_ip] = (
                    self.statistics.connections_by_ip.get(client_ip, 0) + 1
                )

                # Handle connection in a separate thread
                threading.Thread(
                    target=self._tcp_tarpit_handle_connection,
                    args=(client_sock, client_ip, client_port, host, port),
                    daemon=True,
                ).start()

            except Exception as e:
                if (host, port) in self.tcp_tarpits:
                    logging.error(f"Error in TCP tarpit accept loop: {e}")
                break

    def _tcp_tarpit_handle_connection(
        self,
        client_sock: socket.socket,
        client_ip: str,
        client_port: int,
        host: str,
        port: int,
    ) -> None:
        """Handle a single TCP tarpit connection."""
        try:
            # Set timeout
            client_sock.settimeout(self.connection_timeout)

            # Just hold the connection open without sending anything.
            # This wastes the attacker's time. No inner catch-all here:
            # socket.timeout is the only expected exception (handled
            # below) and anything else should reach the outer handler's
            # logging rather than vanish silently.
            while True:
                # Try to receive data (but don't respond)
                try:
                    data = client_sock.recv(1024)
                    if not data:
                        break
                    # Update statistics
                    key = (client_ip, client_port, host, port)
                    if key in self.active_connections:
                        self.active_connections[key].bytes_received += len(data)
                        self.statistics.total_bytes_received += len(data)
                except socket.timeout:
                    # Connection timed out
                    break

                # Sleep briefly to avoid busy waiting
                time.sleep(0.1)

        except Exception as e:
            logging.error(f"Error handling TCP tarpit connection: {e}")
        finally:
            # Close connection - already broken/closing, nothing to act on
            try:
                client_sock.close()
            except Exception:  # nosec B110
                pass

            # Update connection end time
            key = (client_ip, client_port, host, port)
            conn: Optional[TarpitConnection] = None
            if key in self.active_connections:
                conn = self.active_connections.pop(key)
                conn.end_time = datetime.now().isoformat()
                self.connection_history.append(conn)
                self.statistics.active_connections -= 1

                # Update time wasted
                duration = conn.get_duration()
                if duration:
                    self.statistics.total_time_wasted += duration

            duration = conn.get_duration() if conn else 0.0
            logging.info(
                f"TCP tarpit: connection closed from {client_ip}:{client_port} "
                f"(duration: {duration:.1f}s)"
            )

    def stop_tcp_tarpit(self, host: str, port: int) -> bool:
        """Stop a TCP tarpit.

        Args:
            host: Host the tarpit is bound to
            port: Port the tarpit is listening on

        Returns:
            True if tarpit stopped successfully, False otherwise
        """
        key = (host, port)
        if key not in self.tcp_tarpits:
            return True

        try:
            sock = self.tcp_tarpits.pop(key)
            sock.close()
            logging.info(f"TCP tarpit stopped on {host}:{port}")
            return True
        except Exception as e:
            logging.error(f"Failed to stop TCP tarpit on {host}:{port}: {e}")
            return False

    def start_http_tarpit(
        self,
        host: str = "127.0.0.1",
        port: int = 8081,
    ) -> bool:
        """Start an HTTP tarpit on the specified host and port.

        The tarpit serves fake content very slowly, wasting attacker time.

        Args:
            host: Host to bind to. Defaults to loopback - exposing a
                tarpit on a routable interface is an explicit operator
                decision, not a default.
            port: Port to listen on

        Returns:
            True if tarpit started successfully, False otherwise
        """
        if (host, port) in self.http_tarpits:
            logging.warning(f"HTTP tarpit already running on {host}:{port}")
            return False

        try:
            # Create HTTP server with custom handler
            def handler_class(*args: Any) -> "TarpitHTTPHandler":
                return TarpitHTTPHandler(*args, tarpit=self)

            server = HTTPServer((host, port), handler_class)

            # Store server
            self.http_tarpits[(host, port)] = server

            # Start server in a thread
            thread = threading.Thread(
                target=server.serve_forever,
                daemon=True,
            )
            self.http_tarpit_threads[(host, port)] = thread
            thread.start()

            logging.info(f"HTTP tarpit started on {host}:{port}")
            return True
        except Exception as e:
            logging.error(f"Failed to start HTTP tarpit on {host}:{port}: {e}")
            return False

    def stop_http_tarpit(self, host: str, port: int) -> bool:
        """Stop an HTTP tarpit.

        Args:
            host: Host the tarpit is bound to
            port: Port the tarpit is listening on

        Returns:
            True if tarpit stopped successfully, False otherwise
        """
        key = (host, port)
        if key not in self.http_tarpits:
            return True

        try:
            server = self.http_tarpits.pop(key)
            server.shutdown()

            # Thread will exit on its own once the server shuts down.
            self.http_tarpit_threads.pop(key, None)

            logging.info(f"HTTP tarpit stopped on {host}:{port}")
            return True
        except Exception as e:
            logging.error(f"Failed to stop HTTP tarpit on {host}:{port}: {e}")
            return False

    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Get list of currently active tarpit connections.

        Returns:
            List of active connection dictionaries
        """
        return [conn.to_dict() for conn in self.active_connections.values()]

    def get_connection_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent connection history.

        Args:
            limit: Maximum number of connections to return

        Returns:
            List of connection dictionaries
        """
        return [conn.to_dict() for conn in self.connection_history[-limit:]]

    def get_statistics(self) -> Dict[str, Any]:
        """Get tarpit statistics.

        Returns:
            Dictionary with tarpit statistics
        """
        return self.statistics.to_dict()

    def get_top_attackers(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top attacking IPs by connection count.

        Args:
            limit: Maximum number of IPs to return

        Returns:
            List of (ip, count) tuples sorted by count descending
        """
        sorted_ips = sorted(
            self.statistics.connections_by_ip.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        return sorted_ips[:limit]

    def reset(self) -> None:
        """Reset all tarpit state (for testing)."""
        # Stop all tarpits - best-effort close, state is being torn down
        for key, sock in self.tcp_tarpits.items():
            try:
                sock.close()
            except Exception:  # nosec B110
                pass
        self.tcp_tarpits.clear()

        for key, server in self.http_tarpits.items():
            try:
                server.shutdown()
            except Exception:  # nosec B110
                pass
        self.http_tarpits.clear()
        self.http_tarpit_threads.clear()

        # Clear connections
        self.active_connections.clear()
        self.connection_history.clear()
        self.statistics = TarpitStatistics()

        logging.info("TarpitEngine reset")


class TarpitHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the tarpit.

    Serves fake content very slowly to waste attacker time.
    """

    # Class-level storage for tarpit engine reference
    tarpit: Optional[TarpitEngine] = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.tarpit = kwargs.pop("tarpit", None)
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        """Override to use Python logging instead of print."""
        if self.tarpit:
            self.tarpit.logger.info(f"HTTP Tarpit: {format % args}")

    @staticmethod
    def _host_port(address: Any) -> Tuple[str, int]:
        """Extract (host, port) from a socket address.

        BaseServer.server_address / BaseRequestHandler.client_address are
        typed as a union that also covers AF_UNIX (str) addresses; this
        tarpit only ever binds AF_INET/AF_INET6 sockets, so narrowing
        here once keeps every call site simple.
        """
        return str(address[0]), int(address[1])

    def _track_connection(self, method: str, path: str) -> None:
        """Track an HTTP connection."""
        if not self.tarpit:
            return

        client_ip, client_port = self._host_port(self.client_address)
        target_ip, target_port = self._host_port(self.server.server_address)

        # Create connection record
        conn = TarpitConnection(
            source_ip=client_ip,
            source_port=client_port,
            target_ip=target_ip,
            target_port=target_port,
            protocol="http",
            start_time=datetime.now().isoformat(),
        )

        key = (client_ip, client_port, target_ip, target_port)
        self.tarpit.active_connections[key] = conn
        self.tarpit.statistics.active_connections += 1
        self.tarpit.statistics.total_connections += 1
        self.tarpit.statistics.connections_by_ip[client_ip] = (
            self.tarpit.statistics.connections_by_ip.get(client_ip, 0) + 1
        )

        logging.info(f"HTTP tarpit: {method} {path} from {client_ip}:{client_port}")

    def _update_connection(self, bytes_sent: int = 0, bytes_received: int = 0) -> None:
        """Update connection statistics."""
        if not self.tarpit:
            return

        client_ip, client_port = self._host_port(self.client_address)
        target_ip, target_port = self._host_port(self.server.server_address)
        key = (client_ip, client_port, target_ip, target_port)

        if key in self.tarpit.active_connections:
            conn = self.tarpit.active_connections[key]
            conn.bytes_sent += bytes_sent
            conn.bytes_received += bytes_received
            self.tarpit.statistics.total_bytes_sent += bytes_sent
            self.tarpit.statistics.total_bytes_received += bytes_received

    def _end_connection(self) -> None:
        """End connection tracking."""
        if not self.tarpit:
            return

        client_ip, client_port = self._host_port(self.client_address)
        target_ip, target_port = self._host_port(self.server.server_address)
        key = (client_ip, client_port, target_ip, target_port)

        if key in self.tarpit.active_connections:
            conn = self.tarpit.active_connections.pop(key)
            conn.end_time = datetime.now().isoformat()
            self.tarpit.connection_history.append(conn)
            self.tarpit.statistics.active_connections -= 1

            # Update time wasted
            duration = conn.get_duration()
            if duration:
                self.tarpit.statistics.total_time_wasted += duration

    def do_GET(self) -> None:
        """Handle GET requests with deliberate slowness."""
        self._track_connection("GET", self.path)

        # Parse URL
        parsed = urlparse(self.path)

        # Delay before sending response - timing jitter, not a security
        # value, so the standard (non-cryptographic) RNG is fine here.
        delay = random.uniform(5.0, 15.0)  # nosec B311 - 5-15 seconds
        time.sleep(delay)

        # Send very slow response
        if parsed.path == "/":
            self._send_slow_index()
        elif parsed.path.startswith("/api/"):
            self._send_slow_api_response()
        elif parsed.path.startswith("/admin/"):
            self._send_slow_admin_page()
        elif parsed.path.endswith(".php"):
            self._send_slow_php_response()
        else:
            self._send_slow_404()

        self._end_connection()

    def do_POST(self) -> None:
        """Handle POST requests with deliberate slowness."""
        self._track_connection("POST", self.path)

        # Read the body (slowly), capped so a declared multi-GB
        # Content-Length can't be used to exhaust the defender's own
        # memory - the whole point is wasting the attacker's time, not
        # the host running the tarpit.
        content_length = min(
            int(self.headers.get("Content-Length", 0)), MAX_POST_BODY_BYTES
        )
        body = b""
        if content_length > 0:
            # Read in small chunks with delays
            remaining = content_length
            while remaining > 0:
                chunk_size = min(1024, remaining)
                chunk = self.rfile.read(chunk_size)
                if not chunk:
                    break
                body += chunk
                remaining -= len(chunk)
                time.sleep(0.1)  # Delay between chunks

        self._update_connection(bytes_received=len(body))

        # Delay before sending response - timing jitter, not a security value
        delay = random.uniform(10.0, 30.0)  # nosec B311 - 10-30 seconds
        time.sleep(delay)

        # Send response
        self._send_slow_response(b"POST received\n")

        self._end_connection()

    def _send_slow_response(self, content: bytes, status_code: int = 200) -> None:
        """Send a response very slowly."""
        self.send_response(status_code)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()

        # Send data in small chunks with delays
        chunk_size = 100
        for i in range(0, len(content), chunk_size):
            end = i + chunk_size
            chunk = content[i:end]
            self.wfile.write(chunk)
            self.wfile.flush()
            time.sleep(0.1)  # Delay between chunks

        self._update_connection(bytes_sent=len(content))

    def _send_slow_index(self) -> None:
        """Send a fake index page very slowly."""
        html = b"""<!DOCTYPE html>
<html>
<head>
    <title>Welcome to the Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .vulnerable { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Welcome to the Server</h1>
    <p>This is a production server. Unauthorized access is prohibited.</p>
    <div class="vulnerable">
        <p>Warning: Outdated software detected!</p>
        <p>Apache/2.2.15 (Unix) PHP/5.3.10</p>
    </div>
    <p><a href="/admin/">Admin Login</a></p>
    <p><a href="/api/status">API Status</a></p>
    <p><a href="/phpinfo.php">PHP Info</a></p>
</body>
</html>"""
        self._send_slow_response(html)

    def _send_slow_admin_page(self) -> None:
        """Send a fake admin login page very slowly."""
        html = b"""<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .login-box { border: 1px solid #ccc; padding: 20px; width: 300px; }
        input { width: 100%; padding: 8px; margin: 5px 0; }
        button { width: 100%; padding: 10px; background: #4CAF50; color: white; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Admin Login</h2>
        <form method="POST" action="/admin/login">
            <label>Username:</label>
            <input type="text" name="username" placeholder="Enter username">
            <label>Password:</label>
            <input type="password" name="password" placeholder="Enter password">
            <button type="submit">Login</button>
        </form>
        <p>Default credentials: admin:admin123</p>
    </div>
</body>
</html>"""
        self._send_slow_response(html)

    def _send_slow_api_response(self) -> None:
        """Send a fake API response very slowly."""
        json_response = json.dumps(
            {
                "status": "success",
                "version": "1.0.0",
                "data": {
                    "users": [
                        {"id": 1, "username": "admin", "role": "administrator"},
                        {"id": 2, "username": "user1", "role": "user"},
                        {"id": 3, "username": "backup", "role": "user"},
                    ],
                    "databases": [
                        {"name": "production", "host": "localhost"},
                        {"name": "staging", "host": "localhost"},
                        {"name": "backup", "host": "localhost"},
                    ],
                    "config": {
                        "debug": True,
                        # Fake bait values served to attackers, not real
                        # secrets - not a hardcoded credential in this repo.
                        "secret_key": "sk-1234567890abcdef",  # nosec B105
                        "api_key": "ak-9876543210fedcba",
                    },
                },
                "timestamp": datetime.now().isoformat(),
            }
        ).encode()
        self._send_slow_response(json_response)

    def _send_slow_php_response(self) -> None:
        """Send a fake PHP response very slowly."""
        html = b"""<?php
// Database Configuration
$DB_HOST = 'localhost';
$DB_USER = 'root';
$DB_PASS = 'password123';
$DB_NAME = 'production';

// API Keys
$API_KEY = 'sk-1234567890abcdef';
$SECRET_KEY = 'super_secret_key_123';

// Don't modify below this line
// This is a critical system file
?>

<!--
Vulnerability: SQL Injection in line 42
Vulnerability: XSS in line 87
Vulnerability: RCE in line 123
-->
"""
        self._send_slow_response(html)

    def _send_slow_404(self) -> None:
        """Send a 404 Not Found response very slowly."""
        html = b"""<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
</head>
<body>
    <h1>404 Not Found</h1>
    <p>The requested URL was not found on this server.</p>
    <p>However, you might be interested in:</p>
    <ul>
        <li><a href="/">Home</a></li>
        <li><a href="/admin/">Admin</a></li>
        <li><a href="/api/">API</a></li>
    </ul>
</body>
</html>"""
        self._send_slow_response(html, 404)

    def do_PUT(self) -> None:
        """Handle PUT requests."""
        self._track_connection("PUT", self.path)
        time.sleep(5.0)
        self._send_slow_response(b"PUT received\n")
        self._end_connection()

    def do_DELETE(self) -> None:
        """Handle DELETE requests."""
        self._track_connection("DELETE", self.path)
        time.sleep(5.0)
        self._send_slow_response(b"DELETE received\n")
        self._end_connection()

""","""