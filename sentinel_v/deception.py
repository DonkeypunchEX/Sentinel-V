"""Deception network \u2014 decoy addressing and interaction detection.

``DeceptionNetwork`` is the dependency-free component the core system
orchestrates: it derives decoy addresses from a network range and flags
any traffic that touches them (legitimate traffic has no reason to).

``DynamicHoneypot`` is an optional, paramiko-backed SSH decoy retained
for standalone use; paramiko is imported lazily so the package imports
cleanly without it.

Additional deception capabilities:
- HTTP honeypot: Fake web server to capture attacker requests
- Canary tokens: Fake credentials, API keys, and documents
- Honey files: Fake files with embedded canary tokens
"""

import ipaddress
import json
import logging
import secrets
import socket
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse

from .paths import honeypot_log_file


class DeceptionNetwork:
    """Manages decoy endpoints and detects interactions with them."""

    def __init__(self, network_range: str = "10.0.0.0/24", decoy_count: int = 5):
        self.network_range = network_range
        self.active = False
        self.interactions: List[Dict[str, Any]] = []
        self.decoys = self._allocate_decoys(network_range, max(1, decoy_count))

        # Canary tokens
        self.canary_tokens: Set[str] = set()
        self.honey_files: List[Dict[str, Any]] = []

        # HTTP honeypot
        self.http_honeypot_port: Optional[int] = None
        self.http_honeypot_thread: Optional[threading.Thread] = None
        self.http_honeypot_server: Optional[HTTPServer] = None

    @staticmethod
    def _allocate_decoys(network_range: str, count: int) -> List[str]:
        """Deterministically pick decoy addresses spread across the range."""
        try:
            network = ipaddress.ip_network(network_range, strict=False)
        except ValueError:
            logging.warning(
                "invalid deception range %r; using 10.0.0.0/24", network_range
            )
            network = ipaddress.ip_network("10.0.0.0/24")

        hosts = list(network.hosts())
        if not hosts:
            return []
        step = max(1, len(hosts) // (count + 1))
        return [str(hosts[min(i * step, len(hosts) - 1)]) for i in range(1, count + 1)]

    def detect_interaction(
        self,
        source_ip: str,
        target_ip: str,
        port: int = 0,
        protocol: str = "tcp",
    ) -> bool:
        """Return True when traffic touches a decoy address."""
        if not self.active or target_ip not in self.decoys:
            return False

        self.interactions.append(
            {
                "source_ip": source_ip,
                "target_ip": target_ip,
                "port": port,
                "protocol": protocol,
                "timestamp": datetime.now().isoformat(),
            }
        )
        if len(self.interactions) > 5000:
            self.interactions = self.interactions[-2500:]

        logging.warning(
            "decoy interaction source=%s decoy=%s port=%s", source_ip, target_ip, port
        )
        return True

    def get_statistics(self) -> Dict[str, Any]:
        """Summarize deception network state for status reporting."""
        return {
            "active": self.active,
            "active_decoys": len(self.decoys) if self.active else 0,
            "total_decoys": len(self.decoys),
            "interactions_recorded": len(self.interactions),
            "network_range": self.network_range,
            "canary_tokens_count": len(self.canary_tokens),
            "honey_files_count": len(self.honey_files),
            "http_honeypot_port": self.http_honeypot_port,
        }

    def generate_canary_tokens(self, count: int = 10) -> List[str]:
        """Generate canary tokens (fake credentials, API keys, etc.).

        These tokens can be placed in databases, config files, or documents.
        When an attacker uses a canary token, it triggers an alert.

        Args:
            count: Number of tokens to generate

        Returns:
            List of generated canary tokens
        """
        tokens = []
        for i in range(count):
            # Generate different types of canary tokens
            token_type = ["api_key", "password", "database_cred", "aws_key", "ssh_key"][
                i % 5
            ]

            # These compare against a fixed label, not a credential -
            # bandit's B105 heuristic false-positives on the "password"
            # and "aws_key" labels here, since the actual secret in each
            # branch is always a freshly generated secrets.token_*() value.
            if token_type == "api_key":  # nosec B105
                token = f"sk-{secrets.token_urlsafe(32)}"
            elif token_type == "password":  # nosec B105
                token = f"pw-{secrets.token_urlsafe(16)}"
            elif token_type == "database_cred":  # nosec B105
                token = (
                    f"dbuser:{secrets.token_urlsafe(8)}:"
                    f"pass:{secrets.token_urlsafe(16)}"
                )
            elif token_type == "aws_key":  # nosec B105
                token = f"AKIA{secrets.token_hex(16).upper()}"
            elif token_type == "ssh_key":  # nosec B105
                token = f"ssh-rsa {secrets.token_urlsafe(40)} user@host"
            else:
                token = secrets.token_urlsafe(32)

            self.canary_tokens.add(token)
            tokens.append(token)

            logging.info(f"Generated canary token: {token_type}={token[:20]}...")

        return tokens

    def deploy_honey_files(self, directory: str, count: int = 5) -> List[Path]:
        """Deploy fake files with embedded canary tokens.

        Creates files that look valuable to attackers but contain canary tokens
        that trigger alerts when accessed.

        Args:
            directory: Directory to deploy honey files in
            count: Number of honey files to create

        Returns:
            List of paths to created honey files
        """
        dir_path = Path(directory)
        dir_path.mkdir(parents=True, exist_ok=True)

        honey_file_names = [
            "passwords.txt",
            "config.ini",
            "backup.zip",
            "database_dump.sql",
            "api_keys.json",
            "secret.docx",
            "credentials.csv",
            "aws_config",
        ]

        created_files = []
        for i in range(min(count, len(honey_file_names))):
            filename = honey_file_names[i]
            filepath = dir_path / filename

            # Generate content with canary tokens
            token = self.generate_canary_tokens(1)[0]

            if filename.endswith(".txt"):
                content = (
                    f"# {filename}\n\n"
                    "# WARNING: This file contains sensitive information\n\n"
                    f"username: admin\npassword: {token}\n"
                )
            elif filename.endswith(".ini"):
                content = (
                    f"[database]\nuser = admin\npassword = {token}\n"
                    "host = localhost\nport = 3306\n"
                )
            elif filename.endswith(".json"):
                content = json.dumps(
                    {
                        "api_keys": {
                            "production": token,
                            "staging": secrets.token_urlsafe(16),
                            "development": secrets.token_urlsafe(16),
                        }
                    },
                    indent=2,
                )
            elif filename.endswith(".sql"):
                # Static bait content for a decoy file - never executed
                # against a database, so this isn't an injection vector.
                content = (
                    "-- MySQL dump\n-- Host: localhost\n-- User: root\n\n"  # nosec B608
                    "CREATE DATABASE IF NOT EXISTS secret_db;\nUSE secret_db;\n"
                    "CREATE TABLE users (id INT, username VARCHAR(255), "
                    "password VARCHAR(255));\n"
                    f"INSERT INTO users VALUES (1, 'admin', '{token}');\n"
                )
            elif filename.endswith(".csv"):
                content = (
                    "username,password,email\n"
                    f"admin,{token},admin@example.com\n"
                    f"user1,{secrets.token_urlsafe(16)},user1@example.com\n"
                )
            else:
                content = (
                    f"This file contains sensitive information. Access token: {token}"
                )

            # Write file
            filepath.write_text(content)

            # Track honey file
            honey_file = {
                "path": str(filepath),
                "filename": filename,
                "canary_token": token,
                "created_at": datetime.now().isoformat(),
            }
            self.honey_files.append(honey_file)
            created_files.append(filepath)

            logging.info(f"Deployed honey file: {filepath}")

        return created_files

    def check_canary_token(self, token: str) -> bool:
        """Check if a token is a canary token.

        Args:
            token: Token to check

        Returns:
            True if the token is a canary token, False otherwise
        """
        if token in self.canary_tokens:
            logging.warning(f"Canary token used: {token[:20]}...")
            return True
        return False

    def check_honey_file_access(self, filepath: str) -> Optional[str]:
        """Check if a file is a honey file and return its canary token.

        Args:
            filepath: Path to the file being accessed

        Returns:
            Canary token if this is a honey file, None otherwise
        """
        for honey_file in self.honey_files:
            if honey_file["path"] == filepath:
                logging.warning(f"Honey file accessed: {filepath}")
                return str(honey_file["canary_token"])
        return None

    def start_http_honeypot(self, port: int = 8080, host: str = "127.0.0.1") -> bool:
        """Start an HTTP honeypot server.

        Creates a fake web server that logs all requests and can serve
        fake responses to waste attacker time.

        Args:
            port: Port to listen on
            host: Host to bind to. Defaults to loopback, matching
                DynamicHoneypot's convention in this same module -
                exposing a honeypot on a routable interface is an
                explicit operator decision, not a default.

        Returns:
            True if server started successfully, False otherwise
        """
        if self.http_honeypot_server is not None:
            logging.warning("HTTP honeypot already running")
            return False

        try:
            self.http_honeypot_port = port
            self.http_honeypot_server = HTTPServer(
                (host, port),
                lambda *args: HoneypotHTTPHandler(*args, deception_net=self),
            )

            # Start server in a thread
            self.http_honeypot_thread = threading.Thread(
                target=self.http_honeypot_server.serve_forever,
                daemon=True,
            )
            self.http_honeypot_thread.start()

            logging.info(f"HTTP honeypot started on {host}:{port}")
            return True
        except Exception as e:
            logging.error(f"Failed to start HTTP honeypot: {e}")
            return False

    def stop_http_honeypot(self) -> bool:
        """Stop the HTTP honeypot server.

        Returns:
            True if server stopped successfully, False otherwise
        """
        if self.http_honeypot_server is None:
            return True

        try:
            self.http_honeypot_server.shutdown()
            self.http_honeypot_server = None
            self.http_honeypot_port = None
            logging.info("HTTP honeypot stopped")
            return True
        except Exception as e:
            logging.error(f"Failed to stop HTTP honeypot: {e}")
            return False


class HoneypotHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the honeypot.

    Logs all requests and serves fake responses to waste attacker time.
    """

    # Class-level storage for deception network reference
    deception_net: Optional["DeceptionNetwork"] = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.deception_net = kwargs.pop("deception_net", None)
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        """Override to use Python logging instead of print."""
        logging.warning(f"HTTP Honeypot: {format % args}")

    def _parse_request(self) -> Dict[str, Any]:
        """Parse the HTTP request and extract useful information."""
        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)

        # Extract headers
        headers = dict(self.headers)

        # Extract client info
        client_ip = self.client_address[0]

        # Check for canary tokens in request
        canary_token = None
        if self.deception_net:
            # Check URL
            if self.deception_net.check_canary_token(parsed.path):
                canary_token = parsed.path
            # Check query params
            for param, values in query_params.items():
                for value in values:
                    if self.deception_net.check_canary_token(value):
                        canary_token = value
                        break
            # Check headers
            for header, value in headers.items():
                if self.deception_net.check_canary_token(value):
                    canary_token = value
                    break

        return {
            "method": self.command,
            "path": parsed.path,
            "query_params": query_params,
            "headers": headers,
            "client_ip": client_ip,
            "canary_token": canary_token,
            "timestamp": datetime.now().isoformat(),
        }

    def do_GET(self) -> None:
        """Handle GET requests."""
        request_info = self._parse_request()

        # Log the request
        logging.warning(
            f"HTTP Honeypot GET: {request_info['method']} {request_info['path']} "
            f"from {request_info['client_ip']}"
        )

        # If this is a canary token access, trigger an alert
        if request_info.get("canary_token"):
            logging.warning(
                f"CANARY TOKEN USED: {request_info['canary_token'][:20]}... "
                f"from {request_info['client_ip']}"
            )

        # Serve a fake response based on the path
        if request_info["path"] == "/":
            self._send_fake_index()
        elif request_info["path"].startswith("/api/"):
            self._send_fake_api_response()
        elif request_info["path"].startswith("/admin/"):
            self._send_fake_admin_page()
        elif request_info["path"].endswith(".php"):
            self._send_fake_php_response()
        else:
            self._send_fake_404()

    def do_POST(self) -> None:
        """Handle POST requests."""
        request_info = self._parse_request()

        # Read the body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        # Log the request
        logging.warning(
            f"HTTP Honeypot POST: {request_info['method']} {request_info['path']} "
            f"from {request_info['client_ip']} with {content_length} bytes"
        )

        # If this is a canary token access, trigger an alert
        if request_info.get("canary_token"):
            logging.warning(
                f"CANARY TOKEN USED: {request_info['canary_token'][:20]}... "
                f"from {request_info['client_ip']}"
            )

        # Log the body (truncated for logging)
        body_preview = body[:200].decode("utf-8", errors="replace")
        logging.debug(f"POST body preview: {body_preview}")

        # Serve a fake response
        self._send_fake_response(b"POST received\n")

    def do_PUT(self) -> None:
        """Handle PUT requests."""
        self._log_request("PUT")
        self._send_fake_response(b"PUT received\n")

    def do_DELETE(self) -> None:
        """Handle DELETE requests."""
        self._log_request("DELETE")
        self._send_fake_response(b"DELETE received\n")

    def _log_request(self, method: str) -> None:
        """Log an HTTP request."""
        client_ip = self.client_address[0]
        logging.warning(f"HTTP Honeypot {method}: {self.path} from {client_ip}")

    def _send_fake_response(self, content: bytes, status_code: int = 200) -> None:
        """Send a fake HTTP response."""
        self.send_response(status_code)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_fake_index(self) -> None:
        """Send a fake index page."""
        html = b"""<!DOCTYPE html>
<html>
<head>
    <title>Welcome to the Server</title>
</head>
<body>
    <h1>Welcome to the Server</h1>
    <p>This is a production server. Unauthorized access is prohibited.</p>
    <p><a href="/admin/">Admin Login</a></p>
    <p><a href="/api/status">API Status</a></p>
</body>
</html>"""
        self._send_fake_response(html)

    def _send_fake_admin_page(self) -> None:
        """Send a fake admin login page."""
        html = b"""<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
</head>
<body>
    <h1>Admin Login</h1>
    <form method="POST" action="/admin/login">
        <label>Username: <input type="text" name="username"></label><br>
        <label>Password: <input type="password" name="password"></label><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>"""
        self._send_fake_response(html)

    def _send_fake_api_response(self) -> None:
        """Send a fake API response."""
        json_response = json.dumps(
            {
                "status": "success",
                "data": {
                    "users": ["admin", "user1", "user2"],
                    "databases": ["production", "staging", "backup"],
                },
                "timestamp": datetime.now().isoformat(),
            }
        ).encode()
        self._send_fake_response(json_response, 200)

    def _send_fake_php_response(self) -> None:
        """Send a fake PHP response."""
        html = b"""<?php
// Configuration file
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', 'password123');
define('DB_NAME', 'production');

// Don't modify below this line
?>
"""
        self._send_fake_response(html)

    def _send_fake_404(self) -> None:
        """Send a 404 Not Found response."""
        html = b"""<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
</head>
<body>
    <h1>404 Not Found</h1>
    <p>The requested URL was not found on this server.</p>
</body>
</html>"""
        self._send_fake_response(html, 404)


class DynamicHoneypot:
    """Standalone SSH decoy that logs connection attempts.

    Requires the optional ``paramiko`` dependency. Binds to loopback by
    default \u2014 exposing a honeypot on a routable interface is an explicit
    operator decision, not a default.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 2222, key_file: str = ""):
        try:
            import paramiko
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ImportError(
                "DynamicHoneypot requires paramiko: pip install paramiko"
            ) from exc

        self._paramiko = paramiko
        self.host = host
        self.port = port
        if key_file:
            self.host_key = paramiko.RSAKey.from_private_key_file(key_file)
        else:
            self.host_key = paramiko.RSAKey.generate(2048)
        logging.basicConfig(filename=str(honeypot_log_file()), level=logging.INFO)

    def handle_client(self, client: Any, addr: Any) -> None:  # pragma: no cover
        """Complete a fake SSH handshake and log what the client sends."""
        transport = self._paramiko.Transport(client)
        transport.add_server_key(self.host_key)
        transport.start_server(server=self._paramiko.ServerInterface())
        chan = transport.accept(20)
        if chan:
            logging.info(
                "honeypot connection from %s: %s", addr, chan.recv(1024).decode()
            )
            chan.send(b"Invalid credentials\n")
            chan.close()

    def start(self) -> None:  # pragma: no cover - blocking network loop
        """Accept connections forever, one thread per client."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(100)
        while True:
            client, addr = sock.accept()
            threading.Thread(
                target=self.handle_client, args=(client, addr), daemon=True
            ).start()
