"""Deception network — decoy addressing and interaction detection.

``DeceptionNetwork`` is the dependency-free component the core system
orchestrates: it derives decoy addresses from a network range and flags
any traffic that touches them (legitimate traffic has no reason to).

``DynamicHoneypot`` is an optional, paramiko-backed SSH decoy retained
for standalone use; paramiko is imported lazily so the package imports
cleanly without it.
"""

import ipaddress
import logging
import threading
from datetime import datetime
from typing import Any, Dict, List


class DeceptionNetwork:
    """Manages decoy endpoints and detects interactions with them."""

    def __init__(self, network_range: str = "10.0.0.0/24", decoy_count: int = 5):
        self.network_range = network_range
        self.active = False
        self.interactions: List[Dict[str, Any]] = []
        self.decoys = self._allocate_decoys(network_range, max(1, decoy_count))

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
        }


class DynamicHoneypot:
    """Standalone SSH decoy that logs connection attempts.

    Requires the optional ``paramiko`` dependency. Binds to loopback by
    default — exposing a honeypot on a routable interface is an explicit
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
        logging.basicConfig(filename="honeypot.log", level=logging.INFO)

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
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(100)
        while True:
            client, addr = sock.accept()
            threading.Thread(
                target=self.handle_client, args=(client, addr), daemon=True
            ).start()
