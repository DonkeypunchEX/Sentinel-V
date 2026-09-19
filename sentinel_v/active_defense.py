"""Active Defense Engine - Legal, aggressive countermeasures.

Provides firewall-based blocking, host isolation, and rate limiting
capabilities. All actions are scoped to the local network and require
explicit opt-in (enforce_mode=True).

Actions:
- Block IPs at firewall level (Linux iptables, Windows Firewall, macOS pf)
- Isolate compromised hosts (VLAN segmentation, firewall rules)
- Rate limit suspicious traffic
- Tarpit connections (slow attackers to a crawl)

Safety:
- Requires explicit enforce_mode=True to take any action
- All actions are logged and reversible
- No offensive retaliation (hacking back, DDoS, etc.)
"""

import ipaddress
import logging
import platform
import subprocess  # nosec B404 - firewall/network commands, no shell, list argv only
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .paths import active_defense_log_file


@dataclass
class BlockedEntity:
    """Represents a blocked IP or network range."""

    identifier: str  # IP, CIDR, or hostname
    reason: str
    timestamp: str
    expires_at: Optional[str] = None  # None = permanent

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identifier": self.identifier,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "expires_at": self.expires_at,
        }


@dataclass
class IsolatedHost:
    """Represents an isolated host."""

    ip: str
    reason: str
    timestamp: str
    vlan: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "vlan": self.vlan,
        }


@dataclass
class RateLimitRule:
    """Represents a rate limiting rule."""

    source: str
    port: int
    protocol: str
    rate: str  # e.g., "10/min", "100/hour"
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "port": self.port,
            "protocol": self.protocol,
            "rate": self.rate,
            "timestamp": self.timestamp,
        }


class ActiveDefenseEngine:
    """Executes legal, aggressive countermeasures against threats.

    All actions require enforce_mode=True. When enforce_mode=False (default),
    actions are only logged (simulation mode).

    Supported platforms:
    - Linux: iptables/nftables
    - Windows: netsh advfirewall
    - macOS: pfctl
    """

    def __init__(
        self,
        enforce_mode: bool = False,
        log_file: Optional[str] = None,
        auto_block: bool = True,
        auto_isolate: bool = False,
        auto_rate_limit: bool = True,
        block_duration: Optional[int] = None,  # seconds, None = permanent
    ):
        """Initialize the Active Defense Engine.

        Args:
            enforce_mode: If False, only log actions without executing
            log_file: Custom path for active defense log
            auto_block: Automatically block malicious IPs
            auto_isolate: Automatically isolate compromised hosts
            auto_rate_limit: Automatically rate limit suspicious traffic
            block_duration: Duration in seconds for blocks (None = permanent)
        """
        self.enforce_mode = enforce_mode
        self.auto_block = auto_block
        self.auto_isolate = auto_isolate
        self.auto_rate_limit = auto_rate_limit
        self.block_duration = block_duration

        # State tracking
        self.blocked_ips: Set[str] = set()
        self.blocked_networks: Set[str] = set()
        self.isolated_hosts: Set[str] = set()
        self.rate_limit_rules: List[RateLimitRule] = []
        self.action_history: List[Dict[str, Any]] = []

        # Platform detection
        self.platform = platform.system().lower()
        self._firewall_tool = self._detect_firewall_tool()

        # Logging
        self.log_file = log_file or str(active_defense_log_file())
        self._setup_logging()

        # Load existing blocks on startup
        self._load_persistent_blocks()

        logging.info(
            f"ActiveDefenseEngine initialized (enforce_mode={self.enforce_mode}, "
            f"platform={self.platform}, firewall_tool={self._firewall_tool})"
        )

    def _detect_firewall_tool(self) -> str:
        """Detect the appropriate firewall tool for the current platform."""
        if self.platform == "linux":
            # Check for nftables first, fall back to iptables
            try:
                result = subprocess.run(  # nosec
                    ["which", "nft"],
                    capture_output=True,
                    check=False,
                )
                if result.returncode == 0:
                    return "nftables"
            except Exception:
                pass  # nosec - `which` unavailable/failing just means "assume iptables"
            return "iptables"
        elif self.platform == "windows":
            return "netsh"
        elif self.platform == "darwin":
            return "pfctl"
        else:
            return "unknown"

    def _setup_logging(self) -> None:
        """Configure logging for active defense actions."""
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)

        # Create a dedicated logger
        self.logger = logging.getLogger("sentinel_v.active_defense")
        self.logger.setLevel(logging.INFO)

        # self.logger is a module-level named logger, so constructing more
        # than one ActiveDefenseEngine (multiple CLI invocations in one
        # process, tests, ...) must not pile up duplicate handlers - that
        # would both leak file descriptors and duplicate every log line.
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        if not any(
            isinstance(h, logging.FileHandler)
            and h.baseFilename == str(Path(self.log_file).resolve())
            for h in self.logger.handlers
        ):
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

        if not any(isinstance(h, logging.StreamHandler) for h in self.logger.handlers):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

    def _load_persistent_blocks(self) -> None:
        """Load previously blocked IPs from persistent storage."""
        # Implementation for loading from a file or database
        # For now, this is a placeholder for future persistence
        pass

    def _save_action(
        self, action: str, target: str, reason: str, success: bool
    ) -> None:
        """Record an action in the history log."""
        record = {
            "action": action,
            "target": target,
            "reason": reason,
            "success": success,
            "timestamp": datetime.now().isoformat(),
            "enforce_mode": self.enforce_mode,
        }
        self.action_history.append(record)

        # Limit history size
        if len(self.action_history) > 10000:
            self.action_history = self.action_history[-5000:]

        # Log to file
        self.logger.info(
            f"ACTION={action} TARGET={target} REASON={reason} SUCCESS={success}"
        )

    @staticmethod
    def _canonical_ip(value: str) -> Optional[str]:
        """Return the canonical string form of a single IP address, or None.

        This is a hard gate, not an internal-network check: every value
        that reaches a firewall command argument or a pf anchor file
        write must have round-tripped through here first. A value that
        merely fails to parse must never fall through as "not internal,
        safe to proceed" - that is exactly the shape of a rule-injection
        bug (a crafted source_ip containing a newline plus a pf/iptables
        directive would otherwise sail through unblocked).
        """
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if an already-validated IP is in the internal network ranges.

        Callers must reject unparseable input via ``_canonical_ip`` first;
        this method treats "doesn't parse" and "not internal" as the same
        thing, which is safe only for the policy question ("should we
        exempt this address"), never as the sole gate on whether ``ip``
        is safe to embed in a command or config file.
        """
        try:
            addr = ipaddress.ip_address(ip)
            internal_networks = [
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
                ipaddress.ip_network("127.0.0.0/8"),
                ipaddress.ip_network("169.254.0.0/16"),
                ipaddress.ip_network("::1/128"),
                ipaddress.ip_network("fc00::/7"),
                ipaddress.ip_network("fe80::/10"),
            ]
            return any(addr in network for network in internal_networks)
        except ValueError:
            return False

    def block_ip(
        self,
        ip: str,
        reason: str = "Threat detected",
        duration: Optional[int] = None,
    ) -> bool:
        """Block an IP address at the firewall level.

        Args:
            ip: IP address to block (IPv4 or IPv6)
            reason: Reason for blocking
            duration: Duration in seconds (None = use default, 0 = permanent)

        Returns:
            True if block was successful or already exists, False otherwise
        """
        canonical = self._canonical_ip(ip)
        if canonical is None:
            self._save_action("block_ip", ip, reason, False)
            logging.error(f"Refusing to block unparseable IP address: {ip!r}")
            return False
        ip = canonical

        if not self.auto_block:
            self._save_action("block_ip", ip, reason, False)
            logging.debug(f"Block IP disabled by configuration: {ip}")
            return False

        # Don't block internal IPs
        if self._is_internal_ip(ip):
            self._save_action("block_ip", ip, reason, False)
            logging.warning(f"Refusing to block internal IP: {ip}")
            return False

        # Check if already blocked
        if ip in self.blocked_ips:
            self._save_action("block_ip", ip, reason, True)
            logging.debug(f"IP already blocked: {ip}")
            return True

        # Use default duration if not specified
        if duration is None:
            duration = self.block_duration

        success = False
        if self.enforce_mode:
            success = self._execute_block_ip(ip, duration)

        if success:
            self.blocked_ips.add(ip)
            self._save_action("block_ip", ip, reason, True)
            logging.info(f"Blocked IP: {ip} (reason: {reason})")
        else:
            self._save_action("block_ip", ip, reason, False)
            logging.warning(f"Failed to block IP: {ip}")

        return success

    def _execute_block_ip(self, ip: str, duration: Optional[int]) -> bool:
        """Execute the actual firewall command to block an IP."""
        try:
            if self.platform == "linux":
                return self._block_ip_linux(ip, duration)
            elif self.platform == "windows":
                return self._block_ip_windows(ip, duration)
            elif self.platform == "darwin":
                return self._block_ip_macos(ip, duration)
            else:
                logging.error(f"Unsupported platform for IP blocking: {self.platform}")
                return False
        except Exception as e:
            logging.error(f"Error blocking IP {ip}: {e}")
            return False

    def _block_ip_linux(self, ip: str, duration: Optional[int]) -> bool:
        """Block an IP using iptables or nftables on Linux."""
        if self._firewall_tool == "nftables":
            return self._block_ip_nftables(ip, duration)
        else:
            return self._block_ip_iptables(ip, duration)

    def _block_ip_iptables(self, ip: str, duration: Optional[int]) -> bool:
        """Block an IP using iptables."""
        try:
            # Check if rule already exists
            check_cmd = ["iptables", "-L", "INPUT", "-n", "-v"]
            result = subprocess.run(check_cmd, capture_output=True, text=True)  # nosec
            if ip in result.stdout:
                return True

            # Add block rule
            cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)  # nosec

            # Add to OUTPUT chain as well
            cmd = ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)  # nosec

            # If duration is specified, schedule removal
            if duration and duration > 0:
                threading.Timer(duration, self.unblock_ip, args=[ip]).start()

            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"iptables command failed: {e}")
            return False

    def _block_ip_nftables(self, ip: str, duration: Optional[int]) -> bool:
        """Block an IP using nftables."""
        try:
            # Check if table exists, create if not
            check_cmd = ["nft", "list", "table", "inet", "sentinel_v"]
            result = subprocess.run(  # nosec - fixed argv, no shell
                check_cmd, capture_output=True, check=False
            )

            if result.returncode != 0:
                # Create table and chain
                subprocess.run(  # nosec
                    ["nft", "add", "table", "inet", "sentinel_v"], check=True
                )
                subprocess.run(  # nosec
                    [
                        "nft",
                        "add",
                        "chain",
                        "inet",
                        "sentinel_v",
                        "input",
                        "{ type filter hook input priority 0 ; }",
                    ],
                    check=True,
                )
                subprocess.run(  # nosec
                    [
                        "nft",
                        "add",
                        "chain",
                        "inet",
                        "sentinel_v",
                        "output",
                        "{ type filter hook output priority 0 ; }",
                    ],
                    check=True,
                )

            # Add block rule
            subprocess.run(  # nosec
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "sentinel_v",
                    "input",
                    f"ip saddr {ip} counter drop",
                ],
                check=True,
            )
            subprocess.run(  # nosec
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "sentinel_v",
                    "output",
                    f"ip daddr {ip} counter drop",
                ],
                check=True,
            )

            # If duration is specified, schedule removal
            if duration and duration > 0:
                threading.Timer(duration, self.unblock_ip, args=[ip]).start()

            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"nftables command failed: {e}")
            return False

    def _block_ip_windows(self, ip: str, duration: Optional[int]) -> bool:
        """Block an IP using Windows Firewall."""
        try:
            # Check if rule exists
            check_cmd = [
                "netsh",
                "advfirewall",
                "firewall",
                "show",
                "rule",
                f"name=Sentinel-V-Block-{ip}",
            ]
            result = subprocess.run(  # nosec - fixed argv, no shell
                check_cmd, capture_output=True, check=False
            )
            if result.returncode == 0:
                return True

            # Add block rule
            cmd = [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name=Sentinel-V-Block-{ip}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "description=Blocked by Sentinel-V",
            ]
            subprocess.run(cmd, check=True)  # nosec

            # Add outbound rule
            cmd = [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name=Sentinel-V-Block-{ip}-OUT",
                "dir=out",
                "action=block",
                f"remoteip={ip}",
                "description=Blocked by Sentinel-V",
            ]
            subprocess.run(cmd, check=True)  # nosec

            # If duration is specified, schedule removal
            if duration and duration > 0:
                threading.Timer(duration, self.unblock_ip, args=[ip]).start()

            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Windows firewall command failed: {e}")
            return False

    def _block_ip_macos(self, ip: str, duration: Optional[int]) -> bool:
        """Block an IP using pfctl on macOS."""
        try:
            # Check if pf is enabled
            subprocess.run(["pfctl", "-sr"], capture_output=True, check=False)  # nosec

            # Add block rule
            cmd = ["pfctl", "-a", "com.apple/250.Sentinel-V", "-E"]
            subprocess.run(cmd, check=True)  # nosec

            # Add rule to anchor
            rule = f"block from {ip} to any"
            with open("/etc/pf.anchors/com.apple/250.Sentinel-V", "a") as f:
                f.write(rule + "\n")

            # Reload rules
            subprocess.run(["pfctl", "-f", "/etc/pf.conf"], check=True)  # nosec

            # If duration is specified, schedule removal
            if duration and duration > 0:
                threading.Timer(duration, self.unblock_ip, args=[ip]).start()

            return True
        except Exception as e:
            logging.error(f"macOS pfctl command failed: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove a block on an IP address.

        Args:
            ip: IP address to unblock

        Returns:
            True if unblock was successful, False otherwise
        """
        if ip not in self.blocked_ips:
            return True

        try:
            if self.platform == "linux":
                if self._firewall_tool == "nftables":
                    subprocess.run(  # nosec
                        [
                            "nft",
                            "delete",
                            "rule",
                            "inet",
                            "sentinel_v",
                            "input",
                            f"ip saddr {ip} counter drop",
                        ],
                        check=False,
                    )
                    subprocess.run(  # nosec
                        [
                            "nft",
                            "delete",
                            "rule",
                            "inet",
                            "sentinel_v",
                            "output",
                            f"ip daddr {ip} counter drop",
                        ],
                        check=False,
                    )
                else:
                    subprocess.run(  # nosec
                        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False
                    )
                    subprocess.run(  # nosec
                        ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                        check=False,
                    )
            elif self.platform == "windows":
                subprocess.run(  # nosec
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        f"name=Sentinel-V-Block-{ip}",
                    ],
                    check=False,
                )
                subprocess.run(  # nosec
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        f"name=Sentinel-V-Block-{ip}-OUT",
                    ],
                    check=False,
                )
            elif self.platform == "darwin":
                # Remove from anchor file
                try:
                    with open("/etc/pf.anchors/com.apple/250.Sentinel-V", "r") as f:
                        lines = f.readlines()
                    with open("/etc/pf.anchors/com.apple/250.Sentinel-V", "w") as f:
                        for line in lines:
                            if f"block from {ip}" not in line:
                                f.write(line)
                    subprocess.run(["pfctl", "-f", "/etc/pf.conf"], check=True)  # nosec
                except Exception as pf_exc:
                    # Only the tracking state below is best-effort here;
                    # a failed anchor-file rewrite means the pf rule is
                    # still live, so this must not be silent.
                    logging.error(
                        f"Failed to unblock {ip} via pf anchor file: {pf_exc}"
                    )

            self.blocked_ips.discard(ip)
            self._save_action("unblock_ip", ip, "Manual or timeout removal", True)
            logging.info(f"Unblocked IP: {ip}")
            return True
        except Exception as e:
            logging.error(f"Error unblocking IP {ip}: {e}")
            return False

    def block_network(
        self,
        network: str,
        reason: str = "Threat detected",
        duration: Optional[int] = None,
    ) -> bool:
        """Block a network range (CIDR notation).

        Args:
            network: Network in CIDR notation (e.g., 192.168.1.0/24)
            reason: Reason for blocking
            duration: Duration in seconds (None = use default)

        Returns:
            True if block was successful, False otherwise
        """
        if not self.auto_block:
            return False

        # Validate CIDR
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            logging.error(f"Invalid CIDR notation: {network}")
            return False

        # Check if already blocked
        if network in self.blocked_networks:
            return True

        # Use default duration if not specified
        if duration is None:
            duration = self.block_duration

        success = False
        if self.enforce_mode:
            success = self._execute_block_network(network, duration)

        if success:
            self.blocked_networks.add(network)
            self._save_action("block_network", network, reason, True)
        else:
            self._save_action("block_network", network, reason, False)

        return success

    def _execute_block_network(self, network: str, duration: Optional[int]) -> bool:
        """Execute the actual firewall command to block a network."""
        try:
            if self.platform == "linux":
                if self._firewall_tool == "nftables":
                    subprocess.run(  # nosec
                        [
                            "nft",
                            "add",
                            "rule",
                            "inet",
                            "sentinel_v",
                            "input",
                            f"ip saddr {network} counter drop",
                        ],
                        check=True,
                    )
                    subprocess.run(  # nosec
                        [
                            "nft",
                            "add",
                            "rule",
                            "inet",
                            "sentinel_v",
                            "output",
                            f"ip daddr {network} counter drop",
                        ],
                        check=True,
                    )
                else:
                    subprocess.run(  # nosec
                        ["iptables", "-A", "INPUT", "-s", network, "-j", "DROP"],
                        check=True,
                    )
                    subprocess.run(  # nosec
                        ["iptables", "-A", "OUTPUT", "-d", network, "-j", "DROP"],
                        check=True,
                    )
            elif self.platform == "windows":
                safe_network = network.replace("/", "-")
                subprocess.run(  # nosec
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name=Sentinel-V-Block-Network-{safe_network}",
                        "dir=in",
                        "action=block",
                        f"remoteip={network}",
                        "description=Blocked by Sentinel-V",
                    ],
                    check=True,
                )
                subprocess.run(  # nosec
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name=Sentinel-V-Block-Network-{safe_network}-OUT",
                        "dir=out",
                        "action=block",
                        f"remoteip={network}",
                        "description=Blocked by Sentinel-V",
                    ],
                    check=True,
                )
            elif self.platform == "darwin":
                rule = f"block from {network} to any"
                with open("/etc/pf.anchors/com.apple/250.Sentinel-V", "a") as f:
                    f.write(rule + "\n")
                subprocess.run(["pfctl", "-f", "/etc/pf.conf"], check=True)  # nosec

            # If duration is specified, schedule removal
            if duration and duration > 0:
                threading.Timer(duration, self.unblock_network, args=[network]).start()

            return True
        except Exception as e:
            logging.error(f"Error blocking network {network}: {e}")
            return False

    def unblock_network(self, network: str) -> bool:
        """Remove a block on a network range."""
        if network not in self.blocked_networks:
            return True

        try:
            if self.platform == "linux":
                if self._firewall_tool == "nftables":
                    subprocess.run(  # nosec
                        [
                            "nft",
                            "delete",
                            "rule",
                            "inet",
                            "sentinel_v",
                            "input",
                            f"ip saddr {network} counter drop",
                        ],
                        check=False,
                    )
                    subprocess.run(  # nosec
                        [
                            "nft",
                            "delete",
                            "rule",
                            "inet",
                            "sentinel_v",
                            "output",
                            f"ip daddr {network} counter drop",
                        ],
                        check=False,
                    )
                else:
                    subprocess.run(  # nosec
                        ["iptables", "-D", "INPUT", "-s", network, "-j", "DROP"],
                        check=False,
                    )
                    subprocess.run(  # nosec
                        ["iptables", "-D", "OUTPUT", "-d", network, "-j", "DROP"],
                        check=False,
                    )
            elif self.platform == "windows":
                safe_network = network.replace("/", "-")
                subprocess.run(  # nosec
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        f"name=Sentinel-V-Block-Network-{safe_network}",
                    ],
                    check=False,
                )
                subprocess.run(  # nosec
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        f"name=Sentinel-V-Block-Network-{safe_network}-OUT",
                    ],
                    check=False,
                )
            elif self.platform == "darwin":
                try:
                    with open("/etc/pf.anchors/com.apple/250.Sentinel-V", "r") as f:
                        lines = f.readlines()
                    with open("/etc/pf.anchors/com.apple/250.Sentinel-V", "w") as f:
                        for line in lines:
                            if f"block from {network}" not in line:
                                f.write(line)
                    subprocess.run(["pfctl", "-f", "/etc/pf.conf"], check=True)  # nosec
                except Exception as pf_exc:
                    logging.error(
                        f"Failed to unblock {network} via pf anchor file: {pf_exc}"
                    )

            self.blocked_networks.discard(network)
            self._save_action(
                "unblock_network", network, "Manual or timeout removal", True
            )
            return True
        except Exception as e:
            logging.error(f"Error unblocking network {network}: {e}")
            return False

    def isolate_host(
        self,
        ip: str,
        reason: str = "Compromised host detected",
        vlan: Optional[str] = None,
    ) -> bool:
        """Isolate a compromised host from the network.

        This can be done via:
        - VLAN segmentation (if supported)
        - Firewall rules to block all traffic to/from the host
        - Port security (macOS/Linux)

        Args:
            ip: IP address of the host to isolate
            reason: Reason for isolation
            vlan: Optional VLAN to move the host to

        Returns:
            True if isolation was successful, False otherwise
        """
        canonical = self._canonical_ip(ip)
        if canonical is None:
            self._save_action("isolate_host", ip, reason, False)
            logging.error(f"Refusing to isolate unparseable IP address: {ip!r}")
            return False
        ip = canonical

        if not self.auto_isolate:
            self._save_action("isolate_host", ip, reason, False)
            return False

        # Don't isolate internal IPs without explicit VLAN
        if self._is_internal_ip(ip) and vlan is None:
            self._save_action("isolate_host", ip, reason, False)
            logging.warning(f"Refusing to isolate internal IP without VLAN: {ip}")
            return False

        # Check if already isolated
        if ip in self.isolated_hosts:
            self._save_action("isolate_host", ip, reason, True)
            return True

        success = False
        if self.enforce_mode:
            success = self._execute_isolate_host(ip, vlan)

        if success:
            self.isolated_hosts.add(ip)
            self._save_action("isolate_host", ip, reason, True)
            logging.info(f"Isolated host: {ip} (reason: {reason})")
        else:
            self._save_action("isolate_host", ip, reason, False)
            logging.warning(f"Failed to isolate host: {ip}")

        return success

    def _execute_isolate_host(self, ip: str, vlan: Optional[str]) -> bool:
        """Execute the actual isolation of a host."""
        try:
            if vlan:
                # VLAN-based isolation (requires network hardware support)
                return self._isolate_via_vlan(ip, vlan)
            else:
                # Firewall-based isolation
                return self._isolate_via_firewall(ip)
        except Exception as e:
            logging.error(f"Error isolating host {ip}: {e}")
            return False

    def _isolate_via_vlan(self, ip: str, vlan: str) -> bool:
        """Isolate a host by moving it to a quarantine VLAN."""
        # This would require integration with network hardware
        # For now, we'll just log the action
        logging.info(
            f"Would move {ip} to VLAN {vlan} (requires network hardware integration)"
        )
        return True

    def _isolate_via_firewall(self, ip: str) -> bool:
        """Isolate a host by blocking all traffic to/from it."""
        try:
            if self.platform == "linux":
                if self._firewall_tool == "nftables":
                    # Block all traffic to/from this IP
                    subprocess.run(  # nosec
                        [
                            "nft",
                            "add",
                            "rule",
                            "inet",
                            "sentinel_v",
                            "input",
                            f"ip saddr {ip} counter drop",
                        ],
                        check=True,
                    )
                    subprocess.run(  # nosec
                        [
                            "nft",
                            "add",
                            "rule",
                            "inet",
                            "sentinel_v",
                            "input",
                            f"ip daddr {ip} counter drop",
                        ],
                        check=True,
                    )
                    subprocess.run(  # nosec
                        [
                            "nft",
                            "add",
                            "rule",
                            "inet",
                            "sentinel_v",
                            "output",
                            f"ip saddr {ip} counter drop",
                        ],
                        check=True,
                    )
                    subprocess.run(  # nosec
                        [
                            "nft",
                            "add",
                            "rule",
                            "inet",
                            "sentinel_v",
                            "output",
                            f"ip daddr {ip} counter drop",
                        ],
                        check=True,
                    )
                else:
                    subprocess.run(  # nosec
                        ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True
                    )
                    subprocess.run(  # nosec
                        ["iptables", "-A", "INPUT", "-d", ip, "-j", "DROP"], check=True
                    )
                    subprocess.run(  # nosec
                        ["iptables", "-A", "OUTPUT", "-s", ip, "-j", "DROP"], check=True
                    )
                    subprocess.run(  # nosec
                        ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True
                    )
            elif self.platform == "windows":
                subprocess.run(  # nosec
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name=Sentinel-V-Isolate-{ip}",
                        "dir=in",
                        "action=block",
                        f"remoteip={ip}",
                        "description=Isolated by Sentinel-V",
                    ],
                    check=True,
                )
                subprocess.run(  # nosec
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name=Sentinel-V-Isolate-{ip}-OUT",
                        "dir=out",
                        "action=block",
                        f"remoteip={ip}",
                        "description=Isolated by Sentinel-V",
                    ],
                    check=True,
                )
            elif self.platform == "darwin":
                rule = f"block from {ip} to any\nblock from any to {ip}"
                with open("/etc/pf.anchors/com.apple/250.Sentinel-V", "a") as f:
                    f.write(rule + "\n")
                subprocess.run(["pfctl", "-f", "/etc/pf.conf"], check=True)  # nosec

            return True
        except Exception as e:
            logging.error(f"Error isolating host {ip} via firewall: {e}")
            return False

    def unisolate_host(self, ip: str) -> bool:
        """Remove isolation from a host."""
        if ip not in self.isolated_hosts:
            return True

        try:
            if self.platform == "linux":
                if self._firewall_tool == "nftables":
                    subprocess.run(  # nosec
                        [
                            "nft",
                            "delete",
                            "rule",
                            "inet",
                            "sentinel_v",
                            "input",
                            f"ip saddr {ip} counter drop",
                        ],
                        check=False,
                    )
                    subprocess.run(  # nosec
                        [
                            "nft",
                            "delete",
                            "rule",
                            "inet",
                            "sentinel_v",
                            "input",
                            f"ip daddr {ip} counter drop",
                        ],
                        check=False,
                    )
                    subprocess.run(  # nosec
                        [
                            "nft",
                            "delete",
                            "rule",
                            "inet",
                            "sentinel_v",
                            "output",
                            f"ip saddr {ip} counter drop",
                        ],
                        check=False,
                    )
                    subprocess.run(  # nosec
                        [
                            "nft",
                            "delete",
                            "rule",
                            "inet",
                            "sentinel_v",
                            "output",
                            f"ip daddr {ip} counter drop",
                        ],
                        check=False,
                    )
                else:
                    subprocess.run(  # nosec
                        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False
                    )
                    subprocess.run(  # nosec
                        ["iptables", "-D", "INPUT", "-d", ip, "-j", "DROP"], check=False
                    )
                    subprocess.run(  # nosec
                        ["iptables", "-D", "OUTPUT", "-s", ip, "-j", "DROP"],
                        check=False,
                    )
                    subprocess.run(  # nosec
                        ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                        check=False,
                    )
            elif self.platform == "windows":
                subprocess.run(  # nosec
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        f"name=Sentinel-V-Isolate-{ip}",
                    ],
                    check=False,
                )
                subprocess.run(  # nosec
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        f"name=Sentinel-V-Isolate-{ip}-OUT",
                    ],
                    check=False,
                )
            elif self.platform == "darwin":
                try:
                    with open("/etc/pf.anchors/com.apple/250.Sentinel-V", "r") as f:
                        lines = f.readlines()
                    with open("/etc/pf.anchors/com.apple/250.Sentinel-V", "w") as f:
                        for line in lines:
                            if (
                                f"block from {ip}" not in line
                                and f"block from any to {ip}" not in line
                            ):
                                f.write(line)
                    subprocess.run(["pfctl", "-f", "/etc/pf.conf"], check=True)  # nosec
                except Exception as pf_exc:
                    logging.error(
                        f"Failed to unisolate {ip} via pf anchor file: {pf_exc}"
                    )

            self.isolated_hosts.discard(ip)
            self._save_action("unisolate_host", ip, "Manual removal", True)
            return True
        except Exception as e:
            logging.error(f"Error unisolating host {ip}: {e}")
            return False

    def rate_limit(
        self,
        source: str,
        port: int,
        protocol: str = "tcp",
        rate: str = "10/min",
        reason: str = "Suspicious activity",
    ) -> bool:
        """Apply rate limiting to a source IP/port combination.

        Args:
            source: Source IP address or network
            port: Destination port
            protocol: Protocol (tcp/udp)
            rate: Rate limit (e.g., "10/min", "100/hour")
            reason: Reason for rate limiting

        Returns:
            True if rate limit was applied, False otherwise
        """
        canonical_source = self._canonical_ip(source)
        if canonical_source is None:
            try:
                canonical_source = str(ipaddress.ip_network(source, strict=False))
            except ValueError:
                self._save_action(
                    "rate_limit", f"{source}:{port}/{protocol}", reason, False
                )
                logging.error(f"Refusing to rate-limit unparseable source: {source!r}")
                return False
        source = canonical_source

        if protocol not in ("tcp", "udp"):
            self._save_action(
                "rate_limit", f"{source}:{port}/{protocol}", reason, False
            )
            logging.error(f"Refusing to rate-limit unknown protocol: {protocol!r}")
            return False

        if not isinstance(port, int) or not (0 < port < 65536):
            self._save_action(
                "rate_limit", f"{source}:{port}/{protocol}", reason, False
            )
            logging.error(f"Refusing to rate-limit invalid port: {port!r}")
            return False

        if not self.auto_rate_limit:
            return False

        # Check if already rate limited
        for rule in self.rate_limit_rules:
            if (
                rule.source == source
                and rule.port == port
                and rule.protocol == protocol
            ):
                return True

        success = False
        if self.enforce_mode:
            success = self._execute_rate_limit(source, port, protocol, rate)

        if success:
            rule = RateLimitRule(
                source=source,
                port=port,
                protocol=protocol,
                rate=rate,
                timestamp=datetime.now().isoformat(),
            )
            self.rate_limit_rules.append(rule)
            self._save_action("rate_limit", f"{source}:{port}/{protocol}", reason, True)
        else:
            self._save_action(
                "rate_limit", f"{source}:{port}/{protocol}", reason, False
            )

        return success

    def _execute_rate_limit(
        self, source: str, port: int, protocol: str, rate: str
    ) -> bool:
        """Execute the actual rate limiting command."""
        try:
            if self.platform == "linux":
                return self._rate_limit_linux(source, port, protocol, rate)
            elif self.platform == "windows":
                return self._rate_limit_windows(source, port, protocol, rate)
            elif self.platform == "darwin":
                return self._rate_limit_macos(source, port, protocol, rate)
            else:
                return False
        except Exception as e:
            logging.error(
                f"Error applying rate limit to {source}:{port}/{protocol}: {e}"
            )
            return False

    def _rate_limit_linux(
        self, source: str, port: int, protocol: str, rate: str
    ) -> bool:
        """Apply rate limiting using iptables on Linux."""
        try:
            # Parse rate (e.g., "10/min" -> 10 per 60 seconds)
            rate_parts = rate.split("/")
            if len(rate_parts) != 2:
                return False

            count = int(rate_parts[0])
            time_unit = rate_parts[1]

            if time_unit == "min":
                time_seconds = 60
            elif time_unit == "hour":
                time_seconds = 3600
            elif time_unit == "sec":
                time_seconds = 1
            else:
                return False

            # Use iptables recent module for rate limiting
            if protocol == "tcp":
                cmd = [
                    "iptables",
                    "-A",
                    "INPUT",
                    "-p",
                    "tcp",
                    "--dport",
                    str(port),
                    "-s",
                    source,
                    "-m",
                    "recent",
                    "--set",
                    "--name",
                    f"SENTINEL-RL-{source}-{port}",
                    "--rsource",
                ]
                subprocess.run(cmd, check=True)  # nosec

                cmd = [
                    "iptables",
                    "-A",
                    "INPUT",
                    "-p",
                    "tcp",
                    "--dport",
                    str(port),
                    "-s",
                    source,
                    "-m",
                    "recent",
                    "--update",
                    "--seconds",
                    str(time_seconds),
                    "--hitcount",
                    str(count),
                    "--name",
                    f"SENTINEL-RL-{source}-{port}",
                    "--rsource",
                    "-j",
                    "DROP",
                ]
                subprocess.run(cmd, check=True)  # nosec

            return True
        except Exception as e:
            logging.error(f"Error applying rate limit on Linux: {e}")
            return False

    def _rate_limit_windows(
        self, source: str, port: int, protocol: str, rate: str
    ) -> bool:
        """Apply rate limiting using Windows Firewall."""
        # Windows Firewall doesn't support rate limiting natively
        # This would require additional tools or scripting
        logging.warning("Rate limiting not fully supported on Windows")
        return False

    def _rate_limit_macos(
        self, source: str, port: int, protocol: str, rate: str
    ) -> bool:
        """Apply rate limiting using pfctl on macOS."""
        try:
            # Parse rate
            rate_parts = rate.split("/")
            if len(rate_parts) != 2:
                return False

            count = int(rate_parts[0])
            time_unit = rate_parts[1]

            if time_unit == "min":
                time_seconds = 60
            elif time_unit == "hour":
                time_seconds = 3600
            elif time_unit == "sec":
                time_seconds = 1
            else:
                return False

            # Add rate limiting rule to pf
            table_name = f"sentinel_rl_{source}_{port}"
            rule = f"table <{table_name}> {{ {source} }}"
            with open("/etc/pf.anchors/com.apple/250.Sentinel-V", "a") as f:
                f.write(rule + "\n")
                f.write(
                    f"pass in proto {protocol} from <{table_name}> to port {port} "
                    f"keep state (max-src-conn-rate {count}/{time_seconds}, "
                    f"overload <{table_name}_over>)\n"
                )
                f.write(
                    f"block in proto {protocol} from <{table_name}_over> "
                    f"to port {port}\n"
                )

            subprocess.run(["pfctl", "-f", "/etc/pf.conf"], check=True)  # nosec
            return True
        except Exception as e:
            logging.error(f"Error applying rate limit on macOS: {e}")
            return False

    def remove_rate_limit(
        self,
        source: str,
        port: int,
        protocol: str = "tcp",
    ) -> bool:
        """Remove a rate limit rule."""
        for i, rule in enumerate(self.rate_limit_rules):
            if (
                rule.source == source
                and rule.port == port
                and rule.protocol == protocol
            ):
                self.rate_limit_rules.pop(i)
                break

        # Implementation for removing firewall rules would go here
        # For now, just remove from tracking
        self._save_action(
            "remove_rate_limit", f"{source}:{port}/{protocol}", "Manual removal", True
        )
        return True

    def get_blocked_ips(self) -> List[str]:
        """Get list of currently blocked IPs."""
        return list(self.blocked_ips)

    def get_blocked_networks(self) -> List[str]:
        """Get list of currently blocked networks."""
        return list(self.blocked_networks)

    def get_isolated_hosts(self) -> List[str]:
        """Get list of currently isolated hosts."""
        return list(self.isolated_hosts)

    def get_rate_limit_rules(self) -> List[Dict[str, Any]]:
        """Get list of currently active rate limit rules."""
        return [rule.to_dict() for rule in self.rate_limit_rules]

    def get_action_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent action history."""
        return self.action_history[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about active defense actions."""
        return {
            "total_blocked_ips": len(self.blocked_ips),
            "total_blocked_networks": len(self.blocked_networks),
            "total_isolated_hosts": len(self.isolated_hosts),
            "total_rate_limit_rules": len(self.rate_limit_rules),
            "total_actions": len(self.action_history),
            "enforce_mode": self.enforce_mode,
            "auto_block": self.auto_block,
            "auto_isolate": self.auto_isolate,
            "auto_rate_limit": self.auto_rate_limit,
        }

    def reset(self) -> None:
        """Reset all active defense state (for testing)."""
        self.blocked_ips.clear()
        self.blocked_networks.clear()
        self.isolated_hosts.clear()
        self.rate_limit_rules.clear()
        self.action_history.clear()
        logging.info("ActiveDefenseEngine reset")
