"""Adaptive threat matrix — behavioral anomaly scoring.

Learns per-source behavioral baselines from the event stream and scores
new events against them. Pure stdlib: deterministic, dependency-free,
and fast enough to sit in the hot path of ``SentinelVSystem.process_event``.
"""

import logging
from collections import defaultdict, deque
from enum import Enum
from typing import Any, Deque, Dict, Tuple

# Ports commonly probed by scanners and worms; interactions here raise
# suspicion faster than ordinary service traffic.
SENSITIVE_PORTS = frozenset(
    {21, 22, 23, 25, 135, 139, 445, 1433, 2222, 3306, 3389, 5900, 8080}
)


class ThreatLevel(Enum):
    """Ordered threat severity used across the framework."""

    BENIGN = 0
    SUSPICIOUS = 1
    MALICIOUS = 2
    CRITICAL = 3


class AdaptiveThreatMatrix:
    """Self-adjusting anomaly scorer with bounded memory.

    Tracks how often each source hits each (port, protocol) pattern and
    how many distinct ports a source touches. Sources that fan out
    across many ports quickly (scan behavior) or repeatedly hit
    sensitive ports accumulate anomaly score.
    """

    def __init__(self, learning_rate: float = 0.1, memory_size: int = 10000):
        self.learning_rate = max(0.001, min(1.0, learning_rate))
        self.memory_size = max(100, memory_size)
        self.threshold_multiplier = 1.0
        # pattern key -> smoothed frequency
        self.patterns: Dict[str, float] = defaultdict(float)
        # rolling window of recent (source, port) observations
        self.attack_memory: Deque[Tuple[str, int]] = deque(maxlen=self.memory_size)
        # distinct ports seen per source within the memory window
        self._ports_by_source: Dict[str, set] = defaultdict(set)

    def analyze(self, event: Dict[str, Any]) -> Tuple[float, ThreatLevel]:
        """Score an event and classify its threat level.

        Returns a tuple of (anomaly_score in [0, 1], ThreatLevel).
        """
        source = str(event.get("source_ip", "unknown"))
        port = self._as_port(event.get("dest_port", 0))
        protocol = str(event.get("protocol", "tcp")).lower()

        self._observe(source, port, protocol)

        score = 0.0

        # Fan-out: a source touching many distinct ports looks like a scan.
        distinct_ports = len(self._ports_by_source[source])
        score += min(0.5, distinct_ports * 0.05)

        # Sensitive-port pressure.
        if port in SENSITIVE_PORTS:
            score += 0.25

        # Repetition of the exact pattern (brute force / hammering).
        pattern_key = f"{source}:{port}:{protocol}"
        score += min(0.25, self.patterns[pattern_key] * 0.05)

        # Explicit signals from upstream sensors, if present.
        if event.get("failed_auth"):
            score += 0.2
        if event.get("payload_suspicious"):
            score += 0.3

        score = min(1.0, score * self.threshold_multiplier)
        return score, self._classify(score)

    def _observe(self, source: str, port: int, protocol: str) -> None:
        """Fold one observation into the learned baselines."""
        pattern_key = f"{source}:{port}:{protocol}"
        self.patterns[pattern_key] += self.learning_rate * 10

        if len(self.attack_memory) == self.attack_memory.maxlen:
            old_source, old_port = self.attack_memory[0]
            self._ports_by_source[old_source].discard(old_port)
            if not self._ports_by_source[old_source]:
                del self._ports_by_source[old_source]

        self.attack_memory.append((source, port))
        self._ports_by_source[source].add(port)

        # Keep the pattern table bounded alongside the memory window.
        if len(self.patterns) > self.memory_size:
            coldest = min(self.patterns, key=lambda k: self.patterns[k])
            del self.patterns[coldest]

    @staticmethod
    def _as_port(value: Any) -> int:
        """Coerce an untrusted port value to a sane integer."""
        try:
            port = int(value)
        except (TypeError, ValueError):
            return 0
        return port if 0 <= port <= 65535 else 0

    @staticmethod
    def _classify(score: float) -> ThreatLevel:
        """Map a normalized anomaly score onto a threat level."""
        if score >= 0.85:
            return ThreatLevel.CRITICAL
        if score >= 0.6:
            return ThreatLevel.MALICIOUS
        if score >= 0.3:
            return ThreatLevel.SUSPICIOUS
        return ThreatLevel.BENIGN

    def reset(self) -> None:
        """Forget all learned baselines (e.g., between test runs)."""
        self.patterns.clear()
        self.attack_memory.clear()
        self._ports_by_source.clear()
        logging.info("AdaptiveThreatMatrix baselines reset")
