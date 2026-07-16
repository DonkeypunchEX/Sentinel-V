"""Sentinel-V — autonomous cyber-defense framework.

The core system (``SentinelVSystem`` and its components) depends only on
the base install. Heavier research modules (scikit-learn detectors,
paramiko honeypots, PQC bindings, federated learning) are loaded lazily
on first attribute access so importing ``sentinel_v`` never requires the
optional extras.
"""

from typing import Any

from .core import SentinelVSystem, SystemMode, DefenseLevel, create_sentinel_system
from .crypto import QuantumResistantCrypto
from .deception import DeceptionNetwork
from .federation import FederatedDefenseNode
from .monitoring import AdaptiveThreatMatrix, ThreatLevel
from .response import AutonomousResponseEngine

__version__ = "1.0.0"

__all__ = [
    "SentinelVSystem",
    "SystemMode",
    "DefenseLevel",
    "create_sentinel_system",
    "QuantumResistantCrypto",
    "DeceptionNetwork",
    "FederatedDefenseNode",
    "AdaptiveThreatMatrix",
    "ThreatLevel",
    "AutonomousResponseEngine",
    # lazy, require optional extras:
    "ThreatDetector",
    "DynamicHoneypot",
    "QuantumCrypto",
    "AutonomousResponder",
    "RobustModel",
]

# attribute name -> (module, extra needed)
_LAZY = {
    "ThreatDetector": ("threat_detection", "ml"),
    "DynamicHoneypot": ("deception", "paramiko"),
    "QuantumCrypto": ("quantum_security", "quantum"),
    "AutonomousResponder": ("autonomous_response", "ml"),
    "RobustModel": ("vulnerability_mitigation", "ml"),
}


def __getattr__(name: str) -> Any:
    """Load optional-extra classes on first access (PEP 562)."""
    if name in _LAZY:
        module_name, extra = _LAZY[name]
        try:
            from importlib import import_module

            module = import_module(f".{module_name}", __name__)
            return getattr(module, name)
        except ImportError as exc:
            raise ImportError(
                f"sentinel_v.{name} requires optional dependencies "
                f"(install extra: {extra!r}): {exc}"
            ) from exc
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
