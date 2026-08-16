"""Collector contract: subscribe to a source, yield normalized Events."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from sentinel_v.models import Event


class Collector(ABC):
    """One collector per source type. Normalize the source's native format into
    Event. Keep parsing here so the rest of the system is source-agnostic.
    """

    name: str

    @abstractmethod
    def stream(self) -> Iterator[Event]:
        """Yield Events as they arrive (tail a file, read a socket, etc.)."""
        raise NotImplementedError


# Phase-1 targets (see ROADMAP): SuricataEveCollector (parse EVE JSON lines),
# AuthLogCollector (failed logins -> kind="auth_fail"). Implement here.
