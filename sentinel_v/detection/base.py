"""Detector contract. Rules and ML both implement this."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from sentinel_v.models import Alert, Event


class Detector(ABC):
    """A detector consumes Events and yields Alerts.

    Implementations MUST tag alerts with a MITRE ATT&CK technique where one
    applies (see docs/PLAYBOOKS.md). Keep detectors stateless per-event where
    possible; hold model/rule state on the instance.
    """

    name: str

    @abstractmethod
    def detect(self, events: Iterable[Event]) -> Iterable[Alert]:
        """Yield zero or more Alerts for the given events."""
        raise NotImplementedError
