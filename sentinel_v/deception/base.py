"""Deception controller contract.

We do NOT implement honeypots from scratch (see docs/RND.md: Cowrie/OpenCanary/
canarytokens are mature and safer). An adapter tails a honeypot's logs and emits
normalized Events. Any honeypot interaction is near-certain-malicious signal.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from sentinel_v.models import Event


class DeceptionAdapter(ABC):
    name: str  # "cowrie" | "opencanary" | "canarytoken"

    @abstractmethod
    def stream(self) -> Iterator[Event]:
        """Yield Events for each honeypot interaction (source=self.name)."""
        raise NotImplementedError
