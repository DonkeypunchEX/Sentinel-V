"""
provenance.py — the tier/confidence/verification spine as executable code.

This is the OSINT skill-suite rubric turned from advisory prose into a scoring
function that RUNS. Every collected item is graded here before synthesis ever
sees it, so the local model reasons over graded intelligence, not raw headlines.

Two axes, kept deliberately separate (the rubric's core discipline):
  - TIER      = provenance quality of the SOURCE  (who is saying it)
  - RELEVANCE = does this change a decision        (do we care)
Severity is a THIRD thing and is never collapsed into tier. A critical CVE in
software no client runs is T1-authoritative and RELEVANCE~0.

Verification is a third tag, not a tier: opened / corroborated / unverified.
An unopened source is capped at Moderate confidence and barred from a headline.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class Tier(IntEnum):
    """Provenance tier of the source. Lower number = stronger provenance."""
    T1_PRIMARY = 1      # gov filing, court record, the org's own disclosure, breach corpus
    T2_OFFICIAL = 2     # regulator/vendor advisory, authoritative secondary (CISA KEV)
    T3_ESTABLISHED = 3  # credible press with named sourcing, established trade press
    T4_AGGREGATE = 4    # aggregators, general news, keyword search feeds
    T5_UNVETTED = 5     # social, anonymous, single-thread, unattributable


class Verification(IntEnum):
    UNVERIFIED = 0        # referenced but not fetched/read
    CORROBORATED = 1      # independently confirmed by >=2 unlinked lines, not directly opened
    OPENED = 2            # the artifact itself was retrieved and read


class Confidence(IntEnum):
    LOW = 1
    MODERATE = 2
    HIGH = 3


@dataclass
class Item:
    """One piece of collected intelligence, pre-synthesis."""
    source: str                 # e.g. "SEC EDGAR", "CISA KEV", "HIBP"
    title: str
    url: str
    tier: Tier
    relevance: float            # 0.0-1.0, does this change a client decision
    verification: Verification = Verification.UNVERIFIED
    summary: str = ""
    raw: dict = field(default_factory=dict)

    # computed
    confidence: Optional[Confidence] = None
    headline_eligible: bool = False

    def score(self) -> "Item":
        """Apply the spine rules. Mutates + returns self for chaining."""
        # base confidence from tier
        if self.tier <= Tier.T2_OFFICIAL:
            base = Confidence.HIGH
        elif self.tier == Tier.T3_ESTABLISHED:
            base = Confidence.MODERATE
        else:
            base = Confidence.LOW

        # verification cap: an unopened source cannot be HIGH, full stop.
        if self.verification == Verification.UNVERIFIED and base == Confidence.HIGH:
            base = Confidence.MODERATE

        self.confidence = base

        # headline eligibility: never let an unopened item lead a report,
        # and never headline something irrelevant no matter how well-sourced.
        self.headline_eligible = (
            self.verification >= Verification.CORROBORATED
            and self.relevance >= 0.5
            and self.confidence >= Confidence.MODERATE
        )
        return self


def rank(items: list[Item]) -> list[Item]:
    """
    Sort for a report. Primary key: headline-eligible first.
    Then by relevance (do we care), then by tier (how solid), then confidence.
    Relevance leads tier on purpose — a T1 filing about nothing sinks below a
    T3 report about a live client-impacting event.
    """
    for it in items:
        if it.confidence is None:
            it.score()
    return sorted(
        items,
        key=lambda it: (
            not it.headline_eligible,   # eligible (False) sorts first
            -it.relevance,
            it.tier,                    # lower tier number = better
            -int(it.confidence),
        ),
    )


def tag(it: Item) -> str:
    """Human-readable provenance tag for a rendered report line."""
    vmap = {
        Verification.OPENED: "opened",
        Verification.CORROBORATED: "corroborated",
        Verification.UNVERIFIED: "unverified",
    }
    return f"[T{int(it.tier)} · {it.confidence.name.title()} · {vmap[it.verification]}]"
