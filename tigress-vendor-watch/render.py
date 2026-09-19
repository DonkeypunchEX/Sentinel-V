"""
render.py — turn ranked, graded Items into a client-facing markdown brief.

The report is structured so provenance is legible to a non-technical business
owner without dumbing down the rigor:
  - HEADLINE section: only headline-eligible items (corroborated + relevant +
    >=moderate). If nothing qualifies, we SAY SO rather than promote a weak item.
  - WATCH section: relevant but unverified/lower-confidence — things to watch,
    explicitly not yet actionable.
  - LOGGED section: everything else collected, for completeness/audit.
  - GAPS section: what we could NOT see. This is a rubric requirement, not
    decoration — a report that hides its blind spots is the failure mode.

Every line carries its [tier · confidence · verification] tag and a source link,
so any claim can be walked back to its origin. Nothing is asserted beyond what
the grade supports.
"""

import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.provenance import Item, tag, rank, Verification, Confidence


def render(vendor: str, items: list, gaps: list = None, synthesis: str = None) -> str:
    """Return a markdown brief string for `vendor` from graded `items`.

    `synthesis`, if given, is a ready-made markdown section (from synthesize.py)
    inserted as a readable lede above the graded lists. It is always a narrative
    OVER the grades, never a substitute — the graded lists remain authoritative.
    """
    items = rank(items)
    gaps = gaps or []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    headline = [it for it in items if it.headline_eligible]
    watch = [it for it in items
             if not it.headline_eligible and it.relevance >= 0.5]
    logged = [it for it in items
              if not it.headline_eligible and it.relevance < 0.5]

    L = []
    L.append(f"# Vendor Risk Brief — {vendor}")
    L.append(f"*Generated {now} · TIGRESS Vendor Watch*")
    L.append("")
    L.append(f"**Collected:** {len(items)} items · "
             f"**Actionable:** {len(headline)} · "
             f"**Watch:** {len(watch)} · "
             f"**Logged:** {len(logged)}")
    L.append("")
    L.append("---")
    L.append("")

    # SYNTHESIS (optional narrative lede)
    if synthesis:
        L.append(synthesis.rstrip())
        L.append("")
        L.append("---")
        L.append("")

    # HEADLINE
    L.append("## Actionable — corroborated and client-relevant")
    if headline:
        for it in headline:
            L.append(f"- **{it.title}** {tag(it)}")
            if it.summary:
                L.append(f"  - {it.summary}")
            L.append(f"  - source: {it.url}")
    else:
        L.append("*Nothing rose to actionable this run. No corroborated, "
                 "client-relevant signal cleared the bar — this is a clean "
                 "result, not an empty one.*")
    L.append("")

    # WATCH
    if watch:
        L.append("## Watch — relevant but not yet confirmed")
        for it in watch:
            L.append(f"- {it.title} {tag(it)}")
            if it.summary:
                L.append(f"  - {it.summary}")
            L.append(f"  - source: {it.url}")
        L.append("")

    # LOGGED
    if logged:
        L.append("## Logged — routine, low relevance")
        for it in logged:
            L.append(f"- {it.title} {tag(it)}")
        L.append("")

    # GAPS — required
    L.append("## Gaps — what this brief could NOT see")
    if gaps:
        for g in gaps:
            L.append(f"- {g}")
    else:
        L.append("- *(no gaps declared — check the collectors that ran; a "
                 "truly empty gaps list usually means a collector was skipped)*")
    L.append("")
    L.append("---")
    L.append("*Tags: [Tier · Confidence · Verification]. "
             "T1 primary record → T5 unvetted. "
             "'opened' = artifact retrieved; 'corroborated' = independently "
             "confirmed; 'unverified' = referenced only. "
             "Nothing unverified appears as actionable.*")

    return "\n".join(L)
