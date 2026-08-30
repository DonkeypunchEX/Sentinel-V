"""
disruption.py — supply-chain / corporate-distress news collector (T4).

The Tier-4 lead source: keyword news search for disruption signals a client's
vendor might be caught in — strikes, recalls, plant fires, layoffs, port
closures, shortages, insolvency chatter. This is deliberately the WEAKEST
provenance tier in the system and the spine treats it that way:

  - Tier T4 (keyword aggregate feed) -> capped at LOW confidence
  - Verification UNVERIFIED (a headline referenced, not an artifact opened)
  - therefore NEVER headline-eligible on its own

So why collect it at all? Because a T4 lead is where you START. It lands in the
report's WATCH section ("relevant but not yet confirmed") and tells the analyst
what to go corroborate with a T1/T2 source. It is a pointer, never a conclusion.
This is exactly the WorldMonitor-style news query the README says to lift — but
graded down to its true weight instead of presented as fact.

Source: Google News RSS (no key). We build one query pairing the vendor with a
disruption-term OR-group, fetch the feed, and grade each hit by how many
distinct disruption terms it touches.
"""

import os
import re
import sys
import gzip
import zlib
import time
import urllib.request
import urllib.parse
from xml.etree import ElementTree as ET
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.provenance import Item, Tier, Verification

UA = os.environ.get("EDGAR_UA", "TIGRESS Vendor Watch research contact@example.com")
NEWS_RSS = "https://news.google.com/rss/search"

# disruption vocabulary — a hit on any of these near the vendor name is a lead.
DISRUPTION_TERMS = [
    "strike", "recall", "bankruptcy", "insolvency", "chapter 11", "layoffs",
    "shutdown", "plant fire", "factory fire", "port closure", "shortage",
    "supply chain", "data breach", "ransomware", "outage", "lawsuit",
    "default", "restructuring", "going concern",
]
_TERM_RES = [(t, re.compile(r"\b" + re.escape(t) + r"\b", re.IGNORECASE))
             for t in DISRUPTION_TERMS]
_TAG_RE = re.compile(r"<[^>]+>")


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept-Encoding": "gzip, deflate"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = r.read()
        enc = r.headers.get("Content-Encoding", "")
    if enc == "gzip":
        data = gzip.decompress(data)
    elif enc == "deflate":
        data = zlib.decompress(data)
    time.sleep(0.2)
    return data


def _build_query(vendor: str) -> str:
    or_group = " OR ".join(f'"{t}"' if " " in t else t for t in DISRUPTION_TERMS)
    return f'"{vendor}" ({or_group})'


def _terms_in(text: str) -> list:
    return [t for t, rx in _TERM_RES if rx.search(text)]


def _relevance(hit_terms: list, pubdate: str) -> float:
    n = len(hit_terms)
    base = 0.45 if n <= 1 else (0.55 if n == 2 else 0.65)
    # small recency boost — a disruption item from this month is a hotter lead
    try:
        dt = datetime(*ET_parsedate(pubdate)[:6], tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - dt).days
        if age_days <= 14:
            base = min(0.7, base + 0.05)
    except Exception:
        pass
    return round(base, 3)


def ET_parsedate(pubdate: str):
    """Parse an RFC-822 RSS pubDate into a time tuple (via email.utils)."""
    from email.utils import parsedate
    return parsedate(pubdate) or time.gmtime(0)


def parse_feed(xml_bytes: bytes, vendor: str, limit: int) -> list:
    """Parse a Google News RSS payload into graded disruption Items."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        print(f"[disruption] RSS parse failed: {e}")
        return []

    items, seen = [], set()
    for node in root.iter("item"):
        title = (node.findtext("title") or "").strip()
        link = (node.findtext("link") or "").strip()
        desc = _TAG_RE.sub(" ", node.findtext("description") or "")
        pub = (node.findtext("pubDate") or "").strip()
        src_node = node.find("source")
        src = (src_node.text if src_node is not None else "news").strip()
        if not title or not link:
            continue

        hit_terms = _terms_in(f"{title} {desc}")
        if not hit_terms:
            continue  # vendor mentioned but no disruption term -> not our signal
        key = title.lower()
        if key in seen:
            continue
        seen.add(key)

        items.append(Item(
            source=f"News/{src}",
            title=title,
            url=link,
            tier=Tier.T4_AGGREGATE,
            relevance=_relevance(hit_terms, pub),
            verification=Verification.UNVERIFIED,  # a lead, not a confirmed fact
            summary=(f"Disruption lead ({', '.join(hit_terms)}). {pub}. "
                     f"UNVERIFIED — corroborate against a filing/advisory before acting."),
            raw={"terms": hit_terms, "pubDate": pub, "source": src},
        ).score())

    items.sort(key=lambda it: it.raw.get("pubDate", ""), reverse=True)
    return items[:limit]


def collect(vendor: str, limit: int = 12) -> list:
    """Return graded T4 disruption leads for `vendor` from Google News RSS."""
    q = urllib.parse.quote(_build_query(vendor))
    url = f"{NEWS_RSS}?q={q}&hl=en-US&gl=US&ceid=US:en"
    try:
        xml_bytes = _get(url)
    except Exception as e:
        print(f"[disruption] fetch failed: {e}")
        return []
    items = parse_feed(xml_bytes, vendor, limit)
    print(f"[disruption] {len(items)} disruption lead(s) for '{vendor}' (T4, watch-only)")
    return items


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "Yellow Corp"
    from core.provenance import tag
    for it in collect(target, limit=8):
        print(f"  {tag(it):34} rel={it.relevance}  {it.title}")
