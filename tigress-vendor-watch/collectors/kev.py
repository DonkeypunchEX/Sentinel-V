"""
kev.py — CISA Known Exploited Vulnerabilities collector.

The anti-noise CVE source: KEV lists ONLY vulnerabilities confirmed exploited
in the wild, curated by CISA. No API key. This is T2 (authoritative secondary
/ government advisory).

Given a vendor name, surfaces KEV entries whose vendor/product matches. The
discipline the spine enforces: a KEV entry is HIGH severity by definition, but
RELEVANCE depends entirely on whether your client runs that product. Severity
is not relevance. We set relevance by name-match strength and let the report
make the "do you run this?" call explicit.

Runs today.
"""

import os
import sys
import gzip
import zlib
import json
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.provenance import Item, Tier, Verification

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
UA = os.environ.get("EDGAR_UA", "TIGRESS Vendor Watch research contact@example.com")


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": "gzip, deflate"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = r.read()
        enc = r.headers.get("Content-Encoding", "")
    if enc == "gzip":
        data = gzip.decompress(data)
    elif enc == "deflate":
        data = zlib.decompress(data)
    return data


def collect(vendor: str, limit: int = 15) -> list:
    """Return graded Items for KEV entries matching `vendor` (by vendor/product)."""
    try:
        blob = json.loads(_get(KEV_URL))
    except Exception as e:
        print(f"[kev] fetch failed: {e}")
        return []

    q = vendor.lower().strip()
    hits = []
    for v in blob.get("vulnerabilities", []):
        vp = f"{v.get('vendorProject','')} {v.get('product','')}".lower()
        if q in vp:
            # relevance from match quality; severity is inherently high (it's KEV)
            rel = 0.85 if q in v.get("vendorProject", "").lower() else 0.7
            it = Item(
                source="CISA KEV",
                title=f"{v.get('vendorProject')} {v.get('product')} — {v.get('cveID')}",
                url=f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}",
                tier=Tier.T2_OFFICIAL,
                relevance=rel,
                verification=Verification.OPENED,
                summary=(f"{v.get('vulnerabilityName','')}. "
                         f"Added {v.get('dateAdded')}. "
                         f"Due {v.get('dueDate','n/a')}. "
                         f"CLIENT ACTION DEPENDS ON: do they run {v.get('product')}?"),
                raw=v,
            ).score()
            hits.append(it)

    hits.sort(key=lambda it: it.raw.get("dateAdded", ""), reverse=True)
    print(f"[kev] {len(hits)} exploited-in-wild entries matching '{vendor}'")
    return hits[:limit]


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "Cisco"
    from core.provenance import tag
    for it in collect(target, limit=8):
        print(f"  {tag(it):34} rel={it.relevance}  {it.title}")
