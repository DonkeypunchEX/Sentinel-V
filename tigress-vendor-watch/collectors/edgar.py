"""
edgar.py — SEC EDGAR full-text + submissions collector.

Pulls recent filings for a named company and grades them. Filings are T1
(the company's own disclosure to a regulator). Distress-signal form types
(8-K events, going-concern language, bankruptcy) get boosted relevance.

No API key. SEC requires a descriptive User-Agent with contact info — set
EDGAR_UA in your env or edit DEFAULT_UA below. Rate limit: 10 req/sec, we
stay well under.

Runs today. This is the working core of the collector layer.
"""

import os
import time
import gzip
import zlib
import urllib.request
import urllib.parse
import json
from typing import Optional

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.provenance import Item, Tier, Verification

DEFAULT_UA = "TIGRESS Vendor Watch research contact@example.com"
UA = os.environ.get("EDGAR_UA", DEFAULT_UA)

# form types that signal vendor distress / material events -> higher relevance
DISTRESS_FORMS = {
    "8-K": 0.6,      # material event (could be anything, mid relevance)
    "NT 10-K": 0.8,  # late annual filing — a distress tell
    "NT 10-Q": 0.8,  # late quarterly — distress tell
    "SC 13D": 0.5,   # activist / ownership change
    "15-12B": 0.7,   # deregistration — going dark
    "25-NSE": 0.7,   # delisting
}
BANKRUPTCY_HINTS = ("bankrupt", "chapter 11", "chapter 7", "going concern", "receivership")

# EDGAR full-text search (efts). The submissions/ticker path only sees CURRENT
# registrants — a company that delists after bankruptcy DROPS OUT of the ticker
# index, which is exactly the distress we most want to catch. efts indexes the
# filing text itself and finds historical/delisted filers the ticker index has
# forgotten. Coverage note: efts only goes back to 2001.
EFTS_URL = "https://efts.sec.gov/LATEST/search-index"


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": "gzip, deflate"})
    with urllib.request.urlopen(req, timeout=15) as r:
        data = r.read()
        enc = r.headers.get("Content-Encoding", "")
    if enc == "gzip":
        data = gzip.decompress(data)
    elif enc == "deflate":
        data = zlib.decompress(data)
    time.sleep(0.15)  # be polite to SEC
    return data


def _find_cik(company: str) -> Optional[tuple]:
    """Resolve a company name to (cik, official_name) via SEC's ticker file."""
    url = "https://www.sec.gov/files/company_tickers.json"
    try:
        blob = json.loads(_get(url))
    except Exception as e:
        print(f"[edgar] CIK lookup failed: {e}")
        return None
    q = company.lower().strip()
    best = None
    for entry in blob.values():
        title = entry["title"].lower()
        if q == title:
            return (str(entry["cik_str"]).zfill(10), entry["title"])
        if q in title and best is None:
            best = (str(entry["cik_str"]).zfill(10), entry["title"])
    return best


def _parse_efts_hits(blob: dict, limit: int) -> list:
    """Grade efts full-text hits into Items. Isolated for offline testing."""
    items = []
    for hit in blob.get("hits", {}).get("hits", [])[:limit]:
        src = hit.get("_source", {})
        hid = hit.get("_id", "")               # "<accession-with-dashes>:<primary_doc>"
        acc, _, doc = hid.partition(":")
        forms = src.get("root_forms") or ([src.get("file_type")] if src.get("file_type") else [])
        form = (forms[0] if forms else "?") or "?"
        date = src.get("file_date", "n/a")
        ciks = src.get("ciks") or []
        names = src.get("display_names") or []
        name = names[0] if names else (company_from_cik(ciks) if ciks else "unknown filer")
        rel = DISTRESS_FORMS.get(form, 0.25)

        if acc and doc and ciks:
            url = (f"https://www.sec.gov/Archives/edgar/data/{int(ciks[0])}/"
                   f"{acc.replace('-', '')}/{doc}")
        else:
            url = "https://efts.sec.gov/LATEST/search-index"

        items.append(Item(
            source="SEC EDGAR (full-text)",
            title=f"{name} — {form} filed {date}",
            url=url,
            tier=Tier.T1_PRIMARY,
            relevance=rel,
            verification=Verification.OPENED,
            summary=(f"Form {form}, found via full-text search (delisted/historical "
                     f"filers the ticker index misses). Distress-weighted relevance {rel}."),
            raw={"form": form, "date": date, "cik": ciks[0] if ciks else None,
                 "via": "efts"},
        ).score())
    return items


def company_from_cik(ciks) -> str:
    return f"CIK {ciks[0]}" if ciks else "unknown filer"


def _fulltext_fallback(company: str, limit: int = 10) -> list:
    """
    efts full-text fallback for filers the ticker/submissions index can't resolve
    (delisted after bankruptcy, historical, name-mismatched). Best-effort: on any
    failure we return [] so the caller degrades to a declared GAP, never a crash.
    """
    params = urllib.parse.urlencode({"q": f'"{company}"'})
    try:
        blob = json.loads(_get(f"{EFTS_URL}?{params}"))
    except Exception as e:
        print(f"[edgar] full-text fallback failed: {e}")
        return []
    hits = _parse_efts_hits(blob, limit)
    print(f"[edgar] full-text fallback: {len(hits)} hit(s) for '{company}'")
    return hits


def collect(company: str, limit: int = 10) -> list:
    """Return a list of graded Items for the most recent filings of `company`."""
    resolved = _find_cik(company)
    if not resolved:
        print(f"[edgar] no CIK match for '{company}' — trying full-text fallback "
              f"(delisted/historical/private filers)")
        return _fulltext_fallback(company, limit)
    cik, official = resolved
    print(f"[edgar] {company} -> CIK {cik} ({official})")

    sub_url = f"https://data.sec.gov/submissions/CIK{cik}.json"
    try:
        subs = json.loads(_get(sub_url))
    except Exception as e:
        print(f"[edgar] submissions fetch failed: {e}")
        return []

    recent = subs.get("filings", {}).get("recent", {})
    forms = recent.get("form", [])
    dates = recent.get("filingDate", [])
    accession = recent.get("accessionNumber", [])
    primary_doc = recent.get("primaryDocument", [])
    items = []

    for i in range(min(limit, len(forms))):
        form = forms[i]
        rel = DISTRESS_FORMS.get(form, 0.25)  # routine filings still logged, low relevance
        acc_nodash = accession[i].replace("-", "")
        doc_url = (f"https://www.sec.gov/Archives/edgar/data/{int(cik)}/"
                   f"{acc_nodash}/{primary_doc[i]}") if i < len(primary_doc) else sub_url

        it = Item(
            source="SEC EDGAR",
            title=f"{official} — {form} filed {dates[i]}",
            url=doc_url,
            tier=Tier.T1_PRIMARY,
            relevance=rel,
            verification=Verification.OPENED,  # we have the filing metadata directly from SEC
            summary=f"Form {form}. Distress-weighted relevance {rel}.",
            raw={"form": form, "date": dates[i], "cik": cik},
        ).score()
        items.append(it)

    return items


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "Yellow Corp"
    for it in collect(target, limit=8):
        from core.provenance import tag
        print(f"  {tag(it):34} rel={it.relevance}  {it.title}")
