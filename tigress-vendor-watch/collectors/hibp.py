"""
hibp.py — Have I Been Pwned collector for a vendor's DOMAIN.

Breach exposure on a vendor's domain is a Tier-1 leading indicator of vendor
compromise. This is the highest-signal collector in the system and the one that
ties straight to a client action ("your supplier X was in a breach, rotate
credentials now").

Two layers, degrading gracefully:

  1. PUBLIC (no key)  — GET /api/v3/breaches?domain={domain}
     Breaches OF that company's own site. Public, unauthenticated. Always runs.
     This alone is enough to say "this vendor has been breached, here's what
     leaked and how bad the credential exposure is."

  2. AUTHENTICATED (HIBP_API_KEY set) — stealer logs + breacheddomain
     Stealer-log presence is the top-urgency signal (live infostealer infection
     dumping current credentials). Only runs for a domain you control / are
     authorized to check, and only when a key is present. Never hardcode the
     key; read it from env, keep it out of the repo.

Grading (ported from the osint-exposure-check skill's hash-urgency reasoning):
  - password exposure with plaintext / unsalted MD5 / SHA1  -> relevance ~0.9  (rotate now)
  - password exposure with bcrypt / argon2 / PBKDF2         -> relevance ~0.6  (reuse risk)
  - non-credential PII only (names, emails)                 -> relevance ~0.35 (log)
  - stealer-log presence                                    -> relevance  0.95 (top urgency)
  - unverified breach (HIBP IsVerified == false)            -> relevance halved, verification downgraded

Tier is T1 (HIBP is a breach corpus — a primary record of the exposure).
Verification is OPENED when we pulled the breach record; UNVERIFIED when HIBP
itself flags the breach as unverified.
"""

import os
import re
import sys
import gzip
import zlib
import json
import time
import urllib.request
import urllib.error
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.provenance import Item, Tier, Verification

HIBP_KEY = os.environ.get("HIBP_API_KEY")  # set on your machine, never commit
UA = os.environ.get("HIBP_UA", os.environ.get("EDGAR_UA",
                    "TIGRESS Vendor Watch research contact@example.com"))
BASE = "https://haveibeenpwned.com/api/v3"

# hash-strength hints scanned in a breach's free-text Description (HIBP does not
# expose a structured algorithm field, so we read urgency from the words HIBP uses)
PLAINTEXT_HINTS = ("plain text", "plaintext", "unsalted md5", "md5", "sha1", "sha-1",
                   "stored in plain", "cleartext")
STRONG_HASH_HINTS = ("bcrypt", "argon2", "pbkdf2", "scrypt", "salted sha-256", "sha-512")


def _get(path: str, authed: bool = False):
    """GET a HIBP endpoint. Returns parsed JSON, or None on 404 (no results)."""
    url = path if path.startswith("http") else f"{BASE}{path}"
    headers = {"User-Agent": UA, "Accept-Encoding": "gzip, deflate"}
    if authed:
        headers["hibp-api-key"] = HIBP_KEY
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = r.read()
            enc = r.headers.get("Content-Encoding", "")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None  # HIBP uses 404 for "nothing found" — a clean empty, not an error
        raise
    if enc == "gzip":
        data = gzip.decompress(data)
    elif enc == "deflate":
        data = zlib.decompress(data)
    time.sleep(1.6)  # HIBP authed rate limit is ~1 req / 1.5s; stay under it
    return json.loads(data) if data else None


def _password_urgency(breach: dict) -> float:
    """Relevance from credential exposure severity, per the exposure-check rubric."""
    classes = [c.lower() for c in breach.get("DataClasses", [])]
    has_passwords = any("password" in c for c in classes)
    if not has_passwords:
        # non-credential PII still matters (phishing fuel) but is not rotate-now
        return 0.35 if classes else 0.25
    desc = (breach.get("Description", "") or "").lower()
    if any(h in desc for h in PLAINTEXT_HINTS):
        return 0.9   # plaintext / weak hash -> rotate now
    if any(h in desc for h in STRONG_HASH_HINTS):
        return 0.6   # strong hash -> reuse risk, still act
    return 0.75      # passwords exposed, algorithm unstated -> treat as high-ish


def _breach_item(breach: dict) -> Item:
    name = breach.get("Title") or breach.get("Name", "unknown breach")
    verified = breach.get("IsVerified", True)
    rel = _password_urgency(breach)
    verification = Verification.OPENED
    if not verified:
        rel = round(rel * 0.5, 3)          # HIBP flags it unconfirmed -> discount
        verification = Verification.UNVERIFIED

    classes = ", ".join(breach.get("DataClasses", [])) or "unspecified data"
    pwn = breach.get("PwnCount", 0)
    date = breach.get("BreachDate", "n/a")
    return Item(
        source="HIBP",
        title=f"{name} breach — {breach.get('Domain') or breach.get('Name')}",
        url=f"https://haveibeenpwned.com/PwnedWebsites#{breach.get('Name', '')}",
        tier=Tier.T1_PRIMARY,
        relevance=rel,
        verification=verification,
        summary=(f"Breached {date}. {pwn:,} accounts. Exposed: {classes}. "
                 f"{'UNVERIFIED by HIBP. ' if not verified else ''}"
                 f"CLIENT ACTION: rotate any credentials reused from this domain."),
        raw=breach,
    ).score()


def _stealer_item(domain: str, count: int) -> Item:
    """A stealer-log hit is the top-urgency signal: live infostealer exfiltration."""
    return Item(
        source="HIBP",
        title=f"Stealer-log exposure — {domain}",
        url="https://haveibeenpwned.com/",
        tier=Tier.T1_PRIMARY,
        relevance=0.95,
        verification=Verification.OPENED,
        summary=(f"{count} address(es) on {domain} appear in infostealer stealer logs. "
                 f"This indicates active malware-harvested credentials — TOP URGENCY. "
                 f"CLIENT ACTION: force password resets + session invalidation now."),
        raw={"domain": domain, "stealer_count": count},
    ).score()


def collect(domain: str, limit: int = 25) -> list:
    """Return graded Items for breaches touching `domain`."""
    if not domain:
        print("[hibp] no domain given — skipped.")
        return []

    items = []

    # --- Layer 1: public breaches of the vendor's own domain (no key) ---
    try:
        breaches = _get(f"/breaches?domain={urllib.parse.quote(domain)}")
    except Exception as e:
        print(f"[hibp] public breach lookup failed: {e}")
        breaches = None
    for b in (breaches or [])[:limit]:
        items.append(_breach_item(b))
    print(f"[hibp] {len(items)} public breach record(s) for {domain}")

    # --- Layer 2: authenticated stealer-log / breacheddomain (needs key) ---
    if not HIBP_KEY:
        print("[hibp] no HIBP_API_KEY — public layer only. "
              "Wire a subscribed key for stealer-log + breacheddomain signal.")
        return items

    try:
        # accounts on a domain you control, grouped -> count of exposed local parts
        bd = _get(f"/breacheddomain/{urllib.parse.quote(domain)}", authed=True)
        if bd:
            n = len(bd)
            items.append(Item(
                source="HIBP",
                title=f"Domain breach roll-up — {domain}",
                url="https://haveibeenpwned.com/DomainSearch",
                tier=Tier.T1_PRIMARY,
                relevance=0.7,
                verification=Verification.OPENED,
                summary=(f"{n} account(s) on {domain} appear across one or more breaches. "
                         f"Authenticated domain-search result."),
                raw={"domain": domain, "accounts": n},
            ).score())
    except Exception as e:
        print(f"[hibp] breacheddomain lookup failed: {e}")

    try:
        sl = _get(f"/stealerlogsbyemaildomain/{urllib.parse.quote(domain)}", authed=True)
        if sl:
            items.append(_stealer_item(domain, len(sl)))
    except Exception as e:
        print(f"[hibp] stealer-log lookup failed: {e}")

    return items


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "adobe.com"
    from core.provenance import tag
    for it in collect(target, limit=10):
        print(f"  {tag(it):34} rel={it.relevance}  {it.title}")
