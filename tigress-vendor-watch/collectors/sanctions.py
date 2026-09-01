"""
sanctions.py — OFAC sanctions (SDN + Consolidated) collector.

A sanctions designation is the most decisive vendor signal there is: if a vendor,
its parent, or a beneficial owner appears on a US Treasury OFAC list, doing
business with them is potentially a legal violation, not merely a risk. This is
T1 (a primary government designation) and, when matched, high-relevance by
definition — the client action is "stop / escalate to counsel", not "monitor".

No API key. OFAC publishes the lists as free CSV downloads:
  - SDN list (Specially Designated Nationals):      sdn.csv
  - Consolidated (non-SDN sanctions):               cons_prim.csv

Both are flat CSV with NO header row and "-0-" as the empty sentinel. We match
the vendor name against the primary name column with word-boundary matching to
avoid spurious substring hits (a naive "in" match makes "Ford" hit every SDN
entry containing that letter run).

Discipline the spine enforces: a sanctions HIT is high-relevance T1, but the
ABSENCE of a hit is reported as a positive clean-check gap, not silence — a
client wants to see that the screen ran and came back clear.
"""

import os
import re
import io
import sys
import csv
import time
import gzip
import zlib
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.provenance import Item, Tier, Verification

UA = os.environ.get("EDGAR_UA", "TIGRESS Vendor Watch research contact@example.com")

# OFAC flat-file downloads. Column layout is fixed and header-less.
# Each list has a PRIMARY file (canonical names) and an ALT file (a.k.a./f.k.a.).
# The a.k.a. file is essential: OFAC lists an entity under one canonical
# transliteration (e.g. "ROSOBORONEKSPORT OAO") while the spelling a client
# actually types ("Rosoboronexport") is only an a.k.a. Screening the primary
# names alone silently MISSES designations — a false-negative on the single most
# decisive signal in the system, which is unacceptable.
SOURCES = {
    "SDN": {
        "primary": ("https://www.treasury.gov/ofac/downloads/sdn.csv",
                    "https://sanctionslistservice.ofac.treas.gov/api/download/sdn.csv"),
        "alt": ("https://www.treasury.gov/ofac/downloads/alt.csv",
                "https://sanctionslistservice.ofac.treas.gov/api/download/alt.csv"),
    },
    "Consolidated": {
        "primary": ("https://www.treasury.gov/ofac/downloads/consolidated/cons_prim.csv",
                    "https://sanctionslistservice.ofac.treas.gov/api/download/cons_prim.csv"),
        "alt": ("https://www.treasury.gov/ofac/downloads/consolidated/cons_alt.csv",
                "https://sanctionslistservice.ofac.treas.gov/api/download/cons_alt.csv"),
    },
}

# primary-file columns (0-indexed, no header row in the file)
COL_ENT_NUM = 0
COL_NAME = 1
COL_TYPE = 2
COL_PROGRAM = 3
COL_REMARKS = 11
# alt-file columns
ALT_ENT_NUM = 0
ALT_TYPE = 2      # aka / fka / nka
ALT_NAME = 3
EMPTY = "-0-"

# OFAC 50 Percent Rule: an entity owned 50% or more — directly or indirectly,
# individually OR IN AGGREGATE — by one or more blocked persons is ITSELF blocked,
# even though OFAC never lists it. OFAC does not publish ownership graphs, so this
# threshold can only be evaluated against ownership the analyst supplies (from the
# client's KYC). We screen each named owner against OFAC and aggregate the stakes
# of any that are designated.
OWNERSHIP_THRESHOLD = 50.0


def _get_text(urls) -> str:
    """Fetch the first URL that responds; OFAC mirrors the list on two hosts."""
    last = None
    for url in (urls if isinstance(urls, tuple) else (urls,)):
        req = urllib.request.Request(url, headers={"User-Agent": UA,
                                                    "Accept-Encoding": "gzip, deflate"})
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                data = r.read()
                enc = r.headers.get("Content-Encoding", "")
            if enc == "gzip":
                data = gzip.decompress(data)
            elif enc == "deflate":
                data = zlib.decompress(data)
            time.sleep(0.2)
            return data.decode("utf-8", errors="replace")
        except Exception as e:  # try the mirror
            last = e
            continue
    raise last if last else RuntimeError("no OFAC source URL responded")


def _clean(v: str) -> str:
    return "" if v is None or v.strip() == EMPTY else v.strip()


def _match_rows(text: str, query: str, list_name: str) -> list:
    """Yield graded Items for rows whose primary name matches `query`."""
    q = query.lower().strip()
    if len(q) < 3:
        return []  # too short to screen safely
    word_re = re.compile(r"\b" + re.escape(q) + r"\b", re.IGNORECASE)

    items = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if len(row) <= COL_NAME:
            continue
        name = _clean(row[COL_NAME])
        if not name:
            continue
        nlow = name.lower()
        exact = (nlow == q)
        if not (exact or word_re.search(name)):
            continue

        rel = 0.97 if exact else 0.85
        sdn_type = _clean(row[COL_TYPE]) if len(row) > COL_TYPE else ""
        program = _clean(row[COL_PROGRAM]) if len(row) > COL_PROGRAM else ""
        remarks = _clean(row[COL_REMARKS]) if len(row) > COL_REMARKS else ""
        ent = _clean(row[COL_ENT_NUM]) if row else ""

        items.append(Item(
            source=f"OFAC {list_name}",
            title=f"OFAC {list_name} designation — {name}",
            url="https://sanctionssearch.ofac.treas.gov/",
            tier=Tier.T1_PRIMARY,
            relevance=rel,
            verification=Verification.OPENED,
            summary=(f"{sdn_type or 'Entity'} on the OFAC {list_name} list"
                     f"{f' under program(s) {program}' if program else ''}. "
                     f"{('Note: ' + remarks + '. ') if remarks else ''}"
                     f"CLIENT ACTION: HALT dealings and escalate to counsel — "
                     f"transacting with a designated party may violate US sanctions."),
            raw={"ent_num": ent, "name": name, "type": sdn_type,
                 "program": program, "list": list_name, "match": "exact" if exact else "name"},
        ).score())
    return items


def _ent_name_map(text: str) -> dict:
    """Map ent_num -> (name, type, program, remarks) from a primary file."""
    m = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) <= COL_NAME:
            continue
        ent = _clean(row[COL_ENT_NUM])
        if not ent:
            continue
        m[ent] = (
            _clean(row[COL_NAME]),
            _clean(row[COL_TYPE]) if len(row) > COL_TYPE else "",
            _clean(row[COL_PROGRAM]) if len(row) > COL_PROGRAM else "",
            _clean(row[COL_REMARKS]) if len(row) > COL_REMARKS else "",
        )
    return m


def _match_alts(alt_text: str, query: str, list_name: str, ent_map: dict) -> list:
    """Match `query` against a.k.a./f.k.a. names, resolving to the primary entity."""
    q = query.lower().strip()
    if len(q) < 3:
        return []
    word_re = re.compile(r"\b" + re.escape(q) + r"\b", re.IGNORECASE)

    items = []
    for row in csv.reader(io.StringIO(alt_text)):
        if len(row) <= ALT_NAME:
            continue
        alt_name = _clean(row[ALT_NAME])
        if not alt_name:
            continue
        nlow = alt_name.lower()
        exact = (nlow == q)
        if not (exact or word_re.search(alt_name)):
            continue

        ent = _clean(row[ALT_ENT_NUM])
        alt_type = _clean(row[ALT_TYPE]) if len(row) > ALT_TYPE else "aka"
        primary_name, sdn_type, program, remarks = ent_map.get(
            ent, (f"OFAC entity {ent}", "", "", ""))
        rel = 0.9 if exact else 0.82   # an a.k.a. match is a touch below a primary-name hit

        items.append(Item(
            source=f"OFAC {list_name}",
            title=f"OFAC {list_name} designation — {primary_name}",
            url="https://sanctionssearch.ofac.treas.gov/",
            tier=Tier.T1_PRIMARY,
            relevance=rel,
            verification=Verification.OPENED,
            summary=(f"{sdn_type or 'Entity'} on the OFAC {list_name} list"
                     f"{f' under program(s) {program}' if program else ''}, "
                     f"matched via {alt_type or 'a.k.a.'} \"{alt_name}\". "
                     f"{('Note: ' + remarks + '. ') if remarks else ''}"
                     f"CLIENT ACTION: HALT dealings and escalate to counsel — "
                     f"transacting with a designated party may violate US sanctions."),
            raw={"ent_num": ent, "name": primary_name, "type": sdn_type,
                 "program": program, "list": list_name,
                 "match": "alias", "alias": alt_name, "alias_type": alt_type},
        ).score())
    return items


def _screen(name: str, primary: str, alt: str, ent_map: dict, list_name: str) -> list:
    """Screen one name against a single list's primary + a.k.a. data."""
    hits = _match_rows(primary, name, list_name)
    if alt:
        hits += _match_alts(alt, name, list_name, ent_map)
    return hits


def _dedupe(items: list) -> list:
    """De-dupe by (list, entity); prefer a primary-name match over an alias match."""
    best = {}
    for it in items:
        key = (it.raw.get("list"), it.raw.get("ent_num"))
        cur = best.get(key)
        if cur is None or (cur.raw.get("match") == "alias" and it.raw.get("match") != "alias"):
            best[key] = it
    return sorted(best.values(), key=lambda it: -it.relevance)


def _ownership_items(vendor: str, owners: list, owner_hits: dict) -> list:
    """Apply the OFAC 50 Percent Rule to analyst-supplied ownership.

    owners:     [{"name": str, "pct": float}, ...] the vendor's known owners
    owner_hits: {owner_name: [Item, ...]} OFAC designations found for each owner
    Returns graded Items: one per designated owner (so the OFAC source is preserved)
    plus one aggregate conclusion Item when designated ownership exists.
    """
    items = []
    designated = [(o, owner_hits[o["name"]]) for o in owners if owner_hits.get(o["name"])]
    if not designated:
        return items

    aggregate = 0.0
    labels = []
    for o, hits in designated:
        pct = float(o.get("pct") or 0)
        aggregate += pct
        labels.append(f"{o['name']} ({pct:g}%)")
        best = _dedupe(hits)[0]
        items.append(Item(
            source=best.source,
            title=f"Designated OWNER of {vendor} — {best.raw.get('name')} ({pct:g}% stake)",
            url=best.url,
            tier=Tier.T1_PRIMARY,
            relevance=0.9,
            verification=Verification.OPENED,
            summary=(f"{o['name']}, holding a {pct:g}% stake in {vendor}, is on the OFAC "
                     f"{best.raw.get('list')} list. Ownership by a blocked person can block "
                     f"the vendor under the 50% rule."),
            raw={"kind": "owner", "owner": o["name"], "pct": pct,
                 "ent_num": best.raw.get("ent_num"), "list": best.raw.get("list")},
        ).score())

    blocked = aggregate >= OWNERSHIP_THRESHOLD
    items.append(Item(
        source="OFAC 50% Rule",
        title=(f"{vendor} — BLOCKED by ownership (OFAC 50% rule)" if blocked
               else f"{vendor} — partial designated ownership below 50%"),
        url="https://ofac.treasury.gov/faqs/topic/1521",  # OFAC 50% rule FAQs
        tier=Tier.T1_PRIMARY,
        relevance=0.97 if blocked else 0.65,
        # rests on OFAC designations (opened) + analyst-supplied KYC ownership
        verification=Verification.CORROBORATED,
        summary=(
            f"Designated owners total {aggregate:g}% of {vendor}: {', '.join(labels)}. "
            + ("This meets/exceeds the 50% threshold — the vendor is itself BLOCKED even "
               "though OFAC does not list it. CLIENT ACTION: HALT dealings and escalate to "
               "counsel."
               if blocked else
               "This is below the 50% threshold on the ownership provided, but any designated "
               "owner is a serious flag. CLIENT ACTION: verify the FULL ownership chain — "
               "undisclosed stakes could push the aggregate to 50%.")
            + " Note: OFAC publishes no ownership data; this rests on the ownership you supplied."
        ),
        raw={"kind": "ownership_rule", "vendor": vendor, "aggregate_pct": aggregate,
             "blocked": blocked, "owners": labels},
    ).score())
    return items


def collect(vendor: str, limit: int = 25, owners: list = None) -> list:
    """Return graded Items for OFAC hits on `vendor` across SDN + Consolidated,
    matching canonical names and a.k.a./f.k.a. aliases.

    If `owners` is given ([{"name","pct"}, ...]), also screen each owner and apply
    the OFAC 50 Percent Rule: a vendor owned >=50% in aggregate by designated
    parties is itself blocked even when OFAC does not list it.
    """
    owners = owners or []
    vendor_items = []
    owner_hits = {}
    for list_name, files in SOURCES.items():
        try:
            primary = _get_text(files["primary"])
        except Exception as e:
            # a fetch failure must be LOUD, never a silent clean screen
            print(f"[sanctions] {list_name} primary fetch FAILED — screen INCOMPLETE: {e}")
            continue
        ent_map = _ent_name_map(primary)
        try:
            alt = _get_text(files["alt"])
        except Exception as e:
            print(f"[sanctions] {list_name} a.k.a. file fetch failed "
                  f"(primary-name screen still ran): {e}")
            alt = ""

        hits = _screen(vendor, primary, alt, ent_map, list_name)
        print(f"[sanctions] {len(hits)} {list_name} match(es) for '{vendor}' (name + a.k.a.)")
        vendor_items.extend(hits)

        for o in owners:
            oh = _screen(o["name"], primary, alt, ent_map, list_name)
            if oh:
                owner_hits.setdefault(o["name"], []).extend(oh)

    items = _dedupe(vendor_items)
    if owners:
        n_flagged = len([o for o in owners if owner_hits.get(o['name'])])
        print(f"[sanctions] 50% rule: {n_flagged}/{len(owners)} named owner(s) designated")
        items += _ownership_items(vendor, owners, owner_hits)
    return items[:limit]


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "Rosoboronexport"
    from core.provenance import tag
    # optional ownership demo: --owner "Name:pct" (repeatable)
    owners = []
    for a in sys.argv[2:]:
        if a.startswith("--owner=") and ":" in a:
            nm, _, pct = a[len("--owner="):].rpartition(":")
            owners.append({"name": nm.strip(), "pct": float(pct)})
    hits = collect(target, limit=10, owners=owners)
    if not hits:
        print(f"  CLEAN — no OFAC match for '{target}' (this is the expected result "
              f"for a legitimate vendor; report it as a passed screen, not silence).")
    for it in hits:
        print(f"  {tag(it):34} rel={it.relevance}  {it.title}")
