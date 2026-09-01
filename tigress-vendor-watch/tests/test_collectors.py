"""
test_collectors.py — offline invariant tests for the new collector grading.

No network. Every collector's HTTP layer is separated from its GRADING layer, so
these tests feed fixtures straight into the pure grading/parsing functions and
assert the spine's discipline holds end to end. Run:  python3 tests/test_collectors.py
"""
import os
import sys

# make the package root importable regardless of cwd
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.provenance import Confidence, Verification, Tier
from collectors import hibp, sanctions, disruption, edgar
import synthesize


def test_hibp_password_urgency():
    plaintext = {"Name": "Acme", "Title": "Acme", "Domain": "acme.com",
                 "IsVerified": True, "BreachDate": "2024-01-01", "PwnCount": 1_000_000,
                 "DataClasses": ["Email addresses", "Passwords"],
                 "Description": "Passwords were stored in plain text."}
    bcrypt = {"Name": "Beta", "Title": "Beta", "Domain": "beta.com",
              "IsVerified": True, "BreachDate": "2023-05-01", "PwnCount": 500,
              "DataClasses": ["Passwords"], "Description": "Hashed with bcrypt."}
    pii = {"Name": "Gamma", "Title": "Gamma", "Domain": "g.com", "IsVerified": True,
           "BreachDate": "2022-01-01", "PwnCount": 9,
           "DataClasses": ["Email addresses", "Names"], "Description": "PII only."}
    assert hibp._password_urgency(plaintext) == 0.9
    assert hibp._password_urgency(bcrypt) == 0.6
    assert hibp._password_urgency(pii) == 0.35

    # plaintext-password breach must headline; PII-only must not (relevance < 0.5)
    assert hibp._breach_item(plaintext).headline_eligible is True
    assert hibp._breach_item(pii).headline_eligible is False


def test_hibp_unverified_is_discounted_and_barred():
    unverified = {"Name": "Rumor", "Title": "Rumor", "Domain": "r.com",
                  "IsVerified": False, "BreachDate": "2025-01-01", "PwnCount": 10,
                  "DataClasses": ["Passwords"], "Description": "plaintext (alleged)."}
    it = hibp._breach_item(unverified)
    assert it.verification == Verification.UNVERIFIED
    assert it.relevance == 0.45                 # 0.9 halved
    assert it.headline_eligible is False, "unverified HIBP breach must not headline"


def test_hibp_stealer_log_is_top_urgency():
    it = hibp._stealer_item("acme.com", 4)
    assert it.relevance == 0.95
    assert it.tier == Tier.T1_PRIMARY
    assert it.headline_eligible is True


def test_sanctions_word_boundary_and_clean():
    fixture = "\n".join([
        '12345,"ROSOBORONEXPORT OAO","Entity","UKRAINE-EO13662",-0-,-0-,-0-,-0-,-0-,-0-,-0-,"Arms exporter"',
        '999,"ACME LOGISTICS LLC","Entity","SDGT",-0-,-0-,-0-,-0-,-0-,-0-,-0-,-0-',
    ])
    hits = sanctions._match_rows(fixture, "Rosoboronexport", "SDN")
    assert len(hits) == 1
    assert hits[0].tier == Tier.T1_PRIMARY and hits[0].headline_eligible is True
    # word-boundary: a short run inside a longer word must NOT match
    assert sanctions._match_rows(fixture, "oso", "SDN") == []
    # a legitimate vendor screens clean
    assert sanctions._match_rows(fixture, "Ford Motor Co", "SDN") == []
    # too-short query is refused outright
    assert sanctions._match_rows(fixture, "ab", "SDN") == []


def test_sanctions_alias_resolves_to_primary():
    # OFAC lists the canonical transliteration in the primary file and the
    # common spelling only as an a.k.a. — screening must catch the a.k.a. and
    # resolve it back to the primary designation, or it silently false-negatives.
    primary = '18782,"ROSOBORONEKSPORT OAO","Entity","RUSSIA-EO14024",-0-,-0-,-0-,-0-,-0-,-0-,-0-,"Arms exporter"'
    alt = "\n".join([
        '18782,29577,"aka","ROSOBORONEXPORT JSC",-0-',
        '999,12,"aka","SOME OTHER ALIAS",-0-',
    ])
    ent_map = sanctions._ent_name_map(primary)
    # the canonical name is NOT what the client typed
    assert sanctions._match_rows(primary, "Rosoboronexport", "SDN") == []
    # but the a.k.a. match resolves to the primary entity + name
    hits = sanctions._match_alts(alt, "Rosoboronexport", "SDN", ent_map)
    assert len(hits) == 1
    it = hits[0]
    assert "ROSOBORONEKSPORT OAO" in it.title      # resolved to canonical name
    assert it.raw["match"] == "alias"
    assert it.headline_eligible is True
    assert "a.k.a." in it.summary or "aka" in it.summary.lower()


def test_sanctions_50pct_ownership_rule():
    # OFAC 50% rule: a vendor owned >=50% in aggregate by designated parties is
    # itself blocked even though OFAC never lists it. OFAC publishes no ownership,
    # so this is evaluated against analyst-supplied stakes.
    primary = "\n".join([
        '18782,"ROSOBORONEKSPORT OAO","Entity","RUSSIA-EO14024",-0-,-0-,-0-,-0-,-0-,-0-,-0-,"Arms"',
        '555,"BLOCKED HOLDINGS LLC","Entity","SDGT",-0-,-0-,-0-,-0-,-0-,-0-,-0-,-0-',
    ])
    hits_for = lambda name: sanctions._match_rows(primary, name, "SDN")

    # aggregate 30+25 = 55% -> BLOCKED, headline-eligible
    owners = [{"name": "Blocked Holdings LLC", "pct": 30},
              {"name": "Rosoboroneksport OAO", "pct": 25},
              {"name": "Clean Co", "pct": 45}]
    oh = {o["name"]: hits_for(o["name"]) for o in owners if hits_for(o["name"])}
    items = sanctions._ownership_items("Acme Vendor", owners, oh)
    rule = [it for it in items if it.raw.get("kind") == "ownership_rule"][0]
    assert rule.raw["blocked"] is True and rule.raw["aggregate_pct"] == 55
    assert rule.headline_eligible is True
    # each designated owner is surfaced with its OFAC source preserved
    owner_items = [it for it in items if it.raw.get("kind") == "owner"]
    assert len(owner_items) == 2

    # aggregate 20% -> partial flag, not blocked
    owners2 = [{"name": "Blocked Holdings LLC", "pct": 20}, {"name": "Clean Co", "pct": 80}]
    oh2 = {o["name"]: hits_for(o["name"]) for o in owners2 if hits_for(o["name"])}
    rule2 = [it for it in sanctions._ownership_items("Beta", owners2, oh2)
             if it.raw.get("kind") == "ownership_rule"][0]
    assert rule2.raw["blocked"] is False and rule2.raw["aggregate_pct"] == 20

    # no designated owners -> no ownership items at all
    owners3 = [{"name": "Clean Co", "pct": 100}]
    oh3 = {o["name"]: hits_for(o["name"]) for o in owners3 if hits_for(o["name"])}
    assert sanctions._ownership_items("Gamma", owners3, oh3) == []


def test_disruption_leads_never_headline():
    xml = b"""<?xml version="1.0"?><rss version="2.0"><channel>
    <item><title>Yellow Corp files for bankruptcy amid strike</title>
    <link>http://n/1</link><pubDate>Mon, 25 Aug 2026 12:00:00 GMT</pubDate>
    <description>insolvency</description><source>Reuters</source></item>
    <item><title>Yellow Corp unveils new logo</title>
    <link>http://n/2</link><pubDate>Tue, 01 Jan 2026 12:00:00 GMT</pubDate>
    <description>marketing</description><source>Blog</source></item>
    </channel></rss>"""
    items = disruption.parse_feed(xml, "Yellow Corp", 10)
    titles = [it.title for it in items]
    assert any("bankruptcy" in t for t in titles)
    assert not any("logo" in t for t in titles), "no-disruption item must be dropped"
    assert all(it.tier == Tier.T4_AGGREGATE for it in items)
    assert all(it.confidence == Confidence.LOW for it in items)
    assert all(not it.headline_eligible for it in items), "T4 leads must never headline"


def test_edgar_fulltext_fallback_parsing():
    blob = {"hits": {"hits": [
        {"_id": "0000037996-26-000155:f-20260728.htm",
         "_source": {"ciks": ["0000037996"], "display_names": ["FORD MOTOR CO (CIK 0000037996)"],
                     "file_date": "2026-07-28", "root_forms": ["8-K"]}},
    ]}}
    items = edgar._parse_efts_hits(blob, 10)
    assert len(items) == 1
    it = items[0]
    assert it.relevance == 0.6 and "8-K" in it.title
    assert it.source == "SEC EDGAR (full-text)"
    assert it.url == ("https://www.sec.gov/Archives/edgar/data/37996/"
                      "000003799626000155/f-20260728.htm")


def test_synthesize_template_fallback_respects_grades():
    from core.provenance import Item
    demo = [
        Item("CISA KEV", "Cisco ASA — CVE-2026-20349", "http://x", Tier.T2_OFFICIAL,
             relevance=0.85, verification=Verification.OPENED, summary="exploited").score(),
        Item("News/Blog", "Cisco supplier strike", "http://y", Tier.T4_AGGREGATE,
             relevance=0.6, verification=Verification.UNVERIFIED, summary="lead").score(),
    ]
    res = synthesize.synthesize("Cisco Systems", demo, ["HIBP not run — wire the key."])
    assert res["engine"] == "template", "no Ollama here -> must fall back"
    txt = res["text"]
    assert "Cisco ASA" in txt and "actionable" in txt.lower()
    assert "WATCH" in txt and "asserted as fact" in txt
    assert "HIBP not run" in txt


def test_synthesize_backend_selection_falls_back():
    from core.provenance import Item
    demo = [Item("CISA KEV", "Cisco ASA — CVE-2026-20349", "http://x", Tier.T2_OFFICIAL,
                 relevance=0.85, verification=Verification.OPENED, summary="x").score()]
    gaps = ["HIBP not run."]
    # anthropic backend with no key present here -> graceful template fallback
    res = synthesize.synthesize("Cisco", demo, gaps, backend="anthropic")
    assert res["engine"] == "template", "no ANTHROPIC_API_KEY -> template fallback"
    # unknown backend name -> template fallback, never a crash
    res2 = synthesize.synthesize("Cisco", demo, gaps, backend="does-not-exist")
    assert res2["engine"] == "template"
    # both real backends are registered behind the one interface
    assert set(synthesize.BACKENDS) == {"ollama", "anthropic"}


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\nAll {len(tests)} collector invariants hold.")
