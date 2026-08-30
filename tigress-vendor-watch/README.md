# TIGRESS Vendor Watch

Vendor breach + corporate-distress monitoring. Input a vendor, get a tiered
risk report. Built for small-business supply-chain risk — the scalable core of
the cyber practice, distinct from the bespoke individual-protection work.

## What this is NOT
Not a WorldMonitor clone. WorldMonitor polls ~40 general-news feeds for a globe.
This polls PRIMARY RECORDS (SEC filings, breach corpora, exploited-vuln lists,
sanctions) that WorldMonitor doesn't touch. Almost zero source overlap — that's
the whole point. Their moat is breadth; yours is graded, fused depth.

## Architecture
```
collectors/   one module per source
  edgar.py    SEC filings (T1)         — WORKS, no key. + efts full-text fallback
                                          for delisted/historical/private filers
  kev.py      CISA exploited vulns (T2)— WORKS, no key
  hibp.py     breach exposure (T1)     — WORKS. Public breaches?domain layer runs
                                          with NO key; stealer-log + breacheddomain
                                          layers activate when HIBP_API_KEY is set
  sanctions.py OFAC/sanctions (T1)     — WORKS, no key. SDN + consolidated,
                                          word-boundary matched. A hit HALTS dealings
  disruption.py news disruption (T4)   — WORKS, no key. Google News RSS leads,
                                          graded down to true weight (watch-only)
core/
  provenance.py  THE SPINE as code. tier/relevance/verification scoring.
                 relevance leads tier; unopened sources capped + barred from
                 headlines. This is your OSINT-suite rubric made executable.
synthesize.py    hands GRADED items to local Qwen via Ollama -> analyst lede.
                 WORKS. Degrades to a deterministic template if Ollama is offline
                 (the tool never dies for a missing sidecar). Enable with
                 `watch.py --synthesize`.
report/          markdown out first, dashboard later
vendors.yaml     the watchlist
```

## The spine is the product
`core/provenance.py` is why this isn't a generic scraper. Every item is graded
BEFORE the model sees it. Live-tested invariants (tests/test_provenance.py):
- a relevant corroborated T3 report OUTRANKS an irrelevant T1 filing
- an unverified T5 rumor is capped LOW and barred from any headline
- a distress 8-K (rel 0.6) outranks a routine 10-Q (rel 0.25) at the same tier

## Honest limitations (found by testing, not hidden)
- **EDGAR = public companies only, near-exact name match.** Most vendors a
  small-business client cares about are PRIVATE and won't appear. The ticker
  index also FORGETS a company that delists after bankruptcy — exactly the
  distress you most want to catch. *Mitigated:* `edgar.py` now falls back to the
  efts.sec.gov full-text index when the ticker lookup misses, catching
  historical/delisted/name-mismatched filers. efts only reaches back to 2001,
  and a truly private supplier with no SEC footprint still won't appear.
- **HIBP now runs without a key** (public `breaches?domain` layer). The
  stealer-log and breacheddomain layers — the highest-urgency signals — still
  need a subscribed `HIBP_API_KEY`; without it those are declared as a gap, not
  silently skipped.
- **disruption.py is deliberately weak (T4).** It is a lead source, never a
  conclusion: every item is capped LOW confidence, marked unverified, and barred
  from the actionable headline. It tells the analyst what to go corroborate.
- Private-vendor coverage is still the real product gap. EDGAR/KEV/sanctions
  cover the public, technical, and legal; private-vendor distress needs court
  dockets (PACER) and business-registration data — collectors not built yet.

## Laptop / Claude Code handoff
Built out in this pass (all no-key layers run today; keys unlock the rest):
1. **hibp.py** — public breach layer + hash-urgency grading implemented; wire
   `HIBP_API_KEY` in `.env` to add the stealer-log / breacheddomain layers.
2. **sanctions.py** — OFAC SDN + consolidated, word-boundary matched, T1.
3. **disruption.py** — Google News RSS leads, graded to T4 watch-only.
4. **synthesize.py** — Ollama (`OLLAMA_HOST` / `OLLAMA_MODEL`) with a
   deterministic template fallback; enable with `watch.py --synthesize`.
5. **edgar.py** — efts full-text fallback for delisted/historical filers.

Still open: sanctions beneficial-ownership drill-down, PACER/court-docket and
business-registration collectors for private-vendor distress, and the dashboard.

Copy `.env.example` -> `.env` (gitignored) and fill in `EDGAR_UA` (required by
SEC) plus any optional keys. First real deliverable: run one real vendor end to
end, produce the markdown brief, and THAT is the artifact you show a prospect.

## Run it
```
# one vendor, full stack, with the analyst lede:
EDGAR_UA="TIGRESS research you@you.com" \
  python3 watch.py "Cisco Systems" --domain cisco.com \
  --runs edgar,kev,hibp,sanctions,disruption --synthesize

# individual collectors (each runs standalone):
python3 collectors/edgar.py "Ford Motor Co"
python3 collectors/kev.py "Cisco"
python3 collectors/sanctions.py "Rosoboronexport"
python3 collectors/hibp.py "adobe.com"
python3 collectors/disruption.py "Yellow Corp"

# tests (offline, no network, no keys):
python3 tests/test_collectors.py
cd tests && python3 test_provenance.py
```
