"""
watch.py — the orchestrator. One command, one vendor, one brief.

    python watch.py "Ford Motor Co"
    python watch.py "Cisco Systems" --domain cisco.com --runs edgar,kev,hibp

Reads which collectors to fire (from --runs or vendors.yaml), fires them,
pools the graded Items, ranks through the spine, renders the markdown brief,
writes it to report/out/, and prints the actionable summary to stdout.

Each collector is isolated: if one fails, it becomes a declared GAP in the
report rather than crashing the run. A monitoring tool that dies because one
source timed out is useless — partial intelligence with honest gaps beats no
intelligence.
"""

import os
import sys
import argparse
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.provenance import rank
from render import render

from collectors import edgar, kev, hibp, sanctions, disruption

COLLECTORS = {
    "edgar":      ("SEC EDGAR (filings, distress)", lambda v, d: edgar.collect(v)),
    "kev":        ("CISA KEV (exploited vulns)",    lambda v, d: kev.collect(v)),
    "hibp":       ("HIBP (breach exposure)",        lambda v, d: hibp.collect(d) if d else []),
    "sanctions":  ("OFAC sanctions (SDN/consolidated)", lambda v, d: sanctions.collect(v)),
    "disruption": ("News disruption leads (T4 watch)",  lambda v, d: disruption.collect(v)),
}


def run(vendor: str, domain: str = None, runs: list = None, aliases: dict = None,
        synth: bool = False) -> str:
    runs = runs or ["edgar", "kev"]
    aliases = aliases or {}
    items = []
    gaps = []

    for name in runs:
        if name not in COLLECTORS:
            gaps.append(f"Unknown collector '{name}' — skipped.")
            continue
        label, fn = COLLECTORS[name]
        # each collector can take a per-collector alias; falls back to vendor.
        # EDGAR wants the registered name ("Cisco Systems"); KEV wants the
        # product/vendor token as it appears in the KEV data ("Cisco"). One
        # string can't satisfy both, so we let the vendor entry carry both.
        query = aliases.get(name, vendor)
        try:
            got = fn(query, domain)
            if not got:
                gaps.append(f"{label}: no results for '{query}' "
                            f"({'no domain given' if name=='hibp' and not domain else 'nothing matched, or source empty/stubbed'}).")
            items.extend(got)
        except Exception as e:
            gaps.append(f"{label}: collector FAILED — {type(e).__name__}: {e}")

    # standing gaps we always want the client to see
    if "hibp" not in runs or not domain:
        gaps.append("Breach-exposure (HIBP) not run — wire the key + domain for "
                    "the highest-signal source.")
    gaps.append("Private-vendor coverage is limited: EDGAR is public-company only. "
                "A private supplier may have zero footprint here.")

    synthesis = None
    if synth:
        from synthesize import section as synth_section
        synthesis = synth_section(vendor, items, gaps)

    md = render(vendor, items, gaps=gaps, synthesis=synthesis)

    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report", "out")
    os.makedirs(outdir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe = "".join(c if c.isalnum() else "_" for c in vendor)[:40]
    path = os.path.join(outdir, f"{safe}_{stamp}.md")
    with open(path, "w") as f:
        f.write(md)

    ranked = rank(items)
    actionable = [it for it in ranked if it.headline_eligible]
    print(f"\n=== {vendor} ===")
    print(f"collected {len(items)} · actionable {len(actionable)} · gaps {len(gaps)}")
    if actionable:
        print("ACTIONABLE:")
        for it in actionable:
            print(f"  • {it.title}")
    else:
        print("No actionable signal this run (clean result).")
    print(f"\nbrief written -> {path}")
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="TIGRESS Vendor Watch")
    ap.add_argument("vendor")
    ap.add_argument("--domain", default=None)
    ap.add_argument("--runs", default="edgar,kev",
                    help="comma-sep collectors: edgar,kev,hibp,sanctions,disruption")
    ap.add_argument("--synthesize", action="store_true",
                    help="add an analyst-summary lede via local Ollama model "
                         "(falls back to a deterministic template if offline)")
    ap.add_argument("--alias", action="append", default=[],
                    help="per-collector alias, e.g. --alias kev=Cisco "
                         "(repeatable). EDGAR wants the registered name, KEV "
                         "the short product token.")
    args = ap.parse_args()
    aliases = {}
    for a in args.alias:
        if "=" in a:
            k, v = a.split("=", 1)
            aliases[k.strip()] = v.strip()
    run(args.vendor, args.domain, [r.strip() for r in args.runs.split(",")], aliases,
        synth=args.synthesize)
