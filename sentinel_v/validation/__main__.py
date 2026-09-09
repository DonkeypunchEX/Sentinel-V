"""`python -m sentinel_v.validation` / `make validate` — run the coverage suite.

Prints an ATT&CK coverage table and exits non-zero if any scenario's expected
detection did not fire. That non-zero exit is what lets CI *block* on detection
regressions.
"""
from __future__ import annotations

import sys

from sentinel_v.validation.harness import DEFAULT_SCENARIOS_DIR, run_all


def main() -> int:
    results = run_all()
    if not results:
        print(f"No validation scenarios found under {DEFAULT_SCENARIOS_DIR}/")
        return 1

    print(f"Sentinel-V detection validation — {len(results)} scenario(s)\n")
    width = max(len(r.scenario.id) for r in results)
    failed = 0
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        tech = r.scenario.attack_technique or "-"
        print(f"  [{status}] {r.scenario.id:<{width}}  {tech:<10} {r.scenario.name}")
        if not r.passed:
            failed += 1
            print(f"         ↳ {r.reason} (fired: {', '.join(r.fired) or 'nothing'})")

    print(f"\n{len(results) - failed}/{len(results)} passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
