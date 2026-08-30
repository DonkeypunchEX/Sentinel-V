"""
synthesize.py — turn GRADED items into a short analyst narrative.

The spine (core/provenance.py) grades every item before this module ever runs,
so the model reasons over graded intelligence, not raw headlines. This module
hands that graded, ranked material to a model and asks for a tight executive
summary a non-technical business owner can act on.

Three hard rules, enforced by construction rather than trust:

  1. The model only ever sees GRADED items with their [tier · confidence ·
     verification] tags, plus the declared gaps. It cannot reference anything
     the spine didn't already vet.
  2. If the model backend is unreachable, we DO NOT fail — we fall back to a
     deterministic, grade-driven template summary. A monitoring tool that dies
     because a sidecar model is down is useless; an honest template beats an
     outage.
  3. Backend is swappable behind one interface, and nothing else in the system
     knows or cares which model wrote the prose:
       - "ollama"    -> local Qwen at OLLAMA_HOST. DEFAULT: private, free,
                        offline, no third-party dependency. The production path.
       - "anthropic" -> Claude via the Messages API. A convenience for proving
                        the pipeline live when no local Ollama is running; needs
                        ANTHROPIC_API_KEY. Raw HTTP over stdlib on purpose — this
                        project takes no third-party deps so it runs anywhere.
     Select with the TIGRESS_LLM env var (default "ollama") or the `backend=` arg.

The model output is clearly labelled as model-generated narrative. The graded
item list in the markdown brief remains the source of truth; this is a readable
lede over it, never a replacement for it.

Config (env):
  TIGRESS_LLM       "ollama" (default) | "anthropic"
  OLLAMA_HOST       default http://localhost:11434
  OLLAMA_MODEL      default qwen2.5:7b
  ANTHROPIC_API_KEY required only for the anthropic backend (never commit it)
  ANTHROPIC_MODEL   default claude-opus-5
"""

import os
import sys
import json
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.provenance import rank, tag

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5")
DEFAULT_BACKEND = os.environ.get("TIGRESS_LLM", "ollama")

SYSTEM = (
    "You are a vendor-risk analyst writing for a non-technical small-business "
    "owner. You are given intelligence items that have ALREADY been graded by a "
    "provenance rubric: each carries [tier T1-T5 · confidence · verification]. "
    "Rules you must follow:\n"
    "- Write at most 150 words, plain language, no jargon.\n"
    "- Lead with what the client should DO, if anything.\n"
    "- NEVER assert an unverified (T4/T5 or 'unverified') item as fact — call it "
    "a lead to confirm.\n"
    "- If nothing is actionable, say so plainly; do not manufacture urgency.\n"
    "- End by naming the biggest blind spot from the GAPS list.\n"
    "Do not invent items, numbers, or sources beyond what you are given."
)


def _context_block(items: list, gaps: list) -> str:
    items = rank(items)
    headline = [it for it in items if it.headline_eligible]
    watch = [it for it in items if not it.headline_eligible and it.relevance >= 0.5]
    lines = ["ACTIONABLE (corroborated + relevant):"]
    lines += [f"  - {tag(it)} {it.title} :: {it.summary}" for it in headline] or ["  (none)"]
    lines.append("WATCH (relevant leads, not yet confirmed):")
    lines += [f"  - {tag(it)} {it.title}" for it in watch[:8]] or ["  (none)"]
    lines.append(f"LOGGED COUNT: {len(items) - len(headline) - len(watch)} routine items.")
    lines.append("GAPS:")
    lines += [f"  - {g}" for g in gaps] or ["  (none declared)"]
    return "\n".join(lines)


def _ollama(vendor: str, context: str, timeout: int = 60) -> str:
    prompt = (f"{SYSTEM}\n\nVENDOR: {vendor}\n\nGRADED INTELLIGENCE:\n{context}\n\n"
              f"Write the analyst summary now.")
    body = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2},
    }).encode()
    req = urllib.request.Request(f"{OLLAMA_HOST}/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        payload = json.loads(r.read())
    return (payload.get("response") or "").strip()


def _anthropic(vendor: str, context: str, timeout: int = 60) -> str:
    """Claude via the Messages API (raw HTTP, stdlib only). Convenience backend.

    Note: current Claude models reject top-level sampling params (`temperature`
    etc.) — do NOT send them. `effort: low` keeps this cheap/fast for a short
    summary; the graded item list, not this prose, remains the source of truth.
    """
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("no ANTHROPIC_API_KEY set")
    body = json.dumps({
        "model": ANTHROPIC_MODEL,
        "max_tokens": 1024,
        "system": SYSTEM,
        "output_config": {"effort": "low"},
        "messages": [{"role": "user",
                      "content": (f"VENDOR: {vendor}\n\nGRADED INTELLIGENCE:\n{context}\n\n"
                                  f"Write the analyst summary now.")}],
    }).encode()
    req = urllib.request.Request(ANTHROPIC_URL, data=body, headers={
        "content-type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        payload = json.loads(r.read())
    return "".join(b.get("text", "") for b in payload.get("content", [])
                   if b.get("type") == "text").strip()


# backend registry — one interface, model-agnostic to the rest of the system
BACKENDS = {"ollama": _ollama, "anthropic": _anthropic}


def _template(vendor: str, items: list, gaps: list) -> str:
    """Deterministic, grade-driven fallback. Runs with zero dependencies."""
    items = rank(items)
    headline = [it for it in items if it.headline_eligible]
    watch = [it for it in items if not it.headline_eligible and it.relevance >= 0.5]

    parts = []
    if headline:
        top = headline[0]
        parts.append(
            f"{len(headline)} corroborated, client-relevant signal(s) cleared the bar "
            f"for {vendor}. Highest priority: {top.title} {tag(top)}. "
            f"Treat these as actionable now."
        )
    else:
        parts.append(
            f"No corroborated, client-relevant signal cleared the actionable bar for "
            f"{vendor} this run — a clean result, not an empty one."
        )
    if watch:
        parts.append(
            f"{len(watch)} lower-confidence lead(s) sit in WATCH; confirm against a "
            f"primary source before acting — none is asserted as fact."
        )
    if gaps:
        parts.append(f"Biggest blind spot: {gaps[0]}")
    return " ".join(parts)


def synthesize(vendor: str, items: list, gaps: list = None,
               backend: str = None) -> dict:
    """
    Return {'text': narrative, 'engine': 'ollama'|'anthropic'|'template', 'model': ...}.
    Never raises on model unavailability — falls back to the deterministic template.
    Backend selection: `backend=` arg, else TIGRESS_LLM env, else "ollama".
    """
    gaps = gaps or []
    backend = backend or DEFAULT_BACKEND
    context = _context_block(items, gaps)

    fn = BACKENDS.get(backend)
    if fn is None:
        print(f"[synthesize] unknown backend '{backend}' (ollama|anthropic) — "
              f"using deterministic template fallback.")
        return {"text": _template(vendor, items, gaps), "engine": "template", "model": None}

    try:
        text = fn(vendor, context)
        if text:
            model = OLLAMA_MODEL if backend == "ollama" else ANTHROPIC_MODEL
            return {"text": text, "engine": backend, "model": model}
        raise RuntimeError("empty response")
    except (urllib.error.URLError, ConnectionError, TimeoutError,
            RuntimeError, OSError) as e:
        print(f"[synthesize] backend '{backend}' unavailable ({type(e).__name__}) — "
              f"using deterministic template fallback.")
        return {"text": _template(vendor, items, gaps),
                "engine": "template", "model": None}


def section(vendor: str, items: list, gaps: list = None, backend: str = None) -> str:
    """Render the synthesis as a markdown section for the brief."""
    res = synthesize(vendor, items, gaps, backend=backend)
    if res["engine"] == "template":
        label = "deterministic template — model offline"
    else:
        label = f"{res['engine']} model ({res['model']})"
    return (f"## Analyst summary\n> _Narrative generated by {label}. "
            f"The graded item list below remains the source of truth._\n\n"
            f"{res['text']}\n")


if __name__ == "__main__":
    # smoke test with a couple of graded items; will fall back to template here.
    from core.provenance import Item, Tier, Verification
    demo = [
        Item("CISA KEV", "Cisco ASA — CVE-2026-20349", "http://x", Tier.T2_OFFICIAL,
             relevance=0.85, verification=Verification.OPENED,
             summary="Exploited-in-wild. Do they run ASA?").score(),
        Item("News/Blog", "Cisco supplier hit by strike", "http://y", Tier.T4_AGGREGATE,
             relevance=0.6, verification=Verification.UNVERIFIED,
             summary="Disruption lead.").score(),
    ]
    # optional backend arg: `python3 synthesize.py anthropic` (else TIGRESS_LLM/ollama)
    backend = sys.argv[1] if len(sys.argv) > 1 else None
    print(section("Cisco Systems", demo,
                  ["HIBP (breach exposure) not run — wire the key."],
                  backend=backend))
