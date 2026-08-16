"""Rule-based (Sigma) detector — Phase 1.

Loads Sigma YAML rules and evaluates them against normalized Events in-process,
emitting ATT&CK-tagged Alerts. This is a focused, honest implementation of the
Sigma detection grammar rather than a full pySigma backend compile: pySigma's
backends target external query languages (Splunk/ES/...), which is the wrong
shape for an in-memory event stream. We implement the subset that matters for
this schema:

* named search-identifiers: field maps (AND across fields, OR across list
  values) and lists of maps (OR across the maps);
* field modifiers: ``contains``, ``startswith``, ``endswith``, ``re``, ``all``,
  ``cidr``, and numeric ``gt/gte/lt/lte``;
* value wildcards ``*`` / ``?`` (case-insensitive string comparison);
* ``condition`` expressions: ``and`` / ``or`` / ``not`` / parentheses and the
  ``1 of ...`` / ``all of ...`` aggregations over ``them`` or a ``name*`` glob.

Rules ship under ``rules/`` authored against the Event schema. ATT&CK technique
IDs come from the rule's ``tags`` (``attack.tXXXX``). See docs/PLAYBOOKS.md for
the detection-engineering discipline each rule should follow.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

import yaml

from sentinel_v.detection.base import Detector
from sentinel_v.models import Alert, Event, Severity

_LEVEL_TO_SEVERITY = {
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
_ATTACK_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


class SigmaRule:
    """A parsed Sigma rule with an in-memory ``matches(event)`` evaluator."""

    def __init__(self, doc: Mapping[str, Any], source: Path | None = None) -> None:
        self.source = source
        self.title: str = str(doc.get("title") or (source.stem if source else "unnamed"))
        self.id: str | None = doc.get("id")
        self.description: str = str(doc.get("description") or "")
        self.level: str = str(doc.get("level") or "low").lower()
        self.tags: list[str] = [str(t) for t in (doc.get("tags") or [])]
        self.logsource: dict[str, Any] = dict(doc.get("logsource") or {})

        detection = doc.get("detection")
        if not isinstance(detection, dict) or "condition" not in detection:
            raise ValueError(f"rule '{self.title}' has no valid 'detection' block")
        self._condition: str = str(detection["condition"])
        self._selections: dict[str, Any] = {
            k: v for k, v in detection.items() if k != "condition"
        }

    @property
    def severity(self) -> Severity:
        return _LEVEL_TO_SEVERITY.get(self.level, Severity.LOW)

    @property
    def attack_technique(self) -> str | None:
        for tag in self.tags:
            m = _ATTACK_TECHNIQUE.match(tag)
            if m:
                return m.group(1).upper()
        return None

    def matches(self, event: Event) -> bool:
        doc = _event_document(event)
        results = {name: _match_selection(sel, doc) for name, sel in self._selections.items()}
        return _eval_condition(self._condition, results)


class SigmaRuleDetector(Detector):
    name = "rules.sigma"

    def __init__(self, rules_dir: Path) -> None:
        self._rules_dir = Path(rules_dir)
        self.rules: list[SigmaRule] = []
        self.load()

    def load(self) -> None:
        """Load and compile every ``*.yml`` / ``*.yaml`` rule under rules_dir.

        A malformed rule is skipped (not fatal) so one bad file cannot take the
        whole detector offline; the rest still load.
        """
        self.rules = []
        if not self._rules_dir.exists():
            return
        for path in sorted(self._rules_dir.rglob("*")):
            if path.suffix.lower() not in {".yml", ".yaml"}:
                continue
            try:
                for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
                    if isinstance(doc, dict) and doc.get("detection"):
                        self.rules.append(SigmaRule(doc, source=path))
            except (yaml.YAMLError, ValueError):
                continue

    def detect(self, events: Iterable[Event]) -> Iterator[Alert]:
        for event in events:
            for rule in self.rules:
                if rule.matches(event):
                    yield Alert(
                        title=rule.title,
                        severity=rule.severity,
                        detector=self.name,
                        attack_technique=rule.attack_technique,
                        event_ids=[event.id],
                        detail={
                            "rule_id": rule.id,
                            "rule": str(rule.source) if rule.source else None,
                            "tags": rule.tags,
                            "src_ip": event.src_ip,
                            "kind": event.kind,
                        },
                    )


# --------------------------------------------------------------------------- #
# Matching primitives
# --------------------------------------------------------------------------- #
def _event_document(event: Event) -> dict[str, Any]:
    """Flatten an Event into a Sigma-matchable field document.

    Identity fields (kind/source/src_ip/...) are authoritative; the collector's
    normalized ``fields`` fill in the rest.
    """
    doc: dict[str, Any] = dict(event.fields)
    doc.update(
        {
            "kind": event.kind,
            "source": event.source,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "host": event.host,
        }
    )
    return doc


def _match_selection(selection: Any, doc: Mapping[str, Any]) -> bool:
    if isinstance(selection, list):
        # list of sub-selections -> OR
        return any(_match_selection(item, doc) for item in selection)
    if isinstance(selection, dict):
        # map of field constraints -> AND
        return all(_match_field(key, val, doc) for key, val in selection.items())
    # bare keyword selection isn't supported against structured events
    return False


def _resolve(doc: Mapping[str, Any], field: str) -> Any:
    """Look up a (possibly dotted) field path, descending into nested dicts.

    Sigma addresses nested JSON with dotted names (``alert.signature``); Suricata
    EVE records are nested, so honor that here.
    """
    if field in doc:
        return doc[field]
    cur: Any = doc
    for part in field.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _match_field(key: str, expected: Any, doc: Mapping[str, Any]) -> bool:
    field, _, mod = key.partition("|")
    actual = _resolve(doc, field)

    if mod in {"gt", "gte", "lt", "lte"}:
        return _numeric_compare(actual, expected, mod)
    if mod == "cidr":
        return _cidr_match(actual, expected)

    values = expected if isinstance(expected, list) else [expected]
    # "|all" means every listed value must match; default list semantics is OR.
    combine = all if mod == "all" else any
    return combine(_match_value(actual, v, mod) for v in values)


def _match_value(actual: Any, expected: Any, mod: str) -> bool:
    if expected is None:
        return actual is None
    if actual is None:
        return False
    if mod == "re":
        return re.search(str(expected), str(actual)) is not None

    a = str(actual)
    e = str(expected)
    if mod == "contains":
        pattern = f"*{e}*"
    elif mod == "startswith":
        pattern = f"{e}*"
    elif mod == "endswith":
        pattern = f"*{e}"
    else:
        # numeric equality when both sides are numbers
        if isinstance(actual, (int, float)) and _is_number(expected):
            return float(actual) == float(expected)
        pattern = e
    regex = fnmatch.translate(pattern)  # honors Sigma * and ? wildcards
    return re.match(regex, a, re.IGNORECASE) is not None


def _numeric_compare(actual: Any, expected: Any, mod: str) -> bool:
    if not (_is_number(actual) and _is_number(expected)):
        return False
    a, e = float(actual), float(expected)
    return {"gt": a > e, "gte": a >= e, "lt": a < e, "lte": a <= e}[mod]


def _cidr_match(actual: Any, expected: Any) -> bool:
    if not isinstance(actual, str):
        return False
    try:
        return ipaddress.ip_address(actual) in ipaddress.ip_network(str(expected), strict=False)
    except ValueError:
        return False


def _is_number(v: Any) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, (int, float)):
        return True
    try:
        float(v)
        return True
    except (TypeError, ValueError):
        return False


# --------------------------------------------------------------------------- #
# Condition expression evaluation
# --------------------------------------------------------------------------- #
def _eval_condition(condition: str, results: Mapping[str, bool]) -> bool:
    tokens = _tokenize_condition(condition)
    parser = _ConditionParser(tokens, results)
    value = parser.parse()
    if not parser.at_end():
        raise ValueError(f"trailing tokens in condition: {condition!r}")
    return value


def _tokenize_condition(condition: str) -> list[str]:
    spaced = condition.replace("(", " ( ").replace(")", " ) ")
    return spaced.split()


class _ConditionParser:
    """Recursive-descent parser: or > and > not/aggregation/atom."""

    def __init__(self, tokens: list[str], results: Mapping[str, bool]) -> None:
        self._t = tokens
        self._i = 0
        self._results = results

    def at_end(self) -> bool:
        return self._i >= len(self._t)

    def _peek(self) -> str | None:
        return self._t[self._i] if self._i < len(self._t) else None

    def _next(self) -> str:
        tok = self._t[self._i]
        self._i += 1
        return tok

    def parse(self) -> bool:
        return self._parse_or()

    def _parse_or(self) -> bool:
        value = self._parse_and()
        while (self._peek() or "").lower() == "or":
            self._next()
            value = self._parse_and() or value
        return value

    def _parse_and(self) -> bool:
        value = self._parse_unary()
        while (self._peek() or "").lower() == "and":
            self._next()
            value = self._parse_unary() and value
        return value

    def _parse_unary(self) -> bool:
        if (self._peek() or "").lower() == "not":
            self._next()
            return not self._parse_unary()
        return self._parse_atom()

    def _parse_atom(self) -> bool:
        tok = self._peek()
        if tok is None:
            raise ValueError("unexpected end of condition")
        if tok == "(":
            self._next()
            value = self._parse_or()
            if self._peek() != ")":
                raise ValueError("missing closing parenthesis in condition")
            self._next()
            return value
        # aggregation: "1 of ..." / "all of ..."
        if tok.lower() == "all" or tok.isdigit():
            return self._parse_aggregation()
        # bare identifier
        return bool(self._results.get(self._next(), False))

    def _parse_aggregation(self) -> bool:
        quant = self._next().lower()  # "all" or a number
        of = self._next()
        if of.lower() != "of":
            raise ValueError(f"expected 'of' in aggregation, got {of!r}")
        target = self._next()
        matched = self._resolve_targets(target)
        count = sum(1 for v in matched if v)
        if quant == "all":
            return bool(matched) and count == len(matched)
        return count >= int(quant)

    def _resolve_targets(self, target: str) -> list[bool]:
        if target.lower() == "them":
            return list(self._results.values())
        if target.endswith("*"):
            prefix = target[:-1]
            return [v for k, v in self._results.items() if k.startswith(prefix)]
        return [self._results.get(target, False)]
