"""Phase 1: the Sigma-subset evaluator (selections, modifiers, condition grammar)."""
from __future__ import annotations

from pathlib import Path

from sentinel_v.detection.rules import SigmaRuleDetector
from sentinel_v.models import Event


def _write(dir_: Path, name: str, body: str) -> None:
    (dir_ / name).write_text(body)


def test_condition_and_not_and_attack_tag(tmp_path):
    _write(
        tmp_path,
        "a.yml",
        "title: A\n"
        "detection:\n"
        "  sel: { kind: auth_fail }\n"
        "  filt: { src_ip: 10.0.0.1 }\n"
        "  condition: sel and not filt\n"
        "level: medium\n"
        "tags: [attack.t1110]\n",
    )
    det = SigmaRuleDetector(tmp_path)
    assert len(det.rules) == 1

    hit = list(det.detect([Event(source="auth.log", kind="auth_fail", src_ip="1.2.3.4")]))
    assert len(hit) == 1
    assert hit[0].attack_technique == "T1110"

    # filtered source suppresses the alert
    assert list(det.detect([Event(source="auth.log", kind="auth_fail", src_ip="10.0.0.1")])) == []


def test_modifiers_cidr_numeric_and_wildcard(tmp_path):
    _write(
        tmp_path,
        "b.yml",
        "title: B\n"
        "detection:\n"
        "  sel:\n"
        "    kind: flow\n"
        "    src_ip|cidr: 192.168.0.0/16\n"
        "    dst_port|gte: 1024\n"
        "    host|startswith: web\n"
        "  condition: sel\n"
        "level: low\n",
    )
    det = SigmaRuleDetector(tmp_path)
    match = Event(source="s", kind="flow", src_ip="192.168.5.5", host="web-01",
                  fields={"dst_port": 8080})
    miss = Event(source="s", kind="flow", src_ip="8.8.8.8", host="web-01",
                 fields={"dst_port": 8080})
    low_port = Event(source="s", kind="flow", src_ip="192.168.5.5", host="web-01",
                     fields={"dst_port": 22})
    assert len(list(det.detect([match]))) == 1
    assert list(det.detect([miss])) == []
    assert list(det.detect([low_port])) == []


def test_of_them_aggregation_and_list_or(tmp_path):
    _write(
        tmp_path,
        "c.yml",
        "title: C\n"
        "detection:\n"
        "  sel_a: { kind: alert }\n"
        "  sel_b: { source: suricata.eve }\n"
        "  condition: all of sel*\n"
        "level: high\n",
    )
    _write(
        tmp_path,
        "d.yml",
        "title: D\n"
        "detection:\n"
        "  s1: { kind: dns }\n"
        "  s2: { kind: alert }\n"
        "  condition: 1 of them\n"
        "level: low\n",
    )
    det = SigmaRuleDetector(tmp_path)
    ev = Event(source="suricata.eve", kind="alert")
    titles = {a.title for a in det.detect([ev])}
    assert "C" in titles  # all of sel* -> both true
    assert "D" in titles  # 1 of them -> kind==alert satisfies s2


def test_malformed_rule_is_skipped_not_fatal(tmp_path):
    _write(tmp_path, "good.yml", "title: G\ndetection:\n  sel: { kind: flow }\n  condition: sel\n")
    _write(tmp_path, "bad.yml", "title: B\nno_detection_here: true\n")
    det = SigmaRuleDetector(tmp_path)
    assert [r.title for r in det.rules] == ["G"]


def test_bundled_rules_load():
    det = SigmaRuleDetector(Path("rules"))
    assert len(det.rules) >= 2


def test_malformed_condition_skipped_at_load(tmp_path):
    # A truncated aggregation ("1 of") must be rejected at load, not blow up per
    # event (which would silently disable the whole detector).
    _write(tmp_path, "ok.yml", "title: OK\ndetection:\n  sel: { kind: flow }\n  condition: sel\n")
    _write(tmp_path, "bad.yml",
           "title: BAD\ndetection:\n  sel: { kind: flow }\n  condition: 1 of\n")
    det = SigmaRuleDetector(tmp_path)
    assert [r.title for r in det.rules] == ["OK"]
    # And the good rule still evaluates without raising.
    assert len(list(det.detect([Event(source="s", kind="flow")]))) == 1
