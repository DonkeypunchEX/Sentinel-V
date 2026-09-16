"""Regression tests for Windows lifecycle and event-collection scripts."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _script_process_pattern(script_name: str) -> str:
    script = (ROOT / "scripts" / script_name).read_text(encoding="utf-8")
    match = re.search(r"-match '([^']+)'", script)
    assert match, f"{script_name} must define a process detection regex"
    return match.group(1)


def test_process_detection_matches_quoted_windows_invocation() -> None:
    invocation = (
        r'"C:\Users\runner\AppData\Local\Programs\Python\Scripts\sentinel-v.exe" '
        "start --config config\\sentinel.yaml"
    )

    for script_name in ("deploy.ps1", "sentinel-ui.ps1"):
        pattern = _script_process_pattern(script_name)
        assert re.search(pattern, invocation), script_name


def test_process_detection_does_not_match_unrelated_command() -> None:
    invocation = r'"C:\Tools\sentinel-v.exe" analyze events.json'

    for script_name in ("deploy.ps1", "sentinel-ui.ps1"):
        pattern = _script_process_pattern(script_name)
        assert not re.search(pattern, invocation), script_name
