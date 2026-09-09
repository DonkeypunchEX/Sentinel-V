"""Purple-team validation: prove detections fire against known attacks.

This is the line between "I wrote a detector" and "I proved it catches the
attack" (docs/PLAYBOOKS.md). The harness replays ATT&CK-tagged attack *samples*
through the real ingest→detect→correlate pipeline and asserts the expected
Alert/Incident fires. Each scenario references the Atomic Red Team test it
mirrors so the coverage map is legible.

Scope note (no theater): this replays captured/authored telemetry samples; it
does not execute live attacks. The natural extension is to run the referenced
Atomic Red Team atomics on an isolated lab host and feed the resulting telemetry
in through the collectors — the assertions here are already written against the
pipeline, so that path reuses them.
"""
from __future__ import annotations
