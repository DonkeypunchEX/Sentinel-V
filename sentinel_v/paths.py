"""Filesystem locations for Sentinel-V runtime state.

Resolved independent of the current working directory, so behavior (where
the honeypot log lands, where the running system's status file is written
and read from) does not depend on the directory ``sentinel-v`` happens to
be invoked from.
"""

import os
from pathlib import Path


def state_dir() -> Path:
    """Directory for Sentinel-V runtime state (status file, honeypot log, ...).

    Override with the ``SENTINEL_V_STATE_DIR`` environment variable.
    Otherwise resolves to a per-user directory that stays the same
    regardless of the invoking process's working directory.
    """
    override = os.environ.get("SENTINEL_V_STATE_DIR")
    if override:
        path = Path(override)
    elif os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        path = Path(base) / "Sentinel-V"
    else:
        base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
        path = Path(base) / "sentinel-v"

    path.mkdir(parents=True, exist_ok=True)
    return path


def status_file() -> Path:
    """Path to the JSON heartbeat file a running daemon writes.

    ``sentinel-v status`` reads this from a separate process instead of
    spinning up a throwaway ``SentinelVSystem`` and reporting its empty
    metrics as if they were live.
    """
    return state_dir() / "status.json"


def main_log_file() -> Path:
    """Path to the main Sentinel-V application log."""
    return state_dir() / "sentinel.log"


def honeypot_log_file() -> Path:
    """Path to the standalone SSH honeypot's connection log."""
    return state_dir() / "honeypot.log"
