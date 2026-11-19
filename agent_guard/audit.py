"""Append-only JSONL audit log. Secrets are redacted before writing; logging never raises (a broken log must not
open a gate or crash an agent)."""
from __future__ import annotations

import datetime as _dt
import json
import os
from pathlib import Path
from typing import Optional

from .secrets import redact
from .session import default_state_dir
from .types import Decision


def log_path() -> Path:
    env = os.environ.get("AGENT_GUARD_LOG")
    return Path(env) if env else default_state_dir() / "audit.jsonl"


def log_decision(decision: Decision, session_id: str = "", summary: str = "", path: Optional[Path] = None) -> None:
    row = {
        "at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "session": session_id,
        "agent": decision.agent,
        "tool": decision.tool,
        "decision": "allow" if decision.allow else "deny",
        "rules": decision.rules,
        "summary": redact(summary)[:300],
    }
    try:
        p = Path(path) if path else log_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception:
        pass
