"""Per-session taint state. Hooks run as separate processes, so state is a small JSON file per session id.

Taint is the deterministic core of the exfiltration defence: once a session has read untrusted text (a web page,
an inbound e-mail), outbound actions are held to the policy allowlist and may not name any destination that the
untrusted text itself supplied. No model has to notice the attack for the block to hold.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .injection import CleanResult, clean_untrusted, extract_destinations


@dataclass
class Session:
    session_id: str = "ephemeral"
    tainted: bool = False
    sources: List[Dict] = field(default_factory=list)
    attacker_emails: List[str] = field(default_factory=list)
    attacker_hosts: List[str] = field(default_factory=list)
    outbound_count: int = 0
    reply_to: str = ""  # the one address a reply may go to (the thread's own sender), set by trusted code

    def ingest(self, text: str, source: str = "untrusted") -> CleanResult:
        """Record outside text entering the agent's context. Returns the cleaned text and injection flags."""
        res = clean_untrusted(text)
        self.tainted = True
        dest = extract_destinations(text or "")
        self.attacker_emails = sorted(set(self.attacker_emails) | dest.emails)
        self.attacker_hosts = sorted(set(self.attacker_hosts) | dest.hosts)
        self.sources.append({"source": source, "flags": res.flags, "hidden": res.hidden_content})
        self.sources = self.sources[-50:]
        return res

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict) -> "Session":
        known = {k: d[k] for k in cls.__dataclass_fields__ if k in d}
        return cls(**known)


def default_state_dir() -> Path:
    env = os.environ.get("AGENT_GUARD_STATE")
    return Path(env) if env else Path(tempfile.gettempdir()) / "agent-guard"


def _safe_id(session_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", session_id or "default")[:80] or "default"


class SessionStore:
    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root) if root else default_state_dir()

    def _path(self, session_id: str) -> Path:
        return self.root / "sessions" / f"{_safe_id(session_id)}.json"

    def load(self, session_id: str) -> Session:
        p = self._path(session_id)
        if not p.exists():
            return Session(session_id)
        try:
            return Session.from_dict(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            # An unreadable state file is treated as tainted: fail closed, never open.
            return Session(session_id, tainted=True, sources=[{"source": "corrupt-state", "flags": [], "hidden": False}])

    def save(self, session: Session) -> None:
        p = self._path(session.session_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(session.to_dict()), encoding="utf-8")
        os.replace(tmp, p)
