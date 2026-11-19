"""Per-agent policy: tool allowlists, path roots, egress allowlists, SQL mode. Plain JSON, no code in it."""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from . import paths

SQL_MODES = ("read_only", "scoped_write", "deny")
EGRESS_MODES = ("taint-aware", "strict")

DEFAULT_UNTRUSTED_TOOLS = ["WebFetch", "WebSearch", "web_fetch", "web_search", "browse", "browser_*", "read_email",
                           "get_message", "get_thread", "search_email*", "fetch_url", "http_get", "read_webpage"]
_ROLE_DEFAULTS: Dict[str, List[str]] = {
    "shell": ["Bash", "bash", "shell", "run_command", "execute_command", "terminal", "PowerShell", "powershell"],
    "read": ["Read", "Glob", "Grep", "LS", "read_file", "list_dir", "list_files", "view_file", "NotebookRead"],
    "write": ["Write", "Edit", "MultiEdit", "NotebookEdit", "write_file", "create_file", "edit_file", "delete_file",
              "move_file", "apply_patch"],
    "sql": ["*sql*", "db_query", "run_query", "query_database", "database_*"],
    "url": ["WebFetch", "web_fetch", "fetch_url", "http_get", "http_request", "browse", "open_url", "browser_navigate"],
}
_OUTBOUND = re.compile(r"(send|reply|forward|post|publish|notify|tweet|webhook|upload|sms|message|email|mail)", re.I)
_INBOUND = re.compile(r"^(read|get|list|search|fetch|find|view|count)[_-]?", re.I)


@dataclass
class AgentPolicy:
    name: str = "default"
    allowed_tools: Optional[List[str]] = None  # None = any tool (not recommended); [] = no tools
    denied_tools: List[str] = field(default_factory=list)
    read_roots: List[str] = field(default_factory=list)
    write_roots: List[str] = field(default_factory=list)
    allowed_hosts: List[str] = field(default_factory=list)
    allowed_recipients: List[str] = field(default_factory=list)
    sql_mode: str = "scoped_write"
    allow_env_refs: List[str] = field(default_factory=list)
    egress: str = "taint-aware"
    max_outbound_per_session: Optional[int] = None


@dataclass
class Policy:
    home: str = "/home/agent"
    workspace: str = "/workspace"
    untrusted_tools: List[str] = field(default_factory=lambda: list(DEFAULT_UNTRUSTED_TOOLS))
    tool_roles: Dict[str, List[str]] = field(default_factory=dict)
    defaults: Dict = field(default_factory=dict)
    agents: Dict[str, Dict] = field(default_factory=dict)

    # ------------------------------------------------------------------ construction
    @classmethod
    def from_dict(cls, d: Dict) -> "Policy":
        p = cls(home=d.get("home", "/home/agent"), workspace=d.get("workspace", "/workspace"),
                untrusted_tools=list(d.get("untrusted_tools", DEFAULT_UNTRUSTED_TOOLS)),
                tool_roles=dict(d.get("tool_roles", {})), defaults=dict(d.get("defaults", {})),
                agents=dict(d.get("agents", {})))
        for name in list(p.agents) + [""]:
            p.for_agent(name or "default")  # validate eagerly: a bad policy must fail at load, not at 3 a.m.
        return p

    @classmethod
    def load(cls, path) -> "Policy":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def for_agent(self, name: str) -> AgentPolicy:
        merged = dict(self.defaults)
        merged.update(self.agents.get(name, {}))
        known = {f.name for f in fields(AgentPolicy)}
        unknown = set(merged) - known
        if unknown:
            raise ValueError(f"unknown policy keys for agent {name!r}: {sorted(unknown)}")
        ap = AgentPolicy(name=name, **merged)
        if ap.sql_mode not in SQL_MODES:
            raise ValueError(f"sql_mode must be one of {SQL_MODES}")
        if ap.egress not in EGRESS_MODES:
            raise ValueError(f"egress must be one of {EGRESS_MODES}")
        return ap

    # ------------------------------------------------------------------ classification
    def roles(self, tool: str) -> Set[str]:
        out: Set[str] = set()
        for role, pats in _ROLE_DEFAULTS.items():
            if _matches(tool, pats + self.tool_roles.get(role, [])):
                out.add(role)
        if _matches(tool, self.tool_roles.get("message", [])) or (_OUTBOUND.search(tool) and not _INBOUND.match(tool)
                                                                  and "read" not in out and "url" not in out):
            out.add("message")
        return out

    def is_untrusted_source(self, tool: str) -> bool:
        return _matches(tool, self.untrusted_tools)

    def normalized_roots(self, roots: Iterable[str]) -> List[str]:
        return [n for n in (paths.normalize(r, self.workspace, self.home) for r in roots) if n]


def _matches(name: str, patterns: Iterable[str]) -> bool:
    low = name.lower()
    return any(fnmatch.fnmatchcase(low, p.lower()) for p in patterns)


def host_allowed(host: str, allowed: Iterable[str]) -> bool:
    h = (host or "").lower().rstrip(".")
    for a in allowed:
        a = a.lower()
        if a.startswith("*."):
            if h == a[2:] or h.endswith(a[1:]):
                return True
        elif h == a:
            return True
    return False


def recipient_allowed(addr: str, allowed: Iterable[str]) -> bool:
    a = (addr or "").lower()
    for pat in allowed:
        pat = pat.lower()
        if pat == a or (pat.startswith("*@") and a.endswith(pat[1:])):
            return True
    return False
