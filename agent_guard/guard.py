"""The orchestrator: one `Guard.check(...)` call runs every deterministic rule against a proposed tool call."""
from __future__ import annotations

import fnmatch
import os
import re
import shlex
from typing import Any, Dict, List, Optional

from . import exfil, heredoc, normalize, paths
from .policy import AgentPolicy, Policy
from .secrets import contains_env_secret, find_secrets, walk_strings
from .session import Session
from .shellguard import ShellContext, check_shell, effective, flatten
from .sqlguard import check_sql
from .types import Decision, Finding

_DB_CLIENT = re.compile(r"^(?:psql|mysql|mariadb|sqlite3?|sqlcmd|duckdb|clickhouse-client|usql|cockroach)$")
_PATH_KEYS = ("file_path", "path", "paths", "filename", "notebook_path", "dir", "directory", "file", "files", "target",
              "source", "destination", "dest", "src", "old_path", "new_path")
_SQL_KEYS = ("sql", "query", "statement", "statements", "command")
_MAX_SQL_FILE = 1_000_000


def _glob(name: str, patterns: List[str]) -> bool:
    return any(fnmatch.fnmatchcase(name.lower(), p.lower()) for p in patterns)


def _str_list(v: Any) -> List[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, (list, tuple)):
        return [x for x in v if isinstance(x, str)]
    return []


class Guard:
    def __init__(self, policy: Optional[Policy] = None) -> None:
        self.policy = policy or Policy()

    # ----------------------------------------------------------------------------------------- public
    def check(self, agent: str, tool: str, tool_input: Optional[Dict[str, Any]] = None,
              session: Optional[Session] = None, commit: bool = True) -> Decision:
        """Decide one proposed tool call. `commit=True` records its effects on the session (outbound count, taint)."""
        tool_input = tool_input if isinstance(tool_input, dict) else {}
        session = session if session is not None else Session()
        ap = self.policy.for_agent(agent)
        findings: List[Finding] = []

        if _glob(tool, ap.denied_tools):
            findings.append(Finding("tool-denied", f"`{tool}` is denied for agent `{agent}`", "tool"))
        elif ap.allowed_tools is not None and not _glob(tool, ap.allowed_tools):
            findings.append(Finding("tool-not-allowed", f"`{tool}` is not on agent `{agent}`'s tool allowlist", "tool"))
        if findings:
            return Decision(False, findings, agent, tool)

        roles = self.policy.roles(tool)
        # Judge the meaning, not the spelling: refuse look-alike spellings that folding would hide, then fold.
        findings += normalize.spelling_findings(tool_input, roles, _PATH_KEYS)
        tool_input = normalize.fold_input(tool_input)
        cwd = str(tool_input.get("cwd") or self.policy.workspace)
        write_roots = self.policy.normalized_roots(ap.write_roots)
        read_roots = self.policy.normalized_roots(ap.read_roots)
        ctx = ShellContext(cwd=cwd, home=self.policy.home, write_roots=write_roots, allow_env_refs=ap.allow_env_refs)

        findings += self._paths(tool_input, roles, ap, cwd, read_roots, write_roots)
        if "shell" in roles:
            findings += self._shell(tool_input, ap, session, ctx)
        if "sql" in roles and "shell" not in roles:
            for k in _SQL_KEYS:
                for text in _str_list(tool_input.get(k)):
                    findings += check_sql(text, ap.sql_mode)
        if "message" in roles:
            findings += exfil.message_egress(tool_input, ap, session)
        if "url" in roles and "message" not in roles:
            for k in ("url", "uri", "href"):
                if isinstance(tool_input.get(k), str):
                    findings += exfil.url_egress(tool_input[k], str(tool_input.get("method", "GET")), ap, session)
        if roles & {"shell", "message", "url"}:
            findings += self._secrets(tool_input)
        if roles & {"shell", "sql", "message", "url"}:
            findings += self._decoded(tool_input, roles, ap, session, ctx)

        findings = _dedupe(findings)
        decision = Decision(not findings, findings, agent, tool)
        if commit and decision.allow:
            if "message" in roles:
                session.outbound_count += 1
            if self.policy.is_untrusted_source(tool):
                session.tainted = True  # its result is about to enter the context
        return decision

    # ---------------------------------------------------------------------------------------- stages
    def _paths(self, tool_input, roles, ap: AgentPolicy, cwd, read_roots, write_roots) -> List[Finding]:
        out: List[Finding] = []
        home = self.policy.home
        for k in _PATH_KEYS:
            for raw in _str_list(tool_input.get(k)):
                if paths.is_credential_path(raw):
                    out.append(Finding("path-credential", f"`{raw}` is a credential file", "path"))
                    continue
                n = paths.normalize(raw, cwd, home)
                if n is None:
                    if roles & {"read", "write"}:
                        out.append(Finding("path-unresolvable", f"`{raw}` holds an unresolved variable", "path"))
                    continue
                if "write" in roles:
                    if paths.is_protected_path(n) and not paths.under(n, write_roots):
                        out.append(Finding("path-protected", f"`{raw}` is a protected system path", "path"))
                    elif write_roots and not paths.under(n, write_roots):
                        out.append(Finding("path-outside-write-roots", f"`{raw}` is outside the write roots", "path"))
                elif "read" in roles and read_roots and not paths.under(n, read_roots + write_roots):
                    out.append(Finding("path-outside-read-roots", f"`{raw}` is outside the read roots", "path"))
        return out

    def _shell(self, tool_input, ap: AgentPolicy, session: Session, ctx: ShellContext) -> List[Finding]:
        command = ""
        for k in ("command", "cmd", "script"):
            if isinstance(tool_input.get(k), str):
                command = tool_input[k]
                break
        out: List[Finding] = []
        rep = heredoc.analyze(command)
        out += rep.findings
        for body in rep.sql_bodies:
            out += check_sql(body, ap.sql_mode)
        out += check_shell(rep.residual, ctx)
        segments, _ = flatten(rep.residual)
        for seg in segments:
            e = effective(seg.words)
            if e and _DB_CLIENT.match(e.cmd):
                out += check_sql(" ".join(e.args), ap.sql_mode)
                out += self._sql_files(e.args, ap)
        out += exfil.shell_egress(segments, ap, session)
        return out

    def _sql_files(self, args: List[str], ap: AgentPolicy) -> List[Finding]:
        out: List[Finding] = []
        for a in args:
            if a.lower().endswith(".sql") and os.path.isfile(a) and os.path.getsize(a) <= _MAX_SQL_FILE:
                try:
                    with open(a, encoding="utf-8", errors="replace") as f:
                        out += check_sql(f.read(), ap.sql_mode)
                except OSError:
                    out.append(Finding("sql-file-unreadable", f"`{a}` cannot be read for review", "sql"))
        return out

    def _secrets(self, tool_input) -> List[Finding]:
        out: List[Finding] = []
        for s in walk_strings(tool_input):
            names = find_secrets(s)
            if names:
                out.append(Finding("secret-in-payload", f"payload carries a secret ({', '.join(names)})", "secret"))
            elif contains_env_secret(s):
                out.append(Finding("secret-in-payload", "payload carries the value of a secret environment variable", "secret"))
        return out


    def _decoded(self, tool_input, roles, ap: AgentPolicy, session: Session, ctx: ShellContext) -> List[Finding]:
        """Base64 hidden anywhere in the call is decoded and judged by the same rules as plain text."""
        inner: List[Finding] = []
        for _, s in normalize.walk(tool_input):
            for text in normalize.decoded_payloads(s):
                text = normalize.fold(text)
                if find_secrets(text):
                    inner.append(Finding("secret-in-payload", "secret", "secret"))
                if roles & {"shell", "sql"} and normalize.looks_like_sql(text):
                    inner += check_sql(text, ap.sql_mode)
                if "shell" in roles:
                    inner += self._shell({"command": text}, ap, session, ctx)
                    inner += check_shell("python3 -c " + shlex.quote(text), ctx)  # decoded inline code
        rules = list(dict.fromkeys(f.rule for f in inner if f.rule not in ("sql-unterminated", "heredoc-unterminated")))
        if not rules:
            return []
        return [Finding("evasion-base64-payload", f"Base64 hides a blocked payload ({', '.join(rules)})", "evasion")]


def _dedupe(findings: List[Finding]) -> List[Finding]:
    """One finding per rule id, in first-seen order; distinct reasons for the same rule are joined."""
    order: Dict[str, Finding] = {}
    for f in findings:
        first = order.get(f.rule)
        if first is None:
            order[f.rule] = f
        elif f.reason not in first.reason.split("; "):
            order[f.rule] = Finding(f.rule, first.reason + "; " + f.reason, first.category)
    return list(order.values())
