"""Heredoc firewall for multi-line shell commands.

A heredoc is the easiest way for an agent (or an injected instruction) to run code nobody reviewed: the body is
plain text to a tokenizer but live code to the shell that receives it. This module finds every heredoc and
here-string in a command, works out *what command receives it*, and refuses the unsafe shapes:

  heredoc-interpreter   body fed to python / node / bash / ssh / powershell ... (code run straight from text)
  heredoc-script-write  body written to an executable script file (`cat > run.sh <<EOF`, `tee x.py`, `dd of=`)
  heredoc-persistence   body written to a startup / scheduler / credential-trust file (.bashrc, crontab, authorized_keys)
  heredoc-unterminated  no closing delimiter: the rest of the command is swallowed and cannot be reviewed

Safe shapes pass: `git commit -m "$(cat <<'EOF' ... EOF)"`, `cat > notes.md <<'EOF'`, here-strings to grep.
A body fed to a database client is not refused; it is handed back so the SQL firewall can judge it, and the
`$(...)` / backtick commands inside an *unquoted* heredoc body (which the shell would run) are handed back so
the shell firewall can judge those too. Everything else about the command comes back as `residual` with the
heredoc bodies removed, so a commit message that merely mentions `rm -rf` is not mistaken for a command.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .types import Finding

_INTERP = re.compile(
    r"^(?:python[0-9.]*|pythonw|py|pypy[0-9.]*|ipython[0-9.]*|node|nodejs|deno|bun|npx|bunx|perl|ruby|php|lua|rscript|"
    r"bash|sh|zsh|dash|ksh|csh|tcsh|fish|powershell|pwsh|cmd|osascript|ssh|expect|tclsh|julia|groovy|jshell)$"
)
_SHELLISH = re.compile(r"^(?:bash|sh|zsh|dash|ksh|csh|fish|ssh|eval|powershell|pwsh|cmd|sudo|su|doas)$")
_DB = re.compile(r"^(?:psql|mysql|mariadb|sqlite3?|sqlcmd|duckdb|clickhouse-client|usql|mongosh|cockroach|redis-cli)$")
_WRAPPERS = {"sudo", "doas", "env", "time", "nohup", "exec", "command", "nice", "stdbuf", "timeout", "xargs", "setsid",
             "winpty", "ionice", "chroot", "builtin"}
_RUNNERS = {"uv", "poetry", "pipenv", "conda", "pdm", "hatch", "rye", "pipx"}

_SPLIT = re.compile(r"&&|\|\||;|(?<![>&|])&(?![&>])")
_PIPE = re.compile(r"(?<![|>])\|(?!\|)")
_SCRIPT_EXT = r"(?:py|pyw|sh|bash|zsh|ps1|bat|cmd|js|mjs|rb|pl|php|lua|vbs|command)"
_REDIRECT_TARGET = (r"""(?:\d?>>?\|?|&>>?|\btee\b(?:\s+-[a-zA-Z]+)*|\bof=)\s*""")
_SCRIPT_WRITE = re.compile(
    _REDIRECT_TARGET + r"""(?:"[^"]*\.""" + _SCRIPT_EXT + r"""\b"|'[^']*\.""" + _SCRIPT_EXT + r"""\b'|[^\s"'|;&<>()]+\."""
    + _SCRIPT_EXT + r"""(?=[\s|;&)<>]|$))""", re.I)
_PERSIST_WRITE = re.compile(
    _REDIRECT_TARGET + r"""["']?[^\s"'|;&<>()]*(?:\.bashrc|\.zshrc|\.profile|\.bash_profile|\.bash_login|\.zprofile|authorized_keys|"""
    r"""/etc/cron[^\s]*|/etc/systemd[^\s]*|/etc/profile[^\s]*|/etc/rc\.local|sudoers[^\s]*|\.config/autostart[^\s]*|"""
    r"""/etc/init\.d/[^\s]*|\.ssh/config|LaunchAgents/[^\s]*|Startup/[^\s]*)""", re.I)
_CRONTAB = re.compile(r"(?:^|[\s;&|(])crontab(?:\s+-(?!l\b)\S*|\s+[^\s-]\S*|\s*$)", re.I)
_HEREDOC = re.compile(r"""<<(<)?(-)?[ \t]*(?:(['"])([^'"\n]+)\3|\\?([A-Za-z_]\w*))?""")
_SUBST_IN_BODY = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")


@dataclass
class HeredocReport:
    findings: List[Finding] = field(default_factory=list)
    residual: str = ""
    sql_bodies: List[str] = field(default_factory=list)
    count: int = 0


def _canon(word: str) -> str:
    w = word.strip("\"'").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return w[:-4] if w.endswith(".exe") else w


def _words(element: str) -> List[str]:
    return re.findall(r"""(?:[^\s"']|"[^"]*"|'[^']*')+""", element)


def command_word(element: str) -> str:
    """The program an element runs: skips VAR=x, sudo/env/time/timeout/xargs and `uv run`-style runners."""
    ws = _words(element)
    i = 0
    while i < len(ws):
        w = ws[i]
        base = _canon(w)
        if re.match(r"^\w+=", w):
            i += 1
        elif base in _WRAPPERS:
            i += 1
            while i < len(ws) and (ws[i].startswith("-") or re.match(r"^\w+=", ws[i]) or
                                   (base in ("timeout", "nice") and re.match(r"^[0-9.]+[smhd]?$", ws[i]))):
                i += 1
        elif base in _RUNNERS and i + 1 < len(ws) and _canon(ws[i + 1]) == "run":
            i += 2
            while i < len(ws) and ws[i].startswith("-"):
                i += 1
        elif w in ("{", "!", "do", "then", "else", "("):
            i += 1
        else:
            return base
    return ""


def _scan(line: str, q: Optional[str]) -> Tuple[List[Tuple[int, str, Optional[int]]], Optional[str], Optional[int]]:
    """Heredoc operators in one line -> [(index, kind, anchor)], quote still open at line end, where it opened.
    kind: plain (outside quotes) | subst (inside "...$( " where the shell runs it; anchor = `$(` index) |
    quoted (inside a string; anchor = quote start, -1 when the quote began on an earlier line)."""
    ops, i, opened, sub, n = [], 0, (-1 if q else None), None, len(line)
    while i < n:
        c = line[i]
        if q:
            if q == '"' and c == "\\":
                i += 2
                continue
            if q == '"' and (line.startswith("$(", i) or c == "`"):
                sub = i
                i += 2 if c == "$" else 1
                continue
            if c == q and sub is None:
                q, opened = None, None
                i += 1
                continue
            if c == ")" and sub is not None and q == '"':
                sub = None
        else:
            if c == "\\":
                i += 2
                continue
            if c in "'\"":
                q, opened, sub = c, i, None
                i += 1
                continue
            if c == "#" and (i == 0 or line[i - 1] in " \t;"):
                break
        if line.startswith("<<", i):
            if q is None:
                ops.append((i, "plain", None))
            elif sub is not None:
                ops.append((i, "subst", sub))
            else:
                ops.append((i, "quoted", opened))
            i += 3 if line.startswith("<<<", i) else 2
            continue
        i += 1
    return ops, q, opened


def _segment(line: str, pos: int) -> Tuple[int, int]:
    start = 0
    for m in _SPLIT.finditer(line):
        if m.start() >= pos:
            return start, m.start()
        start = m.end()
    return start, len(line)


def _flows(text: str, at: int) -> List[str]:
    """Pipeline elements from the one holding index `at` onward: the command the heredoc feeds, and its pipe targets."""
    elems, pos, idx = [], 0, None
    for m in list(_PIPE.finditer(text)) + [None]:
        end = m.start() if m else len(text)
        if idx is None and pos <= at <= end:
            idx = len(elems)
        elems.append(text[pos:end])
        pos = m.end() if m else pos
    return elems[idx or 0:]


def _plain_text(line: str, pos: int) -> Tuple[str, int]:
    start, end = _segment(line, pos)
    seg = line[start:end]
    lp = pos - start
    head = re.split(r"\$\(|`|\(", seg[:lp])[-1]
    return head + seg[lp:], len(head)


def _judge(flows: List[str], findings: List[Finding], sql_bodies_sink: List[bool]) -> None:
    for e in flows:
        w = command_word(e)
        if _INTERP.match(w):
            findings.append(Finding("heredoc-interpreter",
                                    f"text fed to `{w}` through a heredoc runs as unreviewed code; write the script to a "
                                    "reviewed file and run that", "heredoc"))
            return
    if any(_SCRIPT_WRITE.search(e) for e in flows):
        findings.append(Finding("heredoc-script-write",
                                "heredoc body written to an executable script file; create scripts with a file tool", "heredoc"))
    if any(_PERSIST_WRITE.search(e) or _CRONTAB.search(e) for e in flows):
        findings.append(Finding("heredoc-persistence",
                                "heredoc body written to a startup, scheduler or key-trust file", "heredoc"))
    sql_bodies_sink.append(any(_DB.match(command_word(e)) for e in flows))


def analyze(command: str) -> HeredocReport:
    rep = HeredocReport()
    lines = (command or "").replace("\r\n", "\n").split("\n")
    # a backslash-continued line is one command line
    merged: List[str] = []
    for ln in lines:
        if merged and merged[-1].endswith("\\") and not merged[-1].endswith("\\\\"):
            merged[-1] = merged[-1][:-1] + " " + ln
        else:
            merged.append(ln)
    lines = merged
    kept: List[str] = []
    extra: List[str] = []
    i, q, carry_shell, carry_inner = 0, None, False, ""
    while i < len(lines):
        line = lines[i]
        ops, q_next, opened = _scan(line, q)
        pending: List[Tuple[str, bool, bool, bool]] = []  # delim, strip tabs, quoted delim, goes to a db client
        for pos, kind, anchor in ops:
            m = _HEREDOC.match(line, pos)
            here_string = bool(m.group(1))
            delim = m.group(4) or m.group(5)
            if not (here_string or delim):
                continue  # `<<` that starts no heredoc (arithmetic, a bare operator)
            if kind == "quoted":
                inner = line[:pos] if anchor == -1 else line[anchor + 1:pos]
                to_shell = carry_shell if anchor == -1 else bool(_SHELLISH.match(command_word(_plain_text(line, anchor)[0])))
                if anchor == -1 and carry_inner:
                    inner = carry_inner + " " + inner
                last = re.split(r"&&|\|\||;|\n|\|(?!\|)|\$\(|`|\(", inner)[-1]
                if to_shell and _INTERP.match(command_word(last)):
                    rep.findings.append(Finding("heredoc-interpreter",
                                                "an interpreter heredoc hidden inside a quoted shell string", "heredoc"))
                continue
            if kind == "subst":
                text, at = line[anchor + (2 if line.startswith("$(", anchor) else 1):], 0
                at = pos - (anchor + (2 if line.startswith("$(", anchor) else 1))
            else:
                text, at = _plain_text(line, pos)
            flows = _flows(text, at)
            sink: List[bool] = []
            _judge(flows, rep.findings, sink)
            rep.count += 1
            if here_string:
                word = line[m.end():].lstrip(" \t")
                lit = re.match(r"""(?:"([^"]*)"|'([^']*)'|(\S+))""", word)
                if lit and sink and sink[0]:
                    rep.sql_bodies.append(next(g for g in lit.groups() if g is not None))
            elif delim:
                pending.append((delim, bool(m.group(2)), bool(m.group(3)), bool(sink and sink[0])))
        if q_next and opened is not None and opened != -1:
            carry_shell = bool(_SHELLISH.match(command_word(_plain_text(line, opened)[0])))
            carry_inner = ""
        elif q_next and opened == -1:
            carry_inner = (carry_inner + " " + line).strip()
        else:
            carry_inner = ""
        q = q_next
        kept.append(line)
        i += 1
        for delim, strip, quoted, to_db in pending:
            close = next((k for k in range(i, len(lines))
                          if (lines[k].strip() if strip else lines[k].rstrip("\r")) == delim), None)
            if close is None:
                rep.findings.append(Finding("heredoc-unterminated",
                                            f"heredoc `{delim}` never closes; the rest of the command is unreviewable", "heredoc"))
                body, i = lines[i:], len(lines)
            else:
                body, i = lines[i:close], close + 1
            text = "\n".join(body)
            if to_db:
                rep.sql_bodies.append(text)
            if not quoted:
                for sm in _SUBST_IN_BODY.finditer(text):
                    extra.append(sm.group(1) or sm.group(2) or "")
    rep.residual = "\n".join(kept + extra)
    return rep
