"""Destructive-SQL firewall. Deterministic: tokenises the statement text and judges it, never asks a model.

Blocks DROP / TRUNCATE, DELETE and UPDATE without a real WHERE (missing, or a tautology such as `1=1`, `'a'='a'`,
`"a"="a"`, `2>1`, `OR true`), stacked
statements that smuggle one of those behind a harmless first statement, and a short list of server-side escape
hatches (file read/write, program execution, privilege grants, dynamic SQL).

SQL dialects disagree about comments and string escapes, and an attacker picks the reading that hides the payload.
So the text is sanitised under every combination of the ambiguous rules (`--` comment or not, backslash escapes or
not, nested block comments or not) and the verdict is the union: if any reading is destructive, the call is blocked.
"""
from __future__ import annotations

import itertools
import operator
import re
from typing import Iterable, List, Optional, Tuple

from .types import Finding

_TOKEN = re.compile(
    r"'x'|\"q\"|\$\d+|:[A-Za-z_]\w*|%s|\?|@\w+|[A-Za-z_][A-Za-z0-9_$]*|\d+(?:\.\d+)?|<>|!=|>=|<=|=|[();,*.<>+\-/%]|\S"
)

ESCAPE_HATCHES = {
    "grant": "privilege grant", "revoke": "privilege revoke", "xp_cmdshell": "OS command from SQL",
    "sp_configure": "server reconfiguration", "load_file": "server file read", "pg_read_file": "server file read",
    "pg_read_binary_file": "server file read", "pg_ls_dir": "server directory listing", "lo_import": "server file read",
    "lo_export": "server file write", "outfile": "server file write", "dumpfile": "server file write",
    "shutdown": "server shutdown",
}
_NUMBER = re.compile(r"^\d+(?:\.\d+)?$")
_COMPARE = {"=": operator.eq, "<>": operator.ne, "!=": operator.ne, ">": operator.gt, "<": operator.lt,
            ">=": operator.ge, "<=": operator.le}
READ_ONLY_FIRST ={"SELECT", "WITH", "SHOW", "EXPLAIN", "DESCRIBE", "DESC", "VALUES", "PRAGMA", "TABLE"}


def _sanitise(sql: str, backslash: bool, dashes: bool, nested: bool) -> Optional[str]:
    """Comments -> a space, quoted text -> a placeholder. None when a literal or comment never closes."""
    out: List[str] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        two = sql[i:i + 2]
        # `--` is a comment everywhere when followed by whitespace; MySQL alone treats `--x` as arithmetic
        if two == "--" and (dashes or sql[i + 2:i + 3] in ("", " ", "\t", "\n", "\r")):
            j = sql.find("\n", i)
            i = n if j < 0 else j
            out.append(" ")
        elif two == "/*":
            if sql[i + 2:i + 3] == "!":  # MySQL executable comment: its body is code
                out.append(" ")
                i += 3
                continue
            depth, j = 1, i + 2
            while j < n and depth:
                if sql.startswith("*/", j):
                    depth -= 1
                    j += 2
                elif nested and sql.startswith("/*", j):
                    depth += 1
                    j += 2
                else:
                    j += 1
            if depth:
                return None
            i = j
            out.append(" ")
        elif c in "'\"`":
            j = i + 1
            while True:
                if j >= n:
                    return None
                if backslash and sql[j] == "\\" and c != "`":
                    j += 2
                    continue
                if sql[j] == c:
                    if sql[j + 1:j + 2] == c:  # doubled quote is an escaped quote
                        j += 2
                        continue
                    break
                j += 1
            out.append("'x'" if c == "'" else '"q"')
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _split_statements(text: str) -> List[List[str]]:
    stmts, cur = [], []
    for tok in _TOKEN.findall(text):
        if tok == ";":
            if cur:
                stmts.append(cur)
            cur = []
        else:
            cur.append(tok)
    if cur:
        stmts.append(cur)
    return stmts


def _depths(tokens: List[str]) -> List[int]:
    d, out = 0, []
    for t in tokens:
        if t == ")":
            d = max(0, d - 1)
        out.append(d)
        if t == "(":
            d += 1
    return out


def _is_tautology(disjunct: List[str]) -> bool:
    toks = [t.upper() for t in disjunct]
    if not toks:
        return False
    if toks in (["TRUE"], ["NOT", "FALSE"], ["NOT", "0"]):
        return True
    if len(toks) == 1 and _NUMBER.match(toks[0]):
        return float(toks[0]) != 0  # `WHERE 1`, `WHERE 7`: any non-zero constant is true
    if len(toks) == 3 and _NUMBER.match(toks[0]) and _NUMBER.match(toks[2]) and toks[1] in _COMPARE:
        return _COMPARE[toks[1]](float(toks[0]), float(toks[2]))  # `2>1`, `1<>2`: two constants compared
    if len(toks) == 3 and toks[1] == "=" and toks[0] == toks[2] and toks[0] not in ("?", "%S"):
        return not toks[0].startswith((":", "$", "@"))  # `1=1`, `x=x`, `'x'='x'`; a bind parameter is not one
    if len(toks) == 4 and toks[1:] == ["IS", "NOT", "NULL"]:
        return True  # `WHERE id IS NOT NULL` matches every row in practice
    return False


def _where_clause(tokens: List[str], depths: List[int], start: int) -> Optional[List[str]]:
    """Tokens of the WHERE that belongs to the statement at `start` (same paren depth), or None if there is none."""
    base = depths[start]
    for k in range(start + 1, len(tokens)):
        if depths[k] == base and tokens[k].upper() == "WHERE":
            clause = []
            for m in range(k + 1, len(tokens)):
                if depths[m] < base:
                    break
                if depths[m] == base and tokens[m].upper() in ("RETURNING", "ORDER", "LIMIT"):
                    break
                clause.append(tokens[m])
            return clause
    return None


def _scoped(clause: List[str], depths_base: int = 0) -> bool:
    """A WHERE is scoped when no top-level OR branch is a tautology and the clause is not empty."""
    if not clause:
        return False
    d, branches, cur = 0, [], []
    for t in clause:
        if t == "(":
            d += 1
        elif t == ")":
            d -= 1
        if d == 0 and t.upper() == "OR":
            branches.append(cur)
            cur = []
        else:
            cur.append(t)
    branches.append(cur)
    for b in branches:
        stripped = [t for t in b if t not in ("(", ")")]
        and_parts, part = [], []
        for t in stripped:
            if t.upper() == "AND":
                and_parts.append(part)
                part = []
            else:
                part.append(t)
        and_parts.append(part)
        if all(_is_tautology(p) for p in and_parts if p) and any(and_parts):
            return False
    return True


def _judge(tokens: List[str], mode: str) -> List[Finding]:
    out: List[Finding] = []
    up = [t.upper() for t in tokens]
    first = up[0] if up else ""
    depths = _depths(tokens)
    if mode == "read_only" and first not in READ_ONLY_FIRST:
        out.append(Finding("sql-write-in-read-only", f"{first or 'statement'} is not allowed for a read-only agent", "sql"))
    for i, t in enumerate(up):
        prev = up[i - 1] if i else ""
        if t == "DROP":
            out.append(Finding("sql-drop", "DROP removes schema objects", "sql"))
        elif t == "TRUNCATE":
            out.append(Finding("sql-truncate", "TRUNCATE empties a table with no WHERE", "sql"))
        elif t == "MERGE":
            out.append(Finding("sql-merge", "MERGE can delete rows without a WHERE; use scoped DELETE/UPDATE", "sql"))
        elif t in ("DELETE", "UPDATE"):
            if t == "DELETE" and prev == "ON":
                continue  # ON DELETE CASCADE
            if t == "UPDATE" and prev in ("ON", "FOR", "DO", "KEY"):
                continue  # ON UPDATE ..., SELECT ... FOR UPDATE, ON CONFLICT DO UPDATE, FOR NO KEY UPDATE
            clause = _where_clause(tokens, depths, i)
            if clause is None:
                out.append(Finding(f"sql-unscoped-{t.lower()}", f"{t} without a WHERE clause affects every row", "sql"))
            elif not _scoped(clause):
                out.append(Finding("sql-tautology-where", f"{t} with an always-true WHERE affects every row", "sql"))
        elif t.lower() in ESCAPE_HATCHES:
            out.append(Finding(f"sql-{t.lower()}", f"{ESCAPE_HATCHES[t.lower()]} is blocked", "sql"))
        elif t in ("EXEC", "EXECUTE") and prev in ("", ";", "THEN", "BEGIN") and "IMMEDIATE" in up[i:i + 2]:
            out.append(Finding("sql-dynamic-exec", "dynamic SQL hides the statement from review", "sql"))
        elif t == "COPY" and "PROGRAM" in up:
            out.append(Finding("sql-copy-program", "COPY ... PROGRAM runs an OS command", "sql"))
        elif t == "ATTACH" and mode != "read_only":
            out.append(Finding("sql-attach", "ATTACH opens another database file", "sql"))
    return out


def check_sql(sql: str, mode: str = "scoped_write") -> List[Finding]:
    """Findings for one SQL string (any number of statements). Empty list = allowed."""
    if mode == "deny":
        return [Finding("sql-denied", "this agent may not run SQL", "sql")]
    findings: dict = {}
    parsed = 0
    for backslash, dashes, nested in itertools.product((False, True), repeat=3):
        text = _sanitise(sql or "", backslash, dashes, nested)
        if text is None:
            continue
        parsed += 1
        for stmt in _split_statements(text):
            for f in _judge(stmt, mode):
                findings.setdefault(f.rule, f)
    if not parsed:
        return [Finding("sql-unterminated", "unterminated quote or comment: cannot be judged safely", "sql")]
    return list(findings.values())
