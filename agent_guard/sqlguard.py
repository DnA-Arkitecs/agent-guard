"""Destructive-SQL firewall. Deterministic: tokenises the statement text and judges it, never asks a model.

Blocks DROP / TRUNCATE, DELETE and UPDATE without a real WHERE (missing, or always true: `1=1`, `'a'='a'`, `2>1`,
`'a' LIKE 'a'`, `u.id = u.id`, `1 IN (1)`, `NULL IS NULL`, `1 BETWEEN 0 AND 2`, `OR true`, at any depth of
parentheses, plus an `OR 1=1` branch hidden inside a group that an outer AND narrows), stacked
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
from typing import Dict, Iterable, List, Optional, Tuple

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


_REFLEXIVE = {"=", ">=", "<=", "LIKE", "ILIKE", "GLOB", "<= >", "IS NOT DISTINCT FROM"}  # `X op X`: every non-null X
_IRREFLEXIVE = {"<>", "!=", "<", ">", "NOT LIKE", "NOT ILIKE", "IS DISTINCT FROM"}
_OPERATORS = ("IS NOT DISTINCT FROM", "IS DISTINCT FROM", "IS NOT", "IS", "NOT BETWEEN", "BETWEEN", "NOT IN", "IN",
              "NOT LIKE", "NOT ILIKE", "<= >", "<>", "!=", ">=", "<=", "=", ">", "<", "LIKE", "ILIKE", "GLOB")
_ARITH = {"+", "-", "*", "/", "(", ")"}
_COLUMN = re.compile(r"^[A-Z_][A-Z0-9_$]*$")
_KEYWORDS = {"NULL", "TRUE", "FALSE", "NOT", "AND", "OR", "SELECT", "EXISTS"}


def _bind(tok: str) -> bool:
    return tok in ("?", "%S") or tok.startswith((":", "$", "@"))


def _close(tokens: List[str], k: int) -> int:
    """Index of the `)` that closes the `(` at k (the last index when it never closes)."""
    d = 0
    for j in range(k, len(tokens)):
        if tokens[j] == "(":
            d += 1
        elif tokens[j] == ")":
            d -= 1
            if not d:
                return j
    return len(tokens) - 1


def _const(side: List[str]) -> Optional[float]:
    """The value of a side made only of numbers, + - * / and parentheses (`1+1`, `(2*3)`); None otherwise.
    A tiny recursive-descent reader: nothing is ever handed to eval."""
    if not side or any(not (_NUMBER.match(t) or t in _ARITH) for t in side):
        return None
    pos = [0]

    def peek() -> str:
        return side[pos[0]] if pos[0] < len(side) else ""

    def unary() -> float:
        t = peek()
        pos[0] += 1
        if t in ("-", "+"):
            v = unary()
            return -v if t == "-" else v
        if t == "(":
            v = expr()
            if peek() != ")":
                raise ValueError("unclosed")
            pos[0] += 1
            return v
        if _NUMBER.match(t):
            return float(t)
        raise ValueError("not a number")

    def term() -> float:
        v = unary()
        while peek() in ("*", "/"):
            op = peek()
            pos[0] += 1
            r = unary()
            v = v * r if op == "*" else v / r
        return v

    def expr() -> float:
        v = term()
        while peek() in ("+", "-"):
            op = peek()
            pos[0] += 1
            r = term()
            v = v + r if op == "+" else v - r
        return v

    try:
        v = expr()
    except (ValueError, ZeroDivisionError, OverflowError):
        return None
    return v if pos[0] == len(side) else None


def _literal(side: List[str]) -> bool:
    """A constant: a number expression, a quoted string or TRUE / FALSE. NULL is not a value."""
    return _const(side) is not None or side in (["'X'"], ['"Q"'], ["TRUE"], ["FALSE"])


def _column_ref(side: List[str]) -> bool:
    """`id`, `u.id`, `public.users.id`: identifiers joined by dots."""
    return bool(side) and len(side) % 2 == 1 and all(
        (bool(_COLUMN.match(t)) and t not in _KEYWORDS) if k % 2 == 0 else t == "." for k, t in enumerate(side))


def _items(group: List[str]) -> Optional[List[List[str]]]:
    """`( a , b , c )` -> [[a], [b], [c]]; None when the tokens are not exactly one parenthesised group."""
    if len(group) < 2 or group[0] != "(" or _close(group, 0) != len(group) - 1:
        return None
    items: List[List[str]] = [[]]
    d = 0
    for t in group[1:-1]:
        if t == "(":
            d += 1
        elif t == ")":
            d -= 1
        if t == "," and d == 0:
            items.append([])
        else:
            items[-1].append(t)
    return items


def _op_index(words: Tuple[str, ...]) -> Dict[str, List[Tuple[str, List[str]]]]:
    index: Dict[str, List[Tuple[str, List[str]]]] = {}
    for w in words:
        parts = w.split()
        index.setdefault(parts[0], []).append((w, parts))
    return index


_OP_INDEX = _op_index(_OPERATORS)
_AND_INDEX = _op_index(("AND",))


def _split_at(toks: List[str], index: Dict[str, List[Tuple[str, List[str]]]]
              ) -> Optional[Tuple[List[str], str, List[str]]]:
    """(left, operator, right) at the first top-level operator (multi-word operators are matched as a run of tokens);
    None when there is none. Operators are indexed by first token, so the scan is one pass."""
    d = 0
    for k, t in enumerate(toks):
        if t == "(":
            d += 1
        elif t == ")":
            d -= 1
        elif d == 0 and k and t in index:
            for w, parts in index[t]:
                if toks[k:k + len(parts)] == parts:
                    return toks[:k], w, toks[k + len(parts):]
    return None


def _truth(atom: List[str], strict: bool) -> Optional[bool]:
    """True / False when a predicate with no AND / OR / NOT at its top is the same for every row; None when it
    depends on the row. `strict=False` also counts `col IS NOT NULL` as true (see `_always`)."""
    toks = [t.upper() for t in atom]
    if toks in (["TRUE"], ["FALSE"]):
        return toks == ["TRUE"]
    c = _const(toks)
    if c is not None:
        return c != 0  # `WHERE 1`, `WHERE 7`, `WHERE 0`
    if not toks or any(_bind(t) for t in toks):
        return None  # a bind parameter's value is not in the text
    m = _split_at(toks, _OP_INDEX)
    if not m:
        return None
    left, op, right = m
    if not left or not right:
        return None
    if op in ("IS", "IS NOT"):
        neg = op == "IS NOT"
        if right == ["NULL"]:
            if left == ["NULL"]:
                return not neg  # `NULL IS NULL`
            if _literal(left):
                return neg  # `1 IS NOT NULL`, `'a' IS NULL`
            if neg and not strict and _column_ref(left):
                return True  # `id IS NOT NULL`
            return None
        if right in (["TRUE"], ["FALSE"]) and _literal(left) and left not in (["'X'"], ['"Q"']):
            val = _const(left) != 0 if _const(left) is not None else left == ["TRUE"]
            return (val == (right == ["TRUE"])) != neg  # `TRUE IS TRUE`, `1 IS NOT FALSE`
        return None
    if op in ("BETWEEN", "NOT BETWEEN"):
        bounds = _split_at(right, _AND_INDEX)
        if not bounds:
            return None
        v, lo, hi = _const(left), _const(bounds[0]), _const(bounds[2])
        if v is not None and lo is not None and hi is not None:
            return (lo <= v <= hi) != (op == "NOT BETWEEN")  # `1 BETWEEN 0 AND 2`
        if op == "BETWEEN" and left == bounds[0] == bounds[2] and (_literal(left) or _column_ref(left)):
            return True  # `x BETWEEN x AND x`
        return None
    if op in ("IN", "NOT IN"):
        items = _items(right)
        if items is None:
            return None
        if left in items and (_literal(left) or _column_ref(left)):
            return op == "IN"  # `1 IN (1)`, `id IN (2, id)`
        v, vals = _const(left), [_const(i) for i in items]
        if v is not None and all(x is not None for x in vals):
            return (v in vals) != (op == "NOT IN")  # `1 NOT IN (2, 3)`
        return None
    lv, rv = _const(left), _const(right)
    if lv is not None and rv is not None and op in _COMPARE:
        return _COMPARE[op](lv, rv)  # `2>1`, `1+1=2`, `1<>2`
    if left == right and (_literal(left) or _column_ref(left)):
        if op in _REFLEXIVE:
            return True  # `1=1`, `'a'='a'`, `u.id = u.id`, `'a' LIKE 'a'`
        if op in _IRREFLEXIVE:
            return False
    return None


def _split_bool(tokens: List[str], word: str) -> List[List[str]]:
    """Split at every top-level `word` (OR / AND). The AND inside `x BETWEEN a AND b` is not a split point."""
    parts: List[List[str]] = [[]]
    d, between = 0, False
    for t in tokens:
        u = t.upper()
        if t == "(":
            d += 1
        elif t == ")":
            d -= 1
        elif d == 0 and u == "BETWEEN":
            between = True
        elif d == 0 and u == "AND" and between:
            between = False
            parts[-1].append(t)
            continue
        if d == 0 and u == word:
            parts.append([])
        else:
            parts[-1].append(t)
    return parts


def _group(tokens: List[str]) -> Optional[List[str]]:
    """The inside of `( cond )` when the tokens are exactly one grouped condition (a subquery is not one)."""
    if tokens and tokens[0] == "(" and _close(tokens, 0) == len(tokens) - 1:
        inner = tokens[1:-1]
        if inner and inner[0].upper() not in ("SELECT", "WITH", "VALUES", "TABLE"):
            return inner
    return None


def _always(tokens: List[str], strict: bool = False, depth: int = 0) -> Optional[bool]:
    """True when a condition holds for every row, False when it holds for none, None when it depends on the row.
    Recurses through OR, AND, NOT and grouping parentheses, so a tautology cannot hide inside `( ... )`.

    Strict mode counts only constant logic (`1=1`, `2>1`, `'a' LIKE 'a'`, `u.id = u.id`, `1 IN (1)`). The practical
    mode also counts `col IS NOT NULL` on a bare column as true: as the whole WHERE, or one whole OR branch of it, it
    reaches every row that has a value, which on a key column is every row."""
    if depth > 64 or not tokens:
        return None
    ors = _split_bool(tokens, "OR")
    if len(ors) > 1:
        vals = [_always(p, strict, depth + 1) for p in ors]
        return True if True in vals else (False if all(v is False for v in vals) else None)
    ands = _split_bool(tokens, "AND")
    if len(ands) > 1:
        vals = [_always(p, strict, depth + 1) for p in ands]
        return False if False in vals else (True if all(v is True for v in vals) else None)
    if tokens[0].upper() == "NOT" and len(tokens) > 1:
        v = _always(tokens[1:], strict, depth + 1)
        return None if v is None else not v
    inner = _group(tokens)
    if inner is not None:
        return _always(inner, strict, depth + 1)
    return _truth(tokens, strict)


def _hidden_tautology(tokens: List[str], depth: int = 0) -> bool:
    """An OR group, at any depth, with an always-true branch: the `OR 1=1` injection signature. Blocked even when
    an outer AND narrows it (`id=5 AND (status='x' OR 1=1)`), because no hand-written filter needs one. A constant
    joined by AND (`WHERE 1=1 AND id = 5`, the query-builder prefix) is not this signature."""
    if depth > 64 or not tokens:
        return False
    ors = _split_bool(tokens, "OR")
    if len(ors) > 1 and any(_always(p, True) is True for p in ors):
        return True
    for branch in ors:
        for part in _split_bool(branch, "AND"):
            while part and part[0].upper() == "NOT":
                part = part[1:]
            inner = _group(part)
            if inner is not None and _hidden_tautology(inner, depth + 1):
                return True
    return False


def _is_tautology(clause: List[str]) -> bool:
    return _always(list(clause)) is True or _hidden_tautology(list(clause))


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


def _scoped(clause: List[str]) -> bool:
    """A WHERE is scoped when it is not empty and not always true at any depth of parentheses."""
    return bool(clause) and not _is_tautology(clause)


def _judge(tokens: List[str], mode: str) -> List[Finding]:
    out: List[Finding] = []
    up = [t.upper() for t in tokens]
    first = up[0] if up else ""
    depths = _depths(tokens)
    taut_found = False
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
            elif not taut_found and not _scoped(clause):
                taut_found = True  # one finding per statement is enough; later writes need not be re-judged
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
    judged: set = set()
    parsed = 0
    for backslash, dashes, nested in itertools.product((False, True), repeat=3):
        text = _sanitise(sql or "", backslash, dashes, nested)
        if text is None:
            continue
        parsed += 1
        if text in judged:
            continue  # most readings agree: judge each distinct reading once
        judged.add(text)
        for stmt in _split_statements(text):
            for f in _judge(stmt, mode):
                findings.setdefault(f.rule, f)
    if not parsed:
        return [Finding("sql-unterminated", "unterminated quote or comment: cannot be judged safely", "sql")]
    return list(findings.values())
