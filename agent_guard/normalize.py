"""Evasion normalisation: the guard judges what a payload *means*, not how it is spelled.

Three tricks get past rules written for ASCII text, and each one is undone here before any rule runs:

  1. invisible characters (zero-width space/joiners, bidi marks, BOM, the Unicode tag block) split a keyword
     (`r<ZWSP>m -rf /`) so a pattern no longer matches;
  2. look-alike letters (Cyrillic `о`, Greek `ο`, fullwidth `ｒｍ`) spell a keyword or a host that reads as ASCII;
  3. Base64 hides the payload itself (`base64 -d`, `FromBase64String`, `atob(...)`, `exec(b64decode(...))`,
     `powershell -EncodedCommand`).

`fold()` strips (1) and maps (2) to ASCII; the guard runs every rule on the folded call. Two things are refused
outright because folding alone would hide them: a word that mixes ASCII with look-alike letters (no real command,
keyword or host is spelled that way), and a host with a mixed-script label or a label that folds wholly to ASCII.
A host written wholly in one non-Latin script (`пример.рф`) is a real IDN and passes. `decoded_payloads()`
finds Base64 blobs, decodes them (UTF-8 or the UTF-16LE that PowerShell uses) up to two layers deep, and hands the
text back so the guard judges it with the same shell, SQL and secret rules. Decoding never executes anything.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from typing import Any, Dict, Iterable, List, Tuple

from .types import Finding

# Zero-width and bidi controls, soft hyphen, BOM, invisible fillers, and the tag block that smuggles ASCII.
INVISIBLE = re.compile(
    "[­ᅟᅠ᠎​-‏‪-‮⁠-⁤⁦-⁩ㅤ﻿ﾠ]"
    "|[\U000e0000-\U000e007f]"
)

# Cyrillic and Greek letters that render like ASCII. NFKC leaves these alone because they are real letters.
_CONFUSABLE_PAIRS = (
    # Cyrillic lower / upper
    "а:a е:e о:o р:p с:c у:y х:x і:i ј:j ѕ:s ԁ:d һ:h ӏ:l ԛ:q ԝ:w ү:y ɡ:g "
    "А:A В:B Е:E К:K М:M Н:H О:O Р:P С:C Т:T Х:X У:Y І:I Ј:J Ѕ:S Ԛ:Q Ԝ:W "
    # Greek lower / upper
    "α:a ο:o ρ:p ε:e ι:i κ:k ν:v τ:t υ:u χ:x ϲ:c ϳ:j "
    "Α:A Β:B Ε:E Ζ:Z Η:H Ι:I Κ:K Μ:M Ν:N Ο:O Ρ:P Τ:T Υ:Y Χ:X Ϲ:C"
)
CONFUSABLES: Dict[str, str] = dict(pair.split(":") for pair in _CONFUSABLE_PAIRS.split())
FOLD_TABLE = str.maketrans(CONFUSABLES)

_LETTER_RUN = re.compile(r"[^\W\d_]+")
_HOSTLIKE = re.compile(r"(?:[^\W_]|-)+(?:\.(?:[^\W_]|-)+)+")
_SQL_START = re.compile(r"^\s*(?:SELECT|WITH|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|MERGE|GRANT|REVOKE|EXEC|"
                        r"EXECUTE|COPY|ATTACH|REPLACE|UPSERT|CALL)\b", re.I)
_B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_PS_ENCODED = re.compile(r"(?i)(?:^|\s)-e(?:c|nc|ncodedcommand|ncoded)?\s+([A-Za-z0-9+/]{4,}={0,2})")
# A blob handed straight to a decoder is decoded whatever its length; elsewhere only blobs of 16+ characters are.
_DECODE_CALL = re.compile(
    r"(?i)(?:atob|b64decode|urlsafe_b64decode|decodebytes|decodestring|FromBase64String|Buffer\.from)\s*\(\s*"
    r"(?:[a-z]{1,2})?[\"']([A-Za-z0-9+/_=-]{4,})[\"']"
    r"|(?:echo|printf)\s+(?:-n\s+)?[\"']?([A-Za-z0-9+/_=-]{4,})[\"']?\s*\|\s*(?:base64|openssl\s+(?:base64|enc))"
    r"|<<<\s*[\"']?([A-Za-z0-9+/_=-]{4,})[\"']?"
)
_MAX_DECODE_DEPTH = 2
_MAX_BLOBS = 32


def fold(text: str) -> str:
    """Invisible characters removed, NFKC applied, Cyrillic/Greek look-alikes mapped to ASCII."""
    if not text or text.isascii():
        return text
    return unicodedata.normalize("NFKC", INVISIBLE.sub("", text)).translate(FOLD_TABLE)


def fold_input(value: Any) -> Any:
    """A copy of a tool input with every string folded (dict keys included)."""
    if isinstance(value, str):
        return fold(value)
    if isinstance(value, dict):
        return {fold(k) if isinstance(k, str) else k: fold_input(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [fold_input(v) for v in value]
    return value


def mixed_script_words(text: str) -> List[str]:
    """Letter runs that mix ASCII letters with look-alike letters (`DRОP`, `rм`, `еvil`). Pure Cyrillic or pure
    Greek words are ordinary language and never match."""
    if not text or text.isascii():
        return []
    out = []
    for m in _LETTER_RUN.finditer(INVISIBLE.sub("", text)):
        word = m.group(0)
        if any(c.isascii() for c in word) and any(c in CONFUSABLES for c in word):
            out.append(word)
    return out


def _scripts(label: str) -> set:
    """The writing systems of a label's letters (LATIN, CYRILLIC, GREEK, ...) from their Unicode names."""
    out = set()
    for c in label:
        if c.isalpha():
            name = unicodedata.name(c, "")
            out.add(name.split(" ", 1)[0] if name else "UNKNOWN")
    return out


def _spoofed_label(label: str) -> bool:
    """A label that pretends to be ASCII: it mixes writing systems (`exаmple`, Latin with one Cyrillic `а`), or it
    folds entirely to ASCII (`раураl` in Cyrillic reads as `paypal`; fullwidth `ｅｘａｍｐｌｅ`). A label written
    wholly in one non-Latin script that stays non-ASCII after folding (`пример`) is an ordinary IDN label."""
    if label.isascii():
        return False
    folded = fold(label)
    return len(_scripts(label)) > 1 or (folded != label and folded.isascii())


def spoofed_hosts(text: str) -> List[str]:
    """Host-like tokens that hide a look-alike, fullwidth or invisible character: an invisible character anywhere,
    or any label that is mixed-script or folds to ASCII. Pure single-script IDN hosts (`пример.рф`) pass."""
    if not text or text.isascii():
        return []
    out = []
    for token in text.split():
        visible = INVISIBLE.sub("", token)
        hidden = visible != token  # an invisible character inside the token
        for m in _HOSTLIKE.finditer(visible):
            host = m.group(0)
            if hidden or any(_spoofed_label(lab) for lab in host.split(".")):
                out.append(host)
    return out


def _printable(s: str) -> bool:
    if not s:
        return False
    good = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return good / len(s) >= 0.95


def _decode_blob(blob: str) -> List[str]:
    """Every readable text a Base64 blob decodes to (UTF-8 and UTF-16LE, standard and URL-safe alphabets)."""
    texts: List[str] = []
    core = blob.rstrip("=")
    if len(core) % 4 == 1:
        return texts
    padded = core + "=" * (-len(core) % 4)
    raws = []
    for altchars in (None, b"-_"):
        try:
            raws.append(base64.b64decode(padded, altchars=altchars, validate=True))
        except (binascii.Error, ValueError):
            continue
    for raw in raws:
        for enc in ("utf-8", "utf-16-le"):
            if enc == "utf-16-le" and (len(raw) % 2 or b"\x00" not in raw):
                continue
            try:
                s = raw.decode(enc)
            except UnicodeDecodeError:
                continue
            if _printable(s) and s not in texts:
                texts.append(s)
    return texts


def decoded_payloads(text: str) -> List[str]:
    """Readable text hidden in Base64 inside `text`, decoded up to two layers deep. Never executes anything."""
    if not text or len(text) < 8:
        return []
    found: List[str] = []
    frontier: List[Tuple[str, int]] = [(text, 0)]
    while frontier and len(found) < _MAX_BLOBS:
        current, depth = frontier.pop()
        if depth >= _MAX_DECODE_DEPTH:
            continue
        blobs = [m.group(1) for m in _PS_ENCODED.finditer(current)]
        blobs += [next(g for g in m.groups() if g) for m in _DECODE_CALL.finditer(current)]
        blobs += [m.group(0) for m in _B64_BLOB.finditer(current)]
        for blob in dict.fromkeys(blobs):
            for decoded in _decode_blob(blob):
                if decoded not in found:
                    found.append(decoded)
                    frontier.append((decoded, depth + 1))
    return found


_SQL_PREAMBLE = re.compile(
    r"\s*(?:/\*.*?\*/|--[^\n]*(?:\n|$)|#[^\n]*(?:\n|$)|"
    r"(?:BEGIN(?:\s+(?:TRANSACTION|WORK|TRAN))?\s*|START\s+TRANSACTION\b[^;]*|SET\s[^;]*|USE\s[^;]*);)",
    re.I | re.S)


def looks_like_sql(text: str) -> bool:
    """SQL, also behind leading comments and session preambles (`/* x */`, `-- x`, `BEGIN;`, `START TRANSACTION;`,
    `SET ROLE admin;`, `USE db;`)."""
    text = text or ""
    for _ in range(64):
        m = _SQL_PREAMBLE.match(text)
        if not m or not m.group(0):
            break
        text = text[m.end():]
    return bool(_SQL_START.match(text))


def walk(value: Any) -> Iterable[Tuple[str, str]]:
    """(key, string) for every string in a nested tool input; the key is the nearest dict key."""
    stack: List[Tuple[str, Any]] = [("", value)]
    while stack:
        key, v = stack.pop()
        if isinstance(v, str):
            yield key, v
        elif isinstance(v, dict):
            stack.extend((str(k), x) for k, x in v.items())
        elif isinstance(v, (list, tuple)):
            stack.extend((key, x) for x in v)


_RECIPIENT_KEYS = {"to", "cc", "bcc", "recipient", "recipients", "reply_to", "from", "channel", "url", "uri", "href",
                   "webhook", "endpoint", "host"}


def spelling_findings(tool_input: Dict[str, Any], roles: Iterable[str], path_keys: Iterable[str]) -> List[Finding]:
    """Refusals for spellings that folding would otherwise hide. Runs on the *raw* (unfolded) tool input."""
    roles = set(roles)
    path_keys = set(path_keys)
    code_like = bool(roles & {"shell", "sql", "url"})
    out: List[Finding] = []
    for key, s in walk(tool_input):
        if s.isascii():
            continue
        key_l = key.lower()
        if code_like or key_l in path_keys or key_l in _RECIPIENT_KEYS:
            words = mixed_script_words(s)
            if words:
                out.append(Finding("evasion-homoglyph", f"look-alike letters inside `{words[0]}`", "evasion"))
        if roles & {"shell", "sql", "url", "message"} or key_l in path_keys:
            hosts = spoofed_hosts(s)
            if hosts:
                out.append(Finding("evasion-homoglyph-host", f"host `{hosts[0]}` only reads as ASCII", "evasion"))
        if code_like and INVISIBLE.search(s.lstrip("﻿")):
            out.append(Finding("evasion-invisible-char", "invisible characters inside a command or query", "evasion"))
    return out
