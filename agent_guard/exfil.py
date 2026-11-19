"""Egress rules: what may leave the machine, and to whom.

Three deterministic ideas, in order of strength:
  1. a destination must be on the agent's allowlist (hosts, recipients) to receive *uploaded* data, tainted or not;
  2. once the session has read untrusted text, even plain GETs are allowlist-only (a query string is a data channel);
  3. a destination that only the untrusted text named (an address or host it injected) is refused by name.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Sequence, Set
from urllib.parse import urlsplit

from .policy import AgentPolicy, host_allowed, recipient_allowed
from .secrets import find_secrets
from .session import Session
from .shellguard import Segment, effective
from .types import Finding

_URL_WORD = re.compile(r"^(?:https?|ftp|wss?|sftp|ssh)://\S+$", re.I)
_BARE_HOST = re.compile(r"^(?:[\w-]+@)?([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?::\d+)?(?:/\S*)?$")
_FILE_EXT = {"txt", "json", "md", "py", "js", "csv", "log", "yml", "yaml", "toml", "cfg", "ini", "xml", "html", "htm", "png",
             "jpg", "jpeg", "gif", "pdf", "zip", "gz", "tar", "bin", "out", "tmp", "bak", "conf", "env", "key", "pem", "sql",
             "lock", "cfg", "rs", "go", "ts", "c", "h", "java", "rb", "php", "svg", "map", "dat"}
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_BODY_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)\s*\)|<img\b[^>]*\bsrc\s*=\s*[\"']?(https?://[^\"'>\s]+)", re.I)

_DOWNLOAD = {"curl", "wget", "http", "https", "iwr", "invoke-webrequest", "fetch", "aria2c"}
_RAW_SOCKET = {"nc", "ncat", "netcat", "socat", "telnet", "ftp", "tftp"}
_REMOTE_COPY = {"scp", "sftp", "rsync"}
_QUIET = {"echo", "printf", "grep", "rg", "sed", "awk", "cat", "head", "tail", "less", "more", "tee", "diff", "wc", "sort",
          "uniq", "cut", "tr", "jq", "yq", "ls", "find", "test", "[", "git-log"}
_CURL_VALUE_FLAGS = {"-H", "-d", "-o", "-X", "-u", "-A", "-e", "-F", "-T", "-b", "-c", "-K", "-m", "-x", "-w", "-E", "-r",
                     "--header", "--output", "--request", "--user", "--user-agent", "--form", "--upload-file", "--cookie",
                     "--proxy", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json", "--cert", "--key"}
_WGET_VALUE_FLAGS = {"-O", "-o", "-P", "-U", "-e", "-t", "-T", "-w", "--header", "--post-data", "--post-file", "--method",
                     "--body-data", "--body-file", "--user-agent", "--output-document", "--directory-prefix"}
_NET_INLINE = re.compile(r"urllib|requests\.|http\.client|socket|urlopen|fetch\(|XMLHttpRequest|axios|Invoke-WebRequest|"
                         r"Invoke-RestMethod|net\.connect|https?\.request|WebClient", re.I)


def _host_of(word: str) -> Optional[str]:
    w = word.strip("\"'")
    if _URL_WORD.match(w):
        try:
            return urlsplit(w).hostname or ""
        except ValueError:
            return ""
    return None


def _bare_host(word: str) -> Optional[str]:
    m = _BARE_HOST.match(word.strip("\"'"))
    if not m:
        return None
    host = m.group(1).lower()
    return None if host.rsplit(".", 1)[-1] in _FILE_EXT else host


def _positionals(args: Sequence[str], value_flags: Set[str]) -> List[str]:
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
        elif a in value_flags:
            skip = True
        elif a.startswith("-") and "=" in a:
            continue
        elif not a.startswith("-"):
            out.append(a)
    return out


def _judge_host(host: str, upload: bool, ap: AgentPolicy, session: Session, what: str) -> Optional[Finding]:
    if "$" in host or "`" in host:
        return Finding("exfil-dynamic-destination", f"{what} destination is built at run time: `{host}`", "exfil")
    if host_allowed(host, ap.allowed_hosts):
        return None
    attacker_domains = set(session.attacker_hosts) | {e.rsplit("@", 1)[-1] for e in session.attacker_emails}
    if host in attacker_domains:
        return Finding("exfil-attacker-destination",
                       f"{what} to `{host}`, a destination that untrusted text supplied", "exfil")
    if upload:
        return Finding("exfil-unlisted-destination", f"{what} sends data to `{host}`, which is not on the allowlist", "exfil")
    if session.tainted:
        return Finding("exfil-tainted-egress",
                       f"session has read untrusted text; request to `{host}` is not on the allowlist", "exfil")
    if ap.egress == "strict":
        return Finding("exfil-strict-egress", f"strict egress: `{host}` is not on the allowlist", "exfil")
    return None


def shell_egress(segments: Iterable[Segment], ap: AgentPolicy, session: Session) -> List[Finding]:
    out: List[Finding] = []
    for seg in segments:
        e = effective(seg.words)
        raw_words = seg.words
        for w in raw_words:  # bash's /dev/tcp pseudo-device
            m = re.search(r"/dev/(?:tcp|udp)/([^/\s]+)/", w)
            if m:
                f = _judge_host(m.group(1).lower(), True, ap, session, "raw socket")
                out.append(f or Finding("exfil-raw-socket", "/dev/tcp opens a raw socket", "exfil"))
        if not e or not e.cmd or e.cmd in _QUIET:
            continue
        cmd, args = e.cmd, e.args
        hosts: List[str] = []
        upload = False
        if cmd in _DOWNLOAD:
            flags = _CURL_VALUE_FLAGS if cmd != "wget" else _WGET_VALUE_FLAGS
            for k, a in enumerate(args):
                low = a.lower()
                if cmd == "wget":
                    if low.startswith(("--post-data", "--post-file", "--body-data", "--body-file")):
                        upload = True
                    if low.startswith("--method") and not low.endswith("get"):
                        upload = True
                else:
                    if a in ("-d", "-F", "-T", "-G", "--json") or low.startswith(
                            ("--data", "--form", "--upload-file")) or (a.startswith("-d") and len(a) > 2 and not a.startswith("--")):
                        upload = True
                    if a in ("-X", "--request") and k + 1 < len(args) and args[k + 1].upper() in ("POST", "PUT", "PATCH", "DELETE"):
                        upload = True
                    if a.startswith("-X") and len(a) > 2 and a[2:].upper() in ("POST", "PUT", "PATCH", "DELETE"):
                        upload = True
            for p in _positionals(args, flags):
                h = _host_of(p) if _host_of(p) is not None else _bare_host(p)
                if h is not None:
                    hosts.append(h)
            if not hosts and cmd in ("curl", "wget"):
                out.append(Finding("exfil-unknown-destination", f"`{cmd}` with no destination that can be read", "exfil"))
        elif cmd in _RAW_SOCKET:
            upload = True
            pos = [a for a in args if not a.startswith("-")]
            hosts = [pos[0].lower()] if pos else []
            if not hosts:
                out.append(Finding("exfil-unknown-destination", f"`{cmd}` with no destination that can be read", "exfil"))
        elif cmd in _REMOTE_COPY or cmd == "ssh":
            upload = True
            for p in [a for a in args if not a.startswith("-")]:
                m = re.match(r"^(?:[\w.-]+@)?([A-Za-z0-9.-]+):(?!//)", p) if cmd != "ssh" else None
                if m and not re.match(r"^[A-Za-z]:[\\/]", p):
                    hosts.append(m.group(1).lower())
                elif cmd == "ssh" and not hosts:
                    hosts.append(p.split("@")[-1].lower())
                elif _host_of(p):
                    hosts.append(_host_of(p) or "")
            if cmd != "ssh" and not hosts:
                continue  # a purely local copy
        elif cmd == "git" and any(a in ("push", "remote") for a in args[:3]):
            for a in args:
                h = _host_of(a)
                m = re.match(r"^[\w.-]+@([A-Za-z0-9.-]+):", a)
                if h:
                    hosts.append(h)
                elif m:
                    hosts.append(m.group(1).lower())
            upload = "push" in args[:3]
        elif cmd in ("python", "python3", "node", "perl", "ruby", "powershell", "pwsh") or cmd.startswith(("python", "pypy")):
            code = " ".join(args)
            if _NET_INLINE.search(code) and any(a in ("-c", "-e", "-Command", "-command") for a in args):
                upload = True
                hosts = [h for h in (_host_of(m) for m in re.findall(r"https?://[^\s'\")]+", code)) if h]
                if not hosts:
                    out.append(Finding("exfil-unknown-destination", "inline code opens a network connection", "exfil"))
        else:
            for a in args:  # any other command handed a URL (pip install https://..., npm i https://...)
                h = _host_of(a)
                if h:
                    hosts.append(h)
        for h in dict.fromkeys(hosts):
            f = _judge_host(h, upload, ap, session, f"`{cmd}`")
            if f:
                out.append(f)
    return out


_RECIPIENT_KEYS = ("to", "recipient", "recipients", "email", "address", "channel", "chat_id")
_COPY_KEYS = ("cc", "bcc")
_BODY_KEYS = ("body", "text", "message", "content", "html", "subject", "caption", "markdown")
_URL_KEYS = ("url", "uri", "endpoint", "webhook", "webhook_url", "href")


def _as_list(v) -> List[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [s.strip() for s in re.split(r"[;,]", v) if s.strip()]
    if isinstance(v, (list, tuple)):
        out: List[str] = []
        for x in v:
            out += _as_list(x if isinstance(x, str) else (x.get("email") or x.get("address") if isinstance(x, dict) else None))
        return out
    return []


def _addr(entry: str) -> str:
    m = _EMAIL.search(entry)
    return (m.group(0) if m else entry).lower()


def message_egress(tool_input: Dict, ap: AgentPolicy, session: Session) -> List[Finding]:
    out: List[Finding] = []
    to = [_addr(x) for k in _RECIPIENT_KEYS for x in _as_list(tool_input.get(k))]
    copies = [_addr(x) for k in _COPY_KEYS for x in _as_list(tool_input.get(k))]
    allowed = list(ap.allowed_recipients) + ([session.reply_to.lower()] if session.reply_to else [])
    for r in dict.fromkeys(to + copies):
        if recipient_allowed(r, allowed):
            continue
        if r in session.attacker_emails:
            out.append(Finding("exfil-attacker-destination", f"recipient `{r}` was supplied by untrusted text", "exfil"))
        else:
            out.append(Finding("exfil-unlisted-recipient", f"recipient `{r}` is not on the allowlist or the thread's sender", "exfil"))
    if session.tainted and copies:
        out.append(Finding("exfil-tainted-copy", "cc / bcc are refused once untrusted text has been read", "exfil"))
    if session.tainted and len(set(to)) > 1:
        out.append(Finding("exfil-multiple-recipients", "one recipient only once untrusted text has been read", "exfil"))
    if ap.max_outbound_per_session is not None and session.outbound_count >= ap.max_outbound_per_session:
        out.append(Finding("exfil-rate-limit", f"outbound cap of {ap.max_outbound_per_session} per session reached", "exfil"))
    for k in _URL_KEYS:
        v = tool_input.get(k)
        if isinstance(v, str) and v:
            out += url_egress(v, str(tool_input.get("method", "POST")), ap, session)
    body = "\n".join(str(tool_input[k]) for k in _BODY_KEYS if isinstance(tool_input.get(k), str))
    for m in _MD_IMAGE.finditer(body):
        host = _host_of(m.group(1) or m.group(2)) or ""
        if not host_allowed(host, ap.allowed_hosts):
            out.append(Finding("exfil-markdown-image", f"auto-loading image from `{host}` can carry data out", "exfil"))
    for m in _BODY_URL.finditer(body):
        host = _host_of(m.group(0)) or ""
        if host_allowed(host, ap.allowed_hosts):
            continue
        if host in session.attacker_hosts and session.tainted:
            out.append(Finding("exfil-attacker-link", f"link to `{host}` came from untrusted text", "exfil"))
        elif session.tainted and "?" in m.group(0):
            out.append(Finding("exfil-link-with-data", f"link with a query string to unlisted host `{host}`", "exfil"))
    return out


def url_egress(url: str, method: str, ap: AgentPolicy, session: Session) -> List[Finding]:
    host = _host_of(url) if _host_of(url) is not None else _bare_host(url)
    if host is None:
        return [Finding("exfil-unknown-destination", f"URL `{url[:60]}` cannot be parsed", "exfil")]
    f = _judge_host(host, method.upper() not in ("GET", "HEAD", "OPTIONS"), ap, session, "request")
    return [f] if f else []
