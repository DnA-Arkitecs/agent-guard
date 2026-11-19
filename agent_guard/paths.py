"""Pure-string path logic: no filesystem access, so a verdict is identical on every OS and in every replay."""
from __future__ import annotations

import posixpath
import re
from typing import Iterable, List, Optional

_DRIVE = re.compile(r"^([A-Za-z]):(?:/|$)")
_VARIABLE = re.compile(r"\$|`|%[A-Za-z_]+%")

_CRED_BASENAMES = {
    ".netrc", ".pgpass", ".npmrc", ".pypirc", ".git-credentials", ".htpasswd",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "credentials", "credentials.json", "credentials.yml", "credentials.yaml",
    "secrets.json", "secrets.yml", "secrets.yaml", "secrets.toml", "service-account.json",
    "shadow", "gshadow", "sudoers", "authorized_keys", "master.key", "wallet.dat",
    "cookies.sqlite", "login data", "kubeconfig",
}
_CRED_DIRS = {".ssh", ".aws", ".gnupg", ".azure", ".kube"}
_CRED_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdbx", ".jks", ".keystore", ".ppk")
_ENV_TEMPLATES = (".example", ".sample", ".template", ".dist", ".defaults")

_PROTECTED_PREFIXES = (
    "/etc", "/bin", "/sbin", "/usr", "/lib", "/lib64", "/boot", "/sys", "/proc", "/var/lib", "/root",
    "/dev", "/system", "/library", "c:/windows", "c:/program files", "c:/program files (x86)", "c:/programdata",
)
_SAFE_DEVICES = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty", "/dev/zero"}


def _clean(path: str) -> str:
    return (path or "").strip().strip("\"'").replace("\\", "/")


def normalize(path: str, cwd: str = "/workspace", home: str = "/home/agent") -> Optional[str]:
    """Absolute, normalised, forward-slash path. None when it holds an unresolved variable or a NUL byte."""
    p = _clean(path)
    if not p or "\x00" in p:
        return None
    for token in ("${HOME}", "$HOME"):
        if p.startswith(token):
            p = home + p[len(token):]
            break
    if p == "~" or p.startswith("~/"):
        p = home + p[1:]
    elif p.startswith("~"):
        user, _, rest = p[1:].partition("/")
        p = ("/root" if user == "root" else f"/home/{user}") + ("/" + rest if rest else "")
    if _VARIABLE.search(p):
        return None
    m = _DRIVE.match(p)
    if m:
        p = m.group(1).lower() + p[1:]
        absolute = True
    else:
        absolute = p.startswith("/")
    if not absolute:
        p = _clean(cwd).rstrip("/") + "/" + p
    p = re.sub(r"^/{2,}", "/", p)
    out = posixpath.normpath(p)
    return re.sub(r"^/{2,}", "/", out)


def normalize_all(paths: Iterable[str], cwd: str, home: str) -> List[str]:
    return [n for n in (normalize(p, cwd, home) for p in paths) if n]


def under(norm: str, roots: Iterable[str]) -> bool:
    """Is the normalised path equal to, or inside, one of the (already normalised) roots?"""
    for r in roots:
        r = r.rstrip("/") or "/"
        if r == "/":
            continue  # a root of "/" would allow everything; treated as a configuration mistake
        if norm == r or norm.startswith(r + "/"):
            return True
    return False


def is_credential_path(path: str) -> bool:
    p = _clean(path).lower()
    if not p:
        return False
    parts = [s for s in p.split("/") if s]
    base = parts[-1] if parts else ""
    if base in _CRED_BASENAMES or base.endswith(_CRED_SUFFIXES):
        return True
    if base == ".env" or base.endswith(".env"):
        return True
    if base.startswith(".env.") and not base.endswith(_ENV_TEMPLATES):
        return True
    if any(seg in _CRED_DIRS for seg in parts[:-1]) or (parts and parts[-1] in _CRED_DIRS):
        return True
    if len(parts) >= 2 and parts[-2] == ".docker" and base == "config.json":
        return True
    if ".config/gcloud" in p or ".config/gh/hosts" in p or ".config/git/credentials" in p:
        return True
    if re.search(r"(^|/)proc/(self|\d+)/environ$", p):
        return True
    return False


def is_protected_path(norm: str) -> bool:
    """System-critical locations nothing an agent runs should write to or delete."""
    if norm in _SAFE_DEVICES:
        return False
    if norm.count("/") <= 1:  # "/", "/usr", "c:" level
        return True
    if norm.startswith("/home/") and norm.count("/") <= 2:  # a whole home directory
        return True
    return any(norm == p or norm.startswith(p + "/") for p in _PROTECTED_PREFIXES)
