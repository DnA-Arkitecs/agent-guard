"""Secret detection: well-known key shapes plus the live values of this process's secret-looking env vars."""
from __future__ import annotations

import os
import re
from typing import Iterable, List, Mapping, Optional

SECRET_PATTERNS = {
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "github-fine-grained": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    "slack-token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "api-key-sk": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "payment-live-key": re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}\b"),
    "google-api-key": re.compile(r"\bAI" + r"za[0-9A-Za-z_-]{35}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "private-key-block": re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    "url-credentials": re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s:@]{3,}@"),
}

SECRET_ENV_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", re.I)
MIN_ENV_SECRET_LEN = 8


def find_secrets(text: str) -> List[str]:
    """Names of the secret shapes present in text (never the secrets themselves)."""
    return [name for name, rx in SECRET_PATTERNS.items() if rx.search(text or "")]


def env_secret_values(env: Optional[Mapping[str, str]] = None) -> List[str]:
    """Values of secret-looking environment variables long enough to be worth matching."""
    src = os.environ if env is None else env
    return [v for k, v in src.items() if SECRET_ENV_NAME.search(k) and len(v or "") >= MIN_ENV_SECRET_LEN]


def contains_env_secret(text: str, env: Optional[Mapping[str, str]] = None) -> bool:
    return any(v in (text or "") for v in env_secret_values(env))


def redact(text: str, env: Optional[Mapping[str, str]] = None) -> str:
    out = text or ""
    for name, rx in SECRET_PATTERNS.items():
        out = rx.sub(f"[REDACTED:{name}]", out)
    for v in env_secret_values(env):
        out = out.replace(v, "[REDACTED:env]")
    return out


def walk_strings(obj, limit: int = 5000) -> Iterable[str]:
    """Every string inside a JSON-like value (dict values, list items, nested)."""
    stack = [obj]
    seen = 0
    while stack and seen < limit:
        cur = stack.pop()
        seen += 1
        if isinstance(cur, str):
            yield cur
        elif isinstance(cur, Mapping):
            stack.extend(cur.values())
        elif isinstance(cur, (list, tuple, set)):
            stack.extend(cur)
