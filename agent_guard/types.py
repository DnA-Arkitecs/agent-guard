"""Shared result types. A Decision is the only thing a caller needs to look at."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass(frozen=True)
class Finding:
    """One rule that fired. `rule` is a stable slug; `category` groups rules for reports."""

    rule: str
    reason: str
    category: str  # tool | path | shell | heredoc | sql | exfil | secret | injection


@dataclass
class Decision:
    allow: bool
    findings: List[Finding] = field(default_factory=list)
    agent: str = ""
    tool: str = ""

    def __bool__(self) -> bool:
        return self.allow

    @property
    def rule(self) -> str:
        return self.findings[0].rule if self.findings else ""

    @property
    def reason(self) -> str:
        return "; ".join(f.reason for f in self.findings)

    @property
    def rules(self) -> List[str]:
        return [f.rule for f in self.findings]

    def to_hook_output(self) -> Dict[str, Any]:
        """The JSON a PreToolUse hook prints to stdout to deny a call."""
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"agent-guard [{self.rule}]: {self.reason}",
            }
        }
