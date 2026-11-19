"""PreToolUse / PostToolUse command-interceptor hook.

Wire it as a hook that receives the tool call as JSON on stdin and prints a deny decision on stdout:

    {"hooks": {"PreToolUse":  [{"matcher": "*", "hooks": [{"type": "command", "command": "python -m agent_guard hook"}]}],
               "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "python -m agent_guard hook"}]}]}}

PreToolUse: run every rule; print a deny decision when any fires. PostToolUse: when the tool is an untrusted source
(web fetch, e-mail read), record its result as tainting text for the session. The guard fails CLOSED: if anything
inside it breaks the call is denied, unless --fail-open is passed.
"""
from __future__ import annotations

import json
import os
from typing import Optional

from .audit import log_decision
from .guard import Guard
from .policy import Policy
from .secrets import walk_strings
from .session import SessionStore
from .types import Decision, Finding


def run_hook(stdin_text: str, policy: Policy, store: Optional[SessionStore] = None,
             fail_open: bool = False, default_agent: Optional[str] = None) -> Optional[str]:
    """-> the JSON string to print on stdout (a deny decision), or None to let the call through."""
    store = store or SessionStore()
    agent = tool = ""
    try:
        payload = json.loads(stdin_text or "{}")
        if not isinstance(payload, dict):
            raise ValueError("hook payload is not an object")
        tool = str(payload.get("tool_name") or "")
        tool_input = payload.get("tool_input") or {}
        session_id = str(payload.get("session_id") or "default")
        agent = str(payload.get("agent_name") or payload.get("agent_type") or default_agent
                    or os.environ.get("AGENT_GUARD_AGENT") or "default")
        event = payload.get("hook_event_name") or "PreToolUse"
        session = store.load(session_id)
        if os.environ.get("AGENT_GUARD_REPLY_TO") and not session.reply_to:
            session.reply_to = os.environ["AGENT_GUARD_REPLY_TO"]
        if event == "PostToolUse":
            if policy.is_untrusted_source(tool):
                text = "\n".join(walk_strings(payload.get("tool_response")))
                session.ingest(text, source=tool)
                store.save(session)
            return None
        decision = Guard(policy).check(agent, tool, tool_input, session)
        store.save(session)
        log_decision(decision, session_id, json.dumps(tool_input, default=str))
        return json.dumps(decision.to_hook_output()) if not decision.allow else None
    except Exception as exc:  # noqa: BLE001 - the whole point is to catch everything
        decision = Decision(False, [Finding("guard-internal-error", f"{type(exc).__name__}: {exc}", "tool")], agent, tool)
        log_decision(decision)
        return None if fail_open else json.dumps(decision.to_hook_output())
