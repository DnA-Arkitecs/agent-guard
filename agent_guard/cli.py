"""Command line: --demo, --benchmark, check, hook, scan, sql, policy."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .benchmark import render_benchmark, run_benchmark
from .guard import Guard
from .hook import run_hook
from .injection import clean_untrusted
from .policy import Policy
from .replay import DEMO_POLICY, render, run_replay
from .session import Session, SessionStore
from .sqlguard import check_sql


def _load_policy(path: Optional[str]) -> Policy:
    return Policy.load(path) if path else Policy.from_dict(DEMO_POLICY)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="agent_guard", description="Deterministic pre-execution firewall for AI agents.")
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("--demo", action="store_true", help="replay benign + 20 hostile payloads through the guard")
    ap.add_argument("--benchmark", action="store_true",
                    help="red-team suite: 50 hostile calls over 6 vectors + 40 benign, p50/p95/p99 latency")
    ap.add_argument("--rounds", type=int, default=200, help="replay rounds for --benchmark (default 200)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    sub = ap.add_subparsers(dest="cmd")

    c = sub.add_parser("check", help="judge one proposed tool call")
    c.add_argument("--policy")
    c.add_argument("--agent", default="default")
    c.add_argument("--tool", required=True)
    c.add_argument("--input", default="{}", help="tool input as a JSON object")
    c.add_argument("--ingest", action="append", default=[], metavar="FILE",
                   help="treat this file as untrusted text the agent already read (repeatable)")

    h = sub.add_parser("hook", help="PreToolUse/PostToolUse hook: JSON on stdin, deny decision on stdout")
    h.add_argument("--policy")
    h.add_argument("--agent")
    h.add_argument("--fail-open", action="store_true", help="allow the call if the guard itself errors (default: deny)")

    s = sub.add_parser("scan", help="scan untrusted text (file or - for stdin) for hidden content and injection phrasing")
    s.add_argument("file")

    q = sub.add_parser("sql", help="judge a SQL string")
    q.add_argument("statement")
    q.add_argument("--mode", default="scoped_write", choices=["scoped_write", "read_only", "deny"])

    sub.add_parser("policy", help="print the built-in demo policy as JSON (a starting point for your own)")

    args = ap.parse_args(argv)
    if args.benchmark:
        report = run_benchmark(args.rounds)
        if args.json:
            skip = ("misses", "false_positive_cases")
            print(json.dumps({k: v for k, v in report.items() if k not in skip} | {
                "misses": [r.case.id for r in report["misses"]],
                "false_positive_cases": [r.case.id for r in report["false_positive_cases"]]}, indent=2))
        else:
            print(render_benchmark(report))
        return 0 if report["ok"] else 1
    if args.demo:
        report = run_replay()
        if args.json:
            print(json.dumps({k: v for k, v in report.items() if k != "results"} | {
                "cases": [{"id": r.case.id, "kind": r.case.kind, "allowed": r.allowed, "rules": r.rules,
                           "passed": r.passed} for r in report["results"]]}, indent=2))
        else:
            print(render(report))
        return 0 if report["ok"] else 1

    if args.cmd == "check":
        policy = _load_policy(args.policy)
        session = Session("cli")
        for f in args.ingest:
            session.ingest(open(f, encoding="utf-8", errors="replace").read(), source=f)
        d = Guard(policy).check(args.agent, args.tool, json.loads(args.input), session)
        print(json.dumps({"allow": d.allow, "rules": d.rules, "reason": d.reason}) if args.json
              else ("ALLOW" if d.allow else f"BLOCK [{d.rule}] {d.reason}"))
        return 0 if d.allow else 2
    if args.cmd == "hook":
        policy = _load_policy(args.policy)
        out = run_hook(sys.stdin.read(), policy, SessionStore(), fail_open=args.fail_open, default_agent=args.agent)
        if out:
            print(out)
        return 0
    if args.cmd == "scan":
        text = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8", errors="replace").read()
        r = clean_untrusted(text)
        print(json.dumps({"flags": r.flags, "hidden_content": r.hidden_content, "invisible_removed": r.invisible_removed,
                          "truncated": r.truncated, "suspicious": r.suspicious}, indent=2))
        return 2 if r.suspicious else 0
    if args.cmd == "sql":
        findings = check_sql(args.statement, args.mode)
        print("ALLOW" if not findings else "\n".join(f"BLOCK [{f.rule}] {f.reason}" for f in findings))
        return 0 if not findings else 2
    if args.cmd == "policy":
        print(json.dumps(DEMO_POLICY, indent=2))
        return 0
    ap.print_help()
    return 0
