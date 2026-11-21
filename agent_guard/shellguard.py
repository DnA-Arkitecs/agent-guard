"""Shell command firewall: a real (if small) shell tokenizer plus deterministic rules.

The command is split into simple commands on `; && || | &` and newlines (quote-aware), `$(...)`, backticks, and
`bash -c` / `eval` / `ssh host CMD` / `sudo` payloads are parsed recursively, so nesting does not hide a command.
Rules then judge each command for: recursive/forced deletes of protected or out-of-scope paths, disk and system
destruction, privilege escalation, destructive git, remote-code piping (`curl | sh`), credential-file reads,
environment dumps and secret-variable references, writes outside the agent's write roots, persistence, container
escapes, and destructive infrastructure verbs. Outbound-network rules live in `exfil.py` (same parsed segments).
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from . import paths
from .secrets import SECRET_ENV_NAME
from .types import Finding

MAX_DEPTH = 5


@dataclass
class ShellContext:
    cwd: str = "/workspace"
    home: str = "/home/agent"
    write_roots: List[str] = field(default_factory=list)  # normalised; empty = no scope configured
    allow_env_refs: Sequence[str] = ()


@dataclass
class Segment:
    words: List[str]
    pipe_next: bool = False
    raw: str = ""


@dataclass
class Effective:
    cmd: str
    args: List[str]
    sudo: bool = False
    via_xargs: bool = False
    bare_env: bool = False


# ------------------------------------------------------------------------------------------------ tokenizer

def _balanced(text: str, i: int) -> Tuple[str, int]:
    """text[i:] starts just after `$(`: -> (inner text, index after the closing paren)."""
    depth, j = 1, i
    while j < len(text):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if not depth:
                return text[i:j], j + 1
        j += 1
    return text[i:], len(text)


def tokenize(text: str) -> Tuple[List[Segment], List[str]]:
    segs: List[Segment] = []
    subs: List[str] = []
    words: List[str] = []
    cur: List[str] = []
    has = False
    q: Optional[str] = None
    start = 0  # raw start of the current segment
    i, n = 0, len(text)

    def end_word():
        nonlocal cur, has
        if has or cur:
            words.append("".join(cur))
        cur, has = [], False

    def end_seg(pipe: bool, at: int):
        nonlocal words, start
        end_word()
        if words:
            segs.append(Segment(words, pipe, text[start:at].strip()))
        words = []
        start = at + 1

    while i < n:
        c = text[i]
        if q == "'":
            if c == "'":
                q = None
            else:
                cur.append(c)
            i += 1
            continue
        if q == '"':
            if c == '"':
                q = None
            elif c == "\\" and i + 1 < n:
                cur.append(text[i + 1])
                i += 2
                continue
            elif text.startswith("$(", i) and not text.startswith("$((", i):
                inner, i = _balanced(text, i + 2)
                subs.append(inner)
                cur.append("$(" + inner + ")")
                continue
            elif c == "`":
                j = text.find("`", i + 1)
                j = n if j < 0 else j
                subs.append(text[i + 1:j])
                cur.append(text[i:j + 1])
                i = j + 1
                continue
            else:
                cur.append(c)
            i += 1
            continue
        if c in "'\"":
            q, has = c, True
            i += 1
        elif c == "\\":
            if i + 1 < n and text[i + 1] != "\n":
                cur.append(text[i + 1])
                has = True
            i += 2
        elif text.startswith("$(", i) and not text.startswith("$((", i):
            inner, i = _balanced(text, i + 2)
            subs.append(inner)
            cur.append("$(" + inner + ")")
        elif c == "`":
            j = text.find("`", i + 1)
            j = n if j < 0 else j
            subs.append(text[i + 1:j])
            cur.append(text[i:j + 1])
            i = j + 1
        elif c in " \t\r":
            end_word()
            i += 1
        elif c in ";\n":
            end_seg(False, i)
            i += 1
        elif c == "|":
            if text.startswith("||", i):
                end_seg(False, i)
                i += 2
            else:
                end_seg(True, i)
                i += 1
        elif c == "&":
            prev = text[i - 1] if i else ""
            if prev in "<>" or (text[i + 1:i + 2] == ">" and not cur):
                cur.append(c)
                i += 1
            elif text.startswith("&&", i):
                end_seg(False, i)
                i += 2
            else:
                end_seg(False, i)
                i += 1
        elif c in "()":
            end_seg(False, i)
            i += 1
        else:
            cur.append(c)
            i += 1
    end_seg(False, n)
    return segs, subs


# ------------------------------------------------------------------------------------------------- resolving

_ASSIGN = re.compile(r"^[A-Za-z_]\w*=")
_PASS_THROUGH = {"env", "nohup", "time", "command", "exec", "nice", "stdbuf", "timeout", "setsid", "ionice", "builtin",
                 "winpty", "chrt", "taskset"}
_FLAG_VALUE = {"timeout": 1, "nice": 0}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish"}
_PS = {"powershell", "pwsh"}
_INTERPRETERS = re.compile(r"^(?:python[0-9.]*|pythonw|py|pypy[0-9.]*|ipython[0-9.]*|node|nodejs|deno|bun|perl|ruby|php|lua|rscript)$")


def _canon(word: str) -> str:
    w = word.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return w[:-4] if w.endswith(".exe") else w


def effective(words: List[str]) -> Optional[Effective]:
    """The command a simple command actually runs, after VAR=x, env/time/nohup/timeout, sudo and xargs."""
    i, sudo, xargs, saw_env = 0, False, False, False
    while i < len(words):
        w = words[i]
        base = _canon(w)
        if _ASSIGN.match(w) or w in ("{", "}", "!", "do", "then", "else", "fi", "done"):
            i += 1
        elif base in ("sudo", "doas", "pkexec", "runas"):
            sudo = True
            i += 1
            while i < len(words) and words[i].startswith("-"):
                i += 2 if words[i] in ("-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U") else 1
        elif base == "xargs":
            xargs = True
            i += 1
            while i < len(words) and words[i].startswith("-"):
                i += 2 if words[i] in ("-I", "-n", "-P", "-L", "-d", "-E", "-s") else 1
        elif base in _PASS_THROUGH:
            saw_env = saw_env or base == "env"
            i += 1
            while i < len(words) and (words[i].startswith("-") or _ASSIGN.match(words[i]) or
                                      (base in ("timeout", "nice") and re.match(r"^[0-9.]+[smhd]?$", words[i]))):
                i += 1
        else:
            return Effective(base, words[i + 1:], sudo, xargs)
    if saw_env:
        return Effective("env", [], sudo, xargs, bare_env=True)
    return Effective("", [], sudo, xargs) if sudo else None


def _flag_cluster(args: List[str], letters: str, longs: Sequence[str] = ()) -> bool:
    for a in args:
        if a.startswith("--"):
            if a.lower() in longs:
                return True
        elif a.startswith("-") and len(a) > 1 and any(ch in a[1:] for ch in letters):
            return True
    return False


def _positional(args: List[str]) -> List[str]:
    out, after = [], False
    for a in args:
        if a == "--":
            after = True
        elif after or not a.startswith("-"):
            out.append(a)
    return out


def flatten(command: str, depth: int = 0) -> Tuple[List[Segment], List[Finding]]:
    """Every simple command in the text, including those inside $(...), backticks, `sh -c`, eval, ssh and sudo."""
    if depth > MAX_DEPTH:
        return [], [Finding("shell-nesting-too-deep", "command nesting is too deep to review", "shell")]
    segs, subs = tokenize(command)
    out, findings = list(segs), []
    nested: List[str] = list(subs)
    for s in segs:
        e = effective(s.words)
        if not e:
            continue
        a = e.args
        if e.cmd in _SHELLS or e.cmd in _PS:
            for k, x in enumerate(a):
                if re.match(r"^-[A-Za-z]*c[A-Za-z]*$", x, re.I) or x.lower() in ("-command", "/c", "/k"):
                    if k + 1 < len(a):
                        nested.append(" ".join(a[k + 1:]))
                    break
        elif e.cmd == "eval":
            nested.append(" ".join(a))
        elif e.cmd == "find":
            k = 0
            while k < len(a):
                if a[k] in ("-exec", "-execdir", "-ok", "-okdir"):
                    j = k + 1
                    while j < len(a) and a[j] not in (";", "+"):
                        j += 1
                    nested.append(" ".join(shlex.quote(w) for w in a[k + 1:j]))
                    k = j
                k += 1
        elif e.cmd == "ssh":
            pos = []
            k = 0
            while k < len(a):
                if a[k].startswith("-"):
                    k += 2 if a[k] in ("-p", "-i", "-l", "-o", "-J", "-F", "-L", "-R", "-D", "-b", "-c", "-E") else 1
                else:
                    pos.append(" ".join(a[k:]))
                    break
            if pos and " " in pos[0]:
                nested.append(pos[0].split(" ", 1)[1])
        elif e.cmd in ("su",) and "-c" in a and a.index("-c") + 1 < len(a):
            nested.append(a[a.index("-c") + 1])
    for inner in nested:
        s2, f2 = flatten(inner, depth + 1)
        out += s2
        findings += f2
    return out, findings


# ---------------------------------------------------------------------------------------------------- rules

_DOWNLOADERS = {"curl", "wget", "fetch", "iwr", "invoke-webrequest", "http", "https", "aria2c", "lwp-request"}
_DECODERS = {"base64", "xxd", "openssl", "gunzip", "zcat", "unzip"}
_REMOTE_EXEC = re.compile(
    r"(?:\bsource|\beval|\b(?:ba|z|da|k)?sh|\bpython[0-9.]*|\bperl|\bruby|\bnode)\b[^\n;|&]*?(?:<\(|\$\(|`)\s*"
    r"(?:curl|wget|iwr|invoke-webrequest)\b", re.I)
_FORK_BOMB = re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")
_RM = {"rm", "rmdir", "unlink", "del", "erase", "rd", "remove-item", "ri", "srm", "wipe"}
_DISK = re.compile(r"^(?:mkfs(?:\.\w+)?|mke2fs|fdisk|sfdisk|cfdisk|parted|wipefs|diskpart|format|cryptsetup|blkdiscard)$")
_GLOB_DANGER = {".", "..", "*", ".*", "./", "../", "./*", "../*", "~", "~/", "~/*", "/", "/*", "$home", "${home}", "$home/*",
                "${home}/*"}
_INLINE_RISK = re.compile(r"shutil\.rmtree|rmtree|os\.system|os\.(?:remove|unlink|rmdir)|subprocess|\bsocket\b|urllib|requests\.|"
                          r"http\.client|\bexecSync\b|child_process|fs\.rm|fs\.unlink|rimraf|Remove-Item|Invoke-WebRequest|"
                          r"\bsystem\s*\(|\bexec\s*\(|\bqx\b|popen|\bspawn\b|File::Path|"
                          # perl / ruby / php one-liners: unlink glob "/*", FileUtils.rm_rf, File.delete, %x(...), `...`
                          r"\bunlink\b|\brmdir\b|\brmtree\b|FileUtils\.|\brm_r|File\.(?:delete|unlink)|Dir\.(?:rmdir|delete|unlink)|"
                          r"\bsystem\s+[\"'$]|\bexec\s+[\"'$]|\bKernel\.|\bIO\.popen|\bshell_exec\b|\bpassthru\b")
_SHELL_OUT = re.compile(r"`|%x[({\[]")  # perl / ruby / php backticks and %x(...) run a shell command
_INLINE_FLAG = {"-c", "-e", "-r", "--eval", "-command", "-p", "--print"}
_INLINE_CRED = re.compile(r"\.ssh\b|\.aws\b|id_rsa|id_ed25519|/etc/shadow|\.netrc|\.pgpass|\.git-credentials|\.env\b|credentials\.json", re.I)
_GIT_VALUE_FLAGS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}


def _strictly_under(norm: str, roots: Sequence[str]) -> bool:
    return any(norm.startswith(r.rstrip("/") + "/") for r in roots if r.rstrip("/"))


def _is_glob_danger(raw: str) -> bool:
    return raw.strip("\"'").replace("\\", "/").lower() in _GLOB_DANGER


def _check_delete(cmd: str, args: List[str], e: Effective, ctx: ShellContext, out: List[Finding]) -> None:
    lower = [a.lower() for a in args]
    ps = cmd in ("remove-item", "ri")
    recursive = (_flag_cluster(args, "rR", ("--recursive",)) if not ps else any(a.startswith("-rec") for a in lower)) \
        or cmd in ("rmdir", "rd") and "/s" in lower
    if "--no-preserve-root" in lower:
        out.append(Finding("shell-rm-no-preserve-root", "--no-preserve-root removes the filesystem root guard", "shell"))
    if cmd in ("shred", "srm", "wipe"):
        out.append(Finding("shell-destructive-command", f"`{cmd}` destroys data irrecoverably", "shell"))
    if e.via_xargs and recursive:
        out.append(Finding("shell-rm-unscoped-xargs", "recursive delete over piped targets cannot be scoped", "shell"))
    for raw in _positional(args):
        if raw.startswith("/") and cmd in ("del", "erase", "rd", "rmdir") and len(raw) <= 3:
            continue  # cmd.exe switch such as /s /q
        n = paths.normalize(raw, ctx.cwd, ctx.home)
        if _is_glob_danger(raw) or (n and paths.is_protected_path(n) and not _strictly_under(n, ctx.write_roots)):
            out.append(Finding("shell-rm-protected-target", f"delete of protected or whole-tree target `{raw}`", "shell"))
        elif n is None:
            if recursive:
                out.append(Finding("shell-rm-unresolvable-target", f"recursive delete of unresolved path `{raw}`", "shell"))
        elif ctx.write_roots and not _strictly_under(n, ctx.write_roots):
            out.append(Finding("shell-delete-outside-scope", f"delete outside the agent's write roots: `{raw}`", "shell"))


def _check_find(args: List[str], ctx: ShellContext, out: List[Finding]) -> None:
    lower = [a.lower() for a in args]
    deleting = "-delete" in lower or any(
        a in ("-exec", "-execdir", "-ok", "-okdir") and k + 1 < len(args) and _canon(args[k + 1]) in _RM | {"shred", "mv"}
        for k, a in enumerate(lower))
    if not deleting:
        return
    starts = []
    for a in args:
        if a.startswith(("-", "(", "!")):
            break
        starts.append(a)
    for raw in starts or ["."]:
        n = paths.normalize(raw, ctx.cwd, ctx.home)
        if _is_glob_danger(raw) and raw not in (".", "./") or (n and paths.is_protected_path(n) and not
                                                              (n in ctx.write_roots or _strictly_under(n, ctx.write_roots))):
            out.append(Finding("shell-find-delete-protected", f"find -delete / -exec rm over protected path `{raw}`", "shell"))
        elif n is None or (ctx.write_roots and not (n in ctx.write_roots or _strictly_under(n, ctx.write_roots))):
            out.append(Finding("shell-delete-outside-scope", f"find delete outside the agent's write roots: `{raw}`", "shell"))


def _git_sub(args: List[str]) -> Tuple[str, List[str]]:
    i = 0
    while i < len(args):
        if args[i] in _GIT_VALUE_FLAGS:
            i += 2
        elif args[i].startswith("-"):
            i += 1
        else:
            return args[i], args[i + 1:]
    return "", []


_PROTECTED_BRANCH = re.compile(r"^(?:main|master|trunk|develop|dev|prod|production|release|stable|live|gh-pages)$|"
                               r"^(?:release|hotfix|prod|production)/", re.I)
_PUSH_VALUE_FLAGS = {"--repo", "--receive-pack", "--exec", "-o", "--push-option", "--recurse-submodules"}


def _protected_branch(ref: str) -> bool:
    name = re.sub(r"^refs/heads/", "", ref.lstrip("+"))
    return bool(_PROTECTED_BRANCH.search(name))


def _push_targets(rest: List[str]) -> Optional[List[str]]:
    """Remote branch names a `git push` writes, or None when the command does not name them (current branch,
    --all, a matching push): a guard cannot know those, so it treats them as protected."""
    pos, k = [], 0
    while k < len(rest):
        r = rest[k]
        if r in ("--all", "--branches", "--mirror", "--tags") or r.lower().startswith("--force-with-lease=") and \
                _protected_branch(r.split("=", 1)[1].split(":", 1)[0]):
            return None
        if r in _PUSH_VALUE_FLAGS:
            k += 2
            continue
        if not r.startswith("-"):
            pos.append(r)
        k += 1
    refspecs = pos[1:]
    if not refspecs:
        return None
    return [s.rsplit(":", 1)[-1] if ":" in s else s for s in refspecs]


def _whole_tree(rest: List[str]) -> bool:
    return any(p in (".", "./", ":/", "*") for p in rest)


def _restores_worktree(rest: List[str]) -> bool:
    """`git restore` touches the working tree unless only --staged / -S is given (that one just unstages)."""
    staged = worktree = False
    for r in rest:
        if r in ("--staged",) or re.fullmatch(r"-[A-Za-z]*S[A-Za-z]*", r):
            staged = True
        if r in ("--worktree",) or re.fullmatch(r"-[A-Za-z]*W[A-Za-z]*", r):
            worktree = True
    return worktree or not staged


def _check_git(args: List[str], out: List[Finding]) -> None:
    sub, rest = _git_sub(args)
    low = [r.lower() for r in rest]
    if sub == "push":
        refspec_force = any(r.startswith(("+", ":")) and len(r) > 1 for r in rest if not r.startswith("-"))
        if "--force" in low or "-f" in low or "--mirror" in low or "--delete" in low or "-d" in low or refspec_force \
                or any(r.startswith("--force=") for r in low) or (len(low) and any(
                    r.startswith("-") and not r.startswith("--") and "f" in r[1:] for r in low)):
            out.append(Finding("shell-git-force-push", "force / mirror / delete push can destroy remote history", "shell"))
        elif any(r.startswith(("--force-with-lease", "--force-if-includes")) for r in low):
            targets = _push_targets(rest)
            if targets is None or any(_protected_branch(t) for t in targets):
                out.append(Finding("shell-git-force-push", "--force-with-lease on a protected or unnamed branch "
                                   "still rewrites its remote history", "shell"))
    elif sub == "reset" and "--hard" in low:
        out.append(Finding("shell-git-reset-hard", "git reset --hard discards uncommitted work", "shell"))
    elif sub == "clean" and _flag_cluster(rest, "f", ("--force",)):
        out.append(Finding("shell-git-clean", "git clean -f deletes untracked files", "shell"))
    elif sub in ("checkout", "restore") and _whole_tree(rest) and (sub == "checkout" or _restores_worktree(rest)):
        out.append(Finding("shell-git-discard-all", f"git {sub} . discards every uncommitted change", "shell"))
    elif sub == "branch" and ("-D" in rest or "--force" in low and "-d" in low):
        out.append(Finding("shell-git-branch-delete", "forced branch deletion", "shell"))
    elif sub in ("filter-branch", "filter-repo"):
        out.append(Finding("shell-git-history-rewrite", "history rewrite", "shell"))
    elif sub == "reflog" and rest[:1] in (["expire"], ["delete"]):
        out.append(Finding("shell-git-history-rewrite", "reflog expiry removes recovery points", "shell"))
    elif sub == "gc" and any(r.startswith("--prune=now") for r in low):
        out.append(Finding("shell-git-history-rewrite", "gc --prune=now removes recovery points", "shell"))
    elif sub == "config" and any(re.search(r"core\.hookspath|credential\.helper|insteadof", r) for r in low):
        out.append(Finding("shell-git-config-hijack", "git config key that redirects hooks, credentials or URLs", "shell"))
    if sub in ("commit", "push", "merge", "rebase", "am", "cherry-pick") and (
            "--no-verify" in low or "--no-gpg-sign" in low or (sub == "commit" and "-n" in low)):
        out.append(Finding("shell-git-bypass-hooks", "bypasses commit / push hooks or signing", "shell"))


def _check_write_dest(cmd: str, args: List[str], ctx: ShellContext, out: List[Finding]) -> None:
    targets: List[str] = []
    pos = _positional(args)
    if cmd in ("cp", "mv", "install", "rsync", "ln") and pos:
        targets = [pos[-1]]
        if "-t" in args and args.index("-t") + 1 < len(args):
            targets = [args[args.index("-t") + 1]]
    elif cmd in ("tee", "touch", "mkdir", "truncate", "mkfifo"):
        targets = pos
    elif cmd in ("sed", "perl") and any(a.startswith("-i") for a in args):
        targets = pos[1:] if cmd == "sed" else pos
    elif cmd == "dd":
        targets = [a[3:] for a in args if a.startswith("of=")]
    for raw in targets:
        _judge_write_target(raw, ctx, out)


def _judge_write_target(raw: str, ctx: ShellContext, out: List[Finding]) -> None:
    if not raw or raw.startswith("&") or raw.strip("\"'") in ("-", "/dev/null", "/dev/stdout", "/dev/stderr"):
        return
    n = paths.normalize(raw, ctx.cwd, ctx.home)
    if n is None:
        if ctx.write_roots:
            out.append(Finding("shell-write-unresolvable", f"write target `{raw}` holds an unresolved variable", "shell"))
        return
    if paths.is_protected_path(n) and not _strictly_under(n, ctx.write_roots):
        out.append(Finding("shell-write-protected-path", f"write to protected path `{raw}`", "shell"))
    elif ctx.write_roots and not (_strictly_under(n, ctx.write_roots) or n in ctx.write_roots):
        out.append(Finding("shell-write-outside-scope", f"write outside the agent's write roots: `{raw}`", "shell"))


def _is_env_dump(e: Effective) -> bool:
    cmd, args = e.cmd, e.args
    if e.bare_env or cmd == "printenv":
        return True
    if cmd == "set":
        return not args
    if cmd == "export":
        return not _positional(args) or "-p" in args
    if cmd in ("declare", "typeset"):
        return any(a in ("-x", "-p", "-px", "-xp") for a in args) and not _positional(args)
    if cmd == "compgen":
        return any(a in ("-e", "-v") for a in args)
    return False


def _check_segment(seg: Segment, nxt: Optional[Segment], ctx: ShellContext, out: List[Finding]) -> None:
    e = effective(seg.words)
    if e and e.sudo:
        out.append(Finding("shell-privilege-escalation", "sudo / su / doas escalates privileges", "shell"))
    # credential paths and secret variables in any word (arguments, redirects, assignments' values)
    for w in seg.words:
        cand = w.split("=", 1)[1] if re.match(r"^(--?[\w-]+|of|if)=", w) else w
        cand = cand.lstrip("<>&0123456789") or cand
        if cand and not re.search(r"\s", cand) and paths.is_credential_path(cand):
            out.append(Finding("shell-credential-path", f"touches a credential file: `{cand}`", "shell"))
        for m in re.finditer(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", w):
            name = m.group(1)
            if SECRET_ENV_NAME.search(name) and name not in ctx.allow_env_refs:
                out.append(Finding("shell-secret-env-reference", f"references secret variable ${name}", "shell"))
    # redirect targets
    for k, w in enumerate(seg.words):
        m = re.match(r"^(?:\d*|&)>>?\|?(.*)$", w)
        if m and not w.startswith("&>&"):
            target = m.group(1) or (seg.words[k + 1] if k + 1 < len(seg.words) else "")
            _judge_write_target(target, ctx, out)
    if not e or not e.cmd:
        return
    cmd, args = e.cmd, e.args
    if _is_env_dump(e):
        out.append(Finding("shell-env-dump", "dumps the environment, which holds secrets", "shell"))
    _check_write_dest(cmd, args, ctx, out)
    if cmd in _RM:
        _check_delete(cmd, args, e, ctx, out)
    elif cmd == "find":
        _check_find(args, ctx, out)
    elif cmd == "dd" or _DISK.match(cmd):
        if cmd == "dd":
            for a in args:
                if a.startswith("of=/dev/") and a[3:] not in ("/dev/null", "/dev/stdout", "/dev/stderr"):
                    out.append(Finding("shell-disk-write", f"raw write to device `{a[3:]}`", "shell"))
        else:
            out.append(Finding("shell-disk-write", f"`{cmd}` repartitions or formats storage", "shell"))
    elif cmd in ("chmod", "chown", "chgrp"):
        if _flag_cluster(args, "R", ("--recursive",)):
            pos = _positional(args)
            risky_mode = cmd == "chmod" and any(re.fullmatch(r"[0-7]?777|a\+rwx|o\+w|ugo\+rwx", p) for p in pos)
            targets = pos[1:] if pos else []
            bad = [t for t in targets if _is_glob_danger(t) or (paths.normalize(t, ctx.cwd, ctx.home) or "").count("/") <= 1]
            if risky_mode or bad:
                out.append(Finding("shell-chmod-recursive-unsafe", "recursive permission change on a broad or protected tree", "shell"))
        if cmd == "chmod" and any(re.fullmatch(r"[ugoa]*\+s|[2467][0-7]{3}", a) for a in _positional(args)):
            out.append(Finding("shell-setuid", "sets a setuid / setgid bit", "shell"))
    elif cmd == "git":
        _check_git(args, out)
    elif cmd in ("shutdown", "reboot", "halt", "poweroff", "killall5") or (cmd == "init" and args[:1] in (["0"], ["6"])) \
            or (cmd == "systemctl" and args[:1] in (["poweroff"], ["reboot"], ["halt"])):
        out.append(Finding("shell-system-shutdown", "stops or reboots the machine", "shell"))
    elif cmd == "kill" and any(a in ("-1", "1") for a in _positional(args) + [a for a in args if a == "-1"]):
        out.append(Finding("shell-mass-kill", "kill -1 / pid 1 signals every process", "shell"))
    elif cmd == "crontab" and "-l" not in args:
        out.append(Finding("shell-persistence", "edits the scheduler", "shell"))
    elif cmd == "systemctl" and args[:1] in (["enable"], ["link"]):
        out.append(Finding("shell-persistence", "enables a service at boot", "shell"))
    elif cmd == "schtasks" and any(a.lower() == "/create" for a in args):
        out.append(Finding("shell-persistence", "creates a scheduled task", "shell"))
    elif cmd == "launchctl" and args[:1] in (["load"], ["bootstrap"]):
        out.append(Finding("shell-persistence", "loads a launch agent", "shell"))
    elif cmd in ("docker", "podman", "nerdctl") and args[:1] in (["run"], ["create"], ["exec"]):
        joined = " ".join(args)
        if "--privileged" in args or "--pid=host" in args or re.search(
                r"(?:-v|--volume|--mount)[ =][^ ]*(?:^|[ :=,])(?:/|/etc|/root|/var/run/docker\.sock)(?:[: ,]|$)", joined):
            out.append(Finding("shell-container-escape", "container flags that expose the host", "shell"))
    elif cmd == "terraform" and args[:1] == ["destroy"] or cmd == "pulumi" and args[:1] == ["destroy"]:
        out.append(Finding("shell-infra-destructive", "infrastructure destroy", "shell"))
    elif cmd == "kubectl" and args[:1] == ["delete"] and ("--all" in args or "-A" in args or any(
            a in ("ns", "namespace", "namespaces", "node", "nodes", "pv") for a in args[1:2])):
        out.append(Finding("shell-infra-destructive", "bulk kubectl delete", "shell"))
    elif cmd == "aws" and ((args[:2] == ["s3", "rm"] and "--recursive" in args) or (args[:2] == ["s3", "rb"] and "--force" in args)):
        out.append(Finding("shell-infra-destructive", "bulk bucket delete", "shell"))
    elif cmd in ("gcloud", "az") and "delete" in args and ("--quiet" in args or "-q" in args or "--yes" in args or "-y" in args):
        out.append(Finding("shell-infra-destructive", "unattended cloud resource delete", "shell"))
    elif cmd == "gh" and args[:2] in (["repo", "delete"], ["release", "delete"]):
        out.append(Finding("shell-infra-destructive", "deletes a hosted repository or release", "shell"))
    elif (cmd == "npm" and args[:1] == ["publish"]) or (cmd == "twine" and args[:1] == ["upload"]) or \
            (cmd == "cargo" and args[:1] == ["publish"]) or (cmd == "gem" and args[:1] == ["push"]):
        out.append(Finding("shell-publish", "publishes a package outside the machine", "shell"))
    elif _INTERPRETERS.match(cmd) and any(
            a.lower() in _INLINE_FLAG or re.fullmatch(r"-[A-Za-z]{1,4}", a) and ("e" in a[1:] or "c" in a[1:])
            for a in args):  # -c, -e and clusters such as perl -le / -ne / -pe, ruby -ne, python -Bc
        code = " ".join(args)
        if _INLINE_CRED.search(code):
            out.append(Finding("shell-inline-credential-read", "inline code reads a credential path", "shell"))
        if _INLINE_RISK.search(code) or (cmd in ("perl", "ruby", "php") and _SHELL_OUT.search(code)):
            out.append(Finding("shell-inline-interpreter-risk", "inline code deletes, spawns processes or opens sockets", "shell"))
    # remote code: producer | consumer
    if seg.pipe_next and nxt:
        prod = e.cmd
        ne = effective(nxt.words)
        cons = ne.cmd if ne else ""
        if (prod in _DOWNLOADERS or prod in _DECODERS or prod in ("cat", "echo", "printf")) and \
                (cons in _SHELLS or cons in _PS or _INTERPRETERS.match(cons or "")):
            if prod in _DOWNLOADERS or prod in _DECODERS:
                out.append(Finding("shell-pipe-to-interpreter", f"`{prod} | {cons}` runs fetched or decoded text as code", "shell"))


_SAVE_FLAGS = {"curl": ("-o", "--output"), "wget": ("-O", "--output-document"), "aria2c": ("-o", "--out"),
               "iwr": ("-outfile",), "invoke-webrequest": ("-outfile",), "fetch": ("-o",), "http": ("--output", "-o")}


def _url_basename(args: List[str]) -> List[str]:
    return [re.sub(r"[?#].*$", "", a).rstrip("/").rsplit("/", 1)[-1] for a in args if re.match(r"(?i)^(?:https?|ftp)://", a)]


def _downloaded(e: Effective, seg: Segment) -> List[str]:
    """Files a downloader segment writes: -o / -O / --output / -OutFile, a redirect, or wget's / curl -O's URL name."""
    flags = _SAVE_FLAGS.get(e.cmd)
    if not flags:
        return []
    out, args = [], e.args
    for k, a in enumerate(args):
        low = a.lower()
        for f in flags:
            if (a == f or f == "-outfile" and low == f) and k + 1 < len(args):  # curl -o and -O differ; PS is caseless
                out.append(args[k + 1])
            elif f.startswith("--") and a.startswith(f + "="):
                out.append(a.split("=", 1)[1])
            elif not f.startswith("--") and len(f) == 2 and a.startswith(f) and len(a) > 2 and e.cmd != "wget":
                out.append(a[2:])  # curl -ox.sh
    if e.cmd == "curl":  # clusters: -sSo x.sh, -sSLO
        out += [args[k + 1] for k, a in enumerate(args[:-1]) if re.fullmatch(r"-[A-Za-z]+o", a) and a != "-o"]
    if (e.cmd == "wget" and not out) or (e.cmd == "curl" and any(
            a == "--remote-name" or re.fullmatch(r"-[A-Za-z]*O[A-Za-z]*", a) for a in args)):
        out += _url_basename(args)
    for k, w in enumerate(seg.words):
        m = re.match(r"^>>?(.*)$", w)
        if m:
            out.append(m.group(1) or (seg.words[k + 1] if k + 1 < len(seg.words) else ""))
    return [o for o in out if o]


def _executed(e: Effective, seg: Segment) -> List[str]:
    """Files a segment runs: a command word that is a path (`./x.sh`), or the script of sh / bash / python / source."""
    raw = seg.words[len(seg.words) - len(e.args) - 1] if len(seg.words) > len(e.args) else ""
    out = [raw] if ("/" in raw or "\\" in raw) else []
    if e.cmd in _SHELLS or e.cmd in _PS or e.cmd in ("source", ".") or _INTERPRETERS.match(e.cmd):
        pos = [a for a in e.args if not a.startswith("-")]
        out += pos[:1]
    return out


def _check_download_exec(segs: List[Segment], ctx: ShellContext, out: List[Finding]) -> None:
    """`curl -o x.sh URL && chmod +x x.sh && ./x.sh`: a file fetched and then run is remote code, like `curl | sh`."""
    def key(p: str) -> str:
        return paths.normalize(p, ctx.cwd, ctx.home) or p

    fetched = set()
    for seg in segs:
        e = effective(seg.words)
        if e and e.cmd:
            fetched.update(key(f) for f in _downloaded(e, seg))
    if not fetched:
        return
    for seg in segs:
        e = effective(seg.words)
        if e and e.cmd and any(key(x) in fetched for x in _executed(e, seg)):
            out.append(Finding("shell-download-exec", "runs a file it just downloaded (download, chmod +x, run)", "shell"))
            return


def check_shell(command: str, ctx: Optional[ShellContext] = None) -> List[Finding]:
    ctx = ctx or ShellContext()
    out: List[Finding] = []
    if _FORK_BOMB.search(command):
        out.append(Finding("shell-fork-bomb", "fork bomb", "shell"))
    if _REMOTE_EXEC.search(command):
        out.append(Finding("shell-pipe-to-interpreter", "executes the output of a download", "shell"))
    segs, findings = flatten(command)
    out += findings
    for k, seg in enumerate(segs):
        nxt = segs[k + 1] if seg.pipe_next and k + 1 < len(segs) else None
        _check_segment(seg, nxt, ctx, out)
    _check_download_exec(segs, ctx, out)
    seen, uniq = set(), []
    for f in out:
        key = (f.rule, f.reason)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq
