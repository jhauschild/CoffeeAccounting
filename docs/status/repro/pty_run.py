"""Run a command in a real pseudo-terminal and answer its prompts (stand-in for `docker compose run --rm -it`).

    python docs/status/repro/pty_run.py --script '[["Username: ","alice"],["password","S3cret-pw"]]' -- CMD ARGS...

--script is a JSON list of [regex, reply] pairs, consumed in order: when the regex appears in the output not yet
matched, the reply plus a newline is typed. Everything the terminal shows (the transcript) is printed to stdout
after the run, so the caller can check that a hidden prompt did not echo the typed secret (a line-echoed answer
appears in the transcript, a getpass answer does not). --secret VALUE (repeatable) makes the script fail with exit
code 99 if the transcript contains that value. The child's exit code is returned (99 wins).
Standard library only (no pexpect).
"""

from __future__ import annotations

import argparse
import json
import os
import pty
import re
import select
import sys
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--script", default="[]")
    ap.add_argument("--secret", action="append", default=[])
    ap.add_argument("--timeout", type=float, default=60)
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    ns = ap.parse_args()
    cmd = ns.cmd[1:] if ns.cmd and ns.cmd[0] == "--" else ns.cmd
    steps = json.loads(ns.script)
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
    transcript = ""
    pos = 0
    deadline = time.time() + ns.timeout
    status = None
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                chunk = b""
            if not chunk:
                break
            transcript += chunk.decode("utf-8", "replace")
            if steps:
                pattern, reply = steps[0]
                m = re.search(pattern, transcript[pos:])
                if m:
                    pos += m.end()
                    steps.pop(0)
                    time.sleep(0.05)
                    os.write(fd, (reply + "\n").encode())
    if time.time() >= deadline:
        os.kill(pid, 9)
        print("\n[pty_run] timeout: child killed", file=sys.stderr)
    try:
        _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    code = os.waitstatus_to_exitcode(status) if status is not None else 1
    sys.stdout.write(transcript.replace("\r\n", "\n"))
    leaked = [s for s in ns.secret if s in transcript]
    if leaked:
        print(f"\n[pty_run] SECRET ECHOED in the terminal transcript: {len(leaked)} value(s)", file=sys.stderr)
        return 99
    if steps:
        print(f"\n[pty_run] {len(steps)} scripted prompt(s) never appeared", file=sys.stderr)
        return code or 98
    print(f"\n[pty_run] exit code {code}; no secret in transcript ({len(ns.secret)} checked)", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
