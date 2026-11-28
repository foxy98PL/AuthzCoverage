#!/usr/bin/env python3
"""PreToolUse(Bash): trim output of unpiped `go test` / `make <target>` runs, keeping the exit code.

Drops `ok  pkg` and `?   pkg [no test files]` lines and keeps the last N lines. Commands that already
pipe, redirect or chain are left alone (that is the opt-out).
"""
import json
import re
import sys

PATTERN = re.compile(r"^(go test|make (check|test|e2e|fuzz|eval[\w-]*))(\s|$)")
OPAQUE = re.compile(r"[|<>;&`]|\$\(")
TAIL = {"go": 40, "make": 60}


def main() -> None:
    data = json.load(sys.stdin)
    tool_input = data.get("tool_input") or {}
    cmd = (tool_input.get("command") or "").strip()
    if not PATTERN.match(cmd) or OPAQUE.search(cmd) or "\n" in cmd:
        print("{}")
        return
    n = TAIL["go" if cmd.startswith("go ") else "make"]
    wrapped = (
        f"( {{ {cmd}; }} 2>&1 | grep -v -E '^(ok |\\?   )' | tail -n {n}; s=${{PIPESTATUS[0]}}; "
        f"echo \"[trim-output hook: ok-lines dropped, last {n} lines kept; exit $s]\"; exit $s )"
    )
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": {**tool_input, "command": wrapped},
        }
    }
    print(json.dumps(out))


if __name__ == "__main__":
    main()
