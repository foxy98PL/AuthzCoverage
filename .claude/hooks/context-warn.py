#!/usr/bin/env python3
"""PostToolUse: warn when the session's context passes 80k, then every 20k from 100k on.

Reads the latest assistant usage from the transcript (tail only). Silent otherwise. One warning per
threshold, tracked in a small state file per session/agent.
"""
import json
import os
import sys
import tempfile

FIRST = 80_000
RESTART = 100_000
STEP = 20_000


def last_context(path: str) -> int:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 400_000))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return 0
    for line in reversed(lines):
        if '"usage"' not in line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        u = (d.get("message") or {}).get("usage") or {}
        if u:
            return (u.get("input_tokens", 0) + u.get("cache_read_input_tokens", 0)
                    + u.get("cache_creation_input_tokens", 0))
    return 0


def main() -> None:
    data = json.load(sys.stdin)
    agent = data.get("agent_id") or ""
    path = data.get("agent_transcript_path") or ("" if agent else data.get("transcript_path") or "")
    ctx = last_context(path) if path else 0
    if ctx < FIRST:
        print("{}")
        return
    level = 0 if ctx < RESTART else 1 + (ctx - RESTART) // STEP
    key = f"{data.get('session_id', 'x')}-{agent or 'main'}".replace("/", "_")
    state = os.path.join(tempfile.gettempdir(), f"authzcov-ctx-{key}")
    try:
        last = int(open(state).read())
    except (OSError, ValueError):
        last = -1
    if level <= last:
        print("{}")
        return
    with open(state, "w") as f:
        f.write(str(level))
    who = "orchestrator" if not agent else "subagent"
    if level == 0:
        msg = f"[context-warn] {who} context ≈{ctx // 1000}k. Plan to wrap up; restart point is ~100k."
    else:
        msg = (f"[context-warn] {who} context ≈{ctx // 1000}k (≥100k). Per .claude/delegation-rules.md §0: "
               "finish the current step, write a new docs/progress shard, batch Jira, tell the owner, stop."
               if not agent else
               f"[context-warn] subagent context ≈{ctx // 1000}k. Finish the current step, write your notes "
               "file and return STATUS partial if the task is not nearly done.")
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": msg}}))


if __name__ == "__main__":
    main()
