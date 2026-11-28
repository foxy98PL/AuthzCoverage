---
name: planner
description: Plan upcoming authzcov orchestrator sessions as numbered files docs/sessions/session<N>.md (bug sessions session<N>.<k>.md) from the progress shard, Jira KAN and the context budget. Use when the user types /planner (optionally with a scope).
---

# Plan sessions

Args = optional scope (e.g. "KAN-104..KAN-110", "bugs only", "replan from session4"). Empty = plan all open KAN work.

1. Launch the `planner` agent (Opus) in the foreground with a prompt of ≤ 10 lines: the scope from the args, the
   newest shard path, and any owner decisions made in this conversation that aren't in the shard yet. Don't read
   Jira or the session files yourself: the agent does it, so the issue echoes stay out of this context.
2. When it returns, run `git diff --stat -- docs/sessions` and `ls docs/sessions/session*.md | sort -V`, and skim
   only the session /start will pick up next.
3. Tell the owner in ≤ 8 lines: sessions written, the next session's goal, open owner decisions. Commit
   `docs(sessions): plan <range>` per CLAUDE.md (secrets scan first); push on your own judgment.
