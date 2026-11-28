---
name: resume
description: Continue authzcov work from the newest progress shard without re-pasting the conversation. Use when the user types /resume (optionally with a focus).
---

# Resume authzcov session

Args = optional focus (e.g. "KAN-102", "only step 4"). Empty = follow the shard.

1. CLAUDE.md is already loaded. Read the newest shard (`ls docs/progress/2*.md | tail -1`) and
   `.claude/delegation-rules.md` (binding for models, agents, review, restarts, Jira). Grep `docs/PLAN.md` on demand only.
2. The shard's "Next" list is the approved plan: start it without asking. Items under "Waiting on the owner" are
   not approved: ask about them in ≤ 5 lines first (AskUserQuestion) and work on other items meanwhile.
3. Push per CLAUDE.md (own judgment, after the secrets/HAR scan). Done (Gotowe) is the owner's move, never yours.
4. At the restart warning: write a new shard (decisions, done, next, waiting-on-owner, gotchas; no URLs), commit it,
   batch Jira, tell the owner, stop.
