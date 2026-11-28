---
name: resume
description: Continue authzcov work from the newest progress shard without re-pasting the conversation. Use when the user types /resume (optionally with a focus).
---

# Resume authzcov session

Args = optional focus (e.g. "KAN-102", "only step 4"). Empty = follow the shard.

1. CLAUDE.md is already loaded. Read the newest shard (`ls docs/progress/2*.md | tail -1`) and
   `.claude/delegation-rules.md` (binding for models, agents, review, restarts, Jira). Grep `docs/PLAN.md` on demand only.
   Then the next session file: the first `docs/sessions/session*.md` (`sort -V`) whose Status isn't `done`
   (`docs/sessions/README.md`). Set a `planned` one to `active`.
2. The session file's work list (or, with no session left, the shard's "Next") is the approved plan: start it
   without asking. New Jira Bugs go into a bug session `session<N>.<k>.md` per the sessions README. Items under "Waiting on the owner" are
   decisions to make yourself: reason from the ticket, the code and the project rules, pick the option you can
   defend (reversible, smallest, consistent with PLAN.md), act, and record the decision and its reasoning in the
   Jira comment and the next shard so the owner can overrule it. Ask (AskUserQuestion, ≤ 5 lines) only when the
   action is irreversible or outward-facing beyond CLAUDE.md's allowances, or needs something you lack (credentials,
   docker, gh/cosign, a recording, repo settings). Security or architecture trade-offs follow
   delegation-rules §0 (Opus advisor), not a guess. Never: Done transitions, force-push, settings changes.
3. Push per CLAUDE.md (own judgment, after the secrets/HAR scan). Done (Gotowe) is the owner's move, never yours.
4. At the restart warning: write a new shard (decisions, done, next, waiting-on-owner, gotchas; no URLs; name the
   session file), set the session's Status (`done — shard <file>` if its list is finished), commit both,
   batch Jira, tell the owner, stop.
