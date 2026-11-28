---
name: resume
description: Continue authzcov work from the newest progress shard without re-pasting the conversation. Use when the user types /resume (optionally with a focus).
---

# Resume authzcov session

Args = optional focus (e.g. "KAN-102", "only step 4"). Empty = follow the shard.

1. Read `CLAUDE.md`, the newest shard (`ls docs/progress/2*.md | tail -1`) and `.claude/delegation-rules.md`. Grep `docs/PLAN.md` on demand only.
2. The shard's "Next" list is the approved plan: start it, do NOT do the "reply and wait" step. Exception: items under
   "Waiting on the owner" are not approved. Ask about those in ≤ 5 lines first (use AskUserQuestion), and work on
   other items meanwhile.
3. Roles (rules unchanged): Sonnet orchestrates and commits; `implementer`/`fixer` (Sonnet) write, `reviewer`/`validator`
   (Haiku) check; Opus only as a fresh `general-purpose` agent for security/architecture, with a note in `notes/<KEY>-opus.md`.
   One reviewer pass and one fixer per ticket. 🔒 packages: tests first. `make check` green before "done".
   Contracts in `notes/<KEY>-contract.md`, agents reply ≤ 10 lines. Never poll background agents.
4. Conventional Commits with the Jira key, co-author line. Push after the secrets/HAR scan only with owner approval
   in this session (auto-mode may deny it; then ask).
5. Jira in one batch at the end: comment + transition 31 (W trakcie weryfikacji); Gotowe only when the parent AC is fully met.
6. At ~100k context: write a new shard (decisions, done, next, waiting-on-owner, gotchas; no URLs), commit it, tell the owner, stop.
