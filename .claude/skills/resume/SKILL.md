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
5. Before stopping do the end-of-session report in `.claude/delegation-rules.md` §9: docker eval of external apps,
   next-session impact check (replan if affected), append to `docs/SESSION_LOG.md` (write-only), and give the owner
   the token / cost / Pro-plan summary (cost as the per-agent table: agent, model, tokens, API cost).
6. Tooling and tags (owner request 2026-11-29). Before relying on them, check `command -v gh cosign docker`. A missing
   `gh` or `cosign` is installed user-local into `~/.local/bin` from the official release, with its checksum verified
   (no sudo here). `gh` still needs the owner's `gh auth login`; until then CI and release state cannot be read, so
   say so. When a session finishes a release-worthy set of work (the CHANGELOG section is complete, `make check`
   green), cut the tag per `docs/releasing.md`: pre-release `-rc.N` first, final tag after the rc verifies. The
   owner asked on 2026-11-29 for tags to be produced, so tag and push without asking, but never move or reuse a
   published tag.
