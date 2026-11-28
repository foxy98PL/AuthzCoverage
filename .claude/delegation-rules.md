# Delegation rules (orchestrator ↔ subagents)

Binding. Measurements behind each rule: `.claude/delegation-rationale.md` (grep it on demand, don't read at startup).

## 0. Models, restarts, review (owner decisions 2026-11-28)

- **Sonnet orchestrates** (implement → review → fix → commit → Jira). Never an Opus orchestrator.
- **Opus only for security or architecture decisions** (credentials, identity, tenancy, threat-model trade-offs,
  package/API design), or a security finding the Sonnet reviewer cannot settle: write the question with options to
  `notes/<KEY>-opus.md`, launch the `advisor` agent (Opus, starts at ~6k vs ~32k for `general-purpose`)
  pointed at it, or ask the owner.
- **Restart the orchestrator at ~150k tokens** (the hook warns at 120k; subagents warn at 80k, return at 100k):
  write a new progress shard (`docs/progress/README.md`), do the batched Jira updates (§7), tell the owner, stop.
  Local-only details (agent IDs, scratch paths) go to `notes/orchestrator-state.md`.
- **Review:** when a ticket goes In Review, append a row to `docs/REVIEW_QUEUE.md` and start a background
  `reviewer` (Sonnet, owner change 2026-11-28); the next ticket continues meanwhile. One reviewer pass, then one
  `fixer` for all findings F1…Fn; no second round. Leftover lows go to the Jira comment.
- **Skip the reviewer** for trivial tickets: config, docs, CI or message-text changes under ~30 changed lines
  outside 🔒 packages. Green `make check` + the orchestrator's own `git diff` look closes them; note "no agent
  review (trivial)" in the Jira comment.

## 1. Agent choice

- Lean agents in `.claude/agents/`: `implementer`, `fixer` (Sonnet), `validator` (Sonnet), `reviewer` (Sonnet), `jira` (Haiku),
  `advisor` (Opus, §0 questions only), `planner` (Opus, via `/planner`: writes `docs/sessions/`). Never `general-purpose` for work a lean agent covers.
- Run `make check` / `go test` **yourself** (the hook keeps output short). Use `validator` only for long or noisy
  runs: fuzz, eval, determinism diffs, multi-command scans.
- `subagent_type: fork` only when the task needs the whole conversation. Never fork to implement, fix or review.
- One ticket per agent. Parallel agents get disjoint directories; nobody touches go.mod/go.sum.

## 2. Prompt contract (≤ ~1.5k tokens ≈ 6,000 chars)

Pointers only: ticket ID + acceptance criteria (≤ 15 lines, or "read `notes/<KEY>-spec.md`"); base commit;
paths in scope and off-limits; applicable constraints, one line each; verify commands; report path
`notes/<KEY>-<role>.md`. Never paste file contents, diffs, test output or another agent's report — a fix task
gets "fix F1–F3 in `notes/<KEY>-review.md`". Over 1.5k needs a one-line reason (better: write it to `notes/`).

Reviewer input: `git diff <base>...HEAD -- <paths>` (or `git diff -- <paths>`) + the AC. It reads further code
only to check a specific suspicion, and writes F1…Fn (severity, file:line, failing scenario) to
`notes/<KEY>-review.md`.

Audits (done-readiness, verification, "is X still true") get the same scope as a review: per ticket the
commit(s) (`git show --stat <sha>`) or `git diff <base>...HEAD -- <paths>`, the AC, and a question list. Never
"no diff, explore": four unscoped Haiku audits cost 150 turns and 6.7M cache reads. Skip the audit for a ticket
that already had a reviewer pass; its review notes are the evidence.

## 3. Read hygiene (the biggest saving)

- No whole-file `cat`/`Read` over ~150 lines: `grep -n` the symbol, then `sed -n 'a,bp'` or Read with
  `offset`/`limit`. Whole files only when rewriting most of them.
- Don't re-read a file you just wrote or edited.
- Templates: read the structure (`grep -n '^func '`) and only the functions you copy.

## 4. Output hygiene

- Run `go test|vet|build …`, `golangci-lint …` and `make <check|test|vet|lint|e2e|fuzz|bench|golden|eval…>`
  **unpiped**: `.claude/hooks/trim-output.py` drops ok-lines, keeps the last 40 (go/lint) or 60 (make) lines and
  the exit code. Piping or redirecting opts out.
- Goldens: `git diff --stat testdata/golden` first, then `git diff -U1 -- <one file>`.
- Long logs go to `notes/<KEY>-<step>.log`, then `tail`/`grep` it.

## 5. Return contract (≤ 10 lines to the orchestrator)

```
STATUS: done | partial | blocked
FILES: <changed paths, one line>
CHECKS: <command → ok/fail>, …
FINDINGS/OPEN: <count + one line each, max 3> (details: notes/<KEY>-<role>.md)
```

## 6. Resume vs. fresh agent

SendMessage resumes keep the agent's whole context. Resume only for a small follow-up while the agent is under
~80k; otherwise start a fresh `fixer` with the notes path.

## 7. Orchestrator hygiene

Every byte the orchestrator sees is re-read on every later turn.
- **Never poll background agents** (no `sleep`, `until`, tailing agent output): the harness notifies you. Do other
  work or end the turn.
- **Jira in one batch, at the end** (before a restart or end of round). Go straight to In Review (31) for work
  finished this session. `transitionJiraIssue` and `createJiraIssue` have no `responseFields` and echo the whole
  issue (~4k chars each), so for 2 or more writes, put them in `notes/jira-batch.md` (one block per ticket: key,
  comment ≤ 10 lines, transition 21/31, or a new issue's summary, type and description) and run the `jira` agent
  on it. Its reply is one line per ticket. A single write may stay inline. Reads stay inline: `fields:
  ["summary","status"]` on searches; never re-fetch a description already in `notes/`.
- Startup: newest progress shard only; `grep` PLAN.md / older shards for specific facts.
- Batch independent tool calls into one turn.
- Summarise agent returns to the owner; don't relay them verbatim.
- `notes/` is git-ignored; durable state goes to the progress shard, PLAN.md and Jira.

## 8. Hooks (`.claude/settings.json`)

- `trim-output.py` (PreToolUse Bash): see §4.
- `context-warn.py` (PostToolUse): orchestrator warned at 120k, then every 15k from 150k; subagents at 80k, then
  every 20k from 100k. At the restart warning follow §0.
- `permissions.deny` removes unused built-in tools (Artifact, ScheduleWakeup, ReportFindings, ListAgents) and
  built-in agent types (general-purpose, claude, Explore, Plan, claude-code-guide, statusline-setup, web-fetch)
  from every prompt; `skillOverrides` hides unused skills (still typable as /name). Need one for a session?
  Remove its deny line locally, don't work around it.

## 9. End-of-session report (owner request 2026-11-28; every session, at the restart/stop point)

Order: (1) **External apps**: if the session touched detection, ingest, identity/ownership or matching code, run the
docker suites yourself (`make eval-crapi`, `make eval-vampi`; background, log to `notes/eval-<app>-<session>.log`)
and assess groundtruth flips (TP/FP/miss) before the shard; no docker -> list it under "Waiting on the owner".
(2) **Next-session impact**: read the next `docs/sessions/session*.md` (`sort -V`, Status not done); if this
session's changes touch its files, contracts or assumptions, replan it in place (add a "Replan note", adjust
budget, keep Status `planned`) and say so. (3) **Append a row/block to `docs/SESSION_LOG.md`** (write-only: nobody
reads it at startup, it is for the owner's later investigation). (4) **Tell the owner** the same summary:
- Done / not done, commits, Jira transitions, eval results, replan yes/no.
- Tokens: subagent tokens = sum of `subagent_tokens` from the completion notifications (list per agent role);
  orchestrator = context size at the end (hook figure or `/cost`) × turns is unknowable here, so state the
  context size and say "estimate". Never invent exact numbers.
- Estimated API-equivalent cost: **always a table**, one row per agent run plus the orchestrator and a total row:
  `| Agent | Model | Tokens | API cost (est.) |` (agent = role + ticket, e.g. implementer KAN-104; model from
  `.claude/agents/<role>.md`; tokens = `subagent_tokens` from the notification, orchestrator = estimated
  context × turns split into cache-read / cache-write / output). State the per-model list prices used under the
  table and mark every figure an estimate; same table goes into `docs/SESSION_LOG.md`.
- Pro plan estimate: share of a 5-hour window / weekly allowance the session likely used (rough, say so; subagent
  runs and long contexts count most).

## 10. Practice check (external guidance, 2026-11-28; owner asked to align)

Sources: Anthropic multi-agent research post, Claude Code subagent/caching docs. Already matched: subagents for
context isolation, cheaper models for mechanical work, file handoff, sequential for dependent steps, restart with a
written shard instead of `/compact`. Added:
- **Delegate only when it pays.** Anthropic: multi-agent wins on parallel, breadth-heavy work and costs more tokens
  than one agent; sequential coding is not its sweet spot. Do a ticket inline when it touches ≤ 2 files and
  ≤ ~80 changed lines outside 🔒 packages (cold start ~6k + prompt + report exceeds the inline cost). Otherwise
  implementer.
- **Prompt names the output format.** Anthropic's top delegation failure is vague tasks: the contract (§2) must
  state objective, boundaries, tools/paths and the §5 return format. Missing format → add it, don't resend.
- **Protect the prompt cache.** Don't switch the orchestrator's model or effort mid-session (uncached turn); don't
  edit CLAUDE.md or the rules files mid-session; the cache expires after a few idle minutes, so batch work and
  avoid long idle gaps with a large context. Prefer `/clear` + shard over `/compact` (compaction re-reads the
  whole context).
- **Measure, don't guess.** Weekly: split cache reads by orchestrator vs. subagent type from the transcripts
  (`~/.claude/projects/**/*.jsonl`); if the orchestrator dominates, restart earlier; if subagents dominate,
  tighten scope or go inline.
