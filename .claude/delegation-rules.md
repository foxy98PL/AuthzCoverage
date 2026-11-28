# Delegation rules (orchestrator ↔ subagents)

Measured on 2026-11-27 (10 subagents, see `notes/orchestrator-state.md` → "Context audit"):
the fixed floor of any subagent is **~35k tokens** (system prompt + skill listing ≈ 13k + CLAUDE.md +
MCP/agent listings); a "reply OK" agent costs 34.6k. Everything above the floor came from the agent's
**own whole-file reads (70–98% of tool output)**, the code it wrote, full test/golden output, and
**resumes via SendMessage** (which keep the whole prior context). Prompts were never the driver
(0.4–1.8k tokens). These rules target those causes.

## 0. Orchestrator model, restarts, review rounds (owner decision 2026-11-28)

- **Sonnet orchestrates every session** (implement → review → fix → commit → Jira). Opus costs 2× Sonnet
  per token (input, output and cache reads), and the orchestrator re-reads its whole context on every turn.
- **Reviews are Haiku, including 🔒 packages** (`reviewer` as defined). 🔒 code is already guarded by
  tests-first; the reviewer maps criteria → tests and runs them.
- **Opus only for security or architecture decisions** (owner, 2026-11-28), e.g. changing how credentials,
  identity or tenancy are handled, a new threat-model trade-off, a package/API design choice. Also when a
  Haiku reviewer flags a security finding it cannot settle. Write the question with options to
  `notes/<KEY>-opus.md`, then launch a fresh `general-purpose` agent with `model: opus` pointed at it
  (~35k + the note, never an Opus orchestrator), or hand it to the owner.
- **Restart at ~100k** orchestrator tokens (the context hook warns you): write a new progress shard
  (`docs/progress/README.md`), do the batched Jira updates (§8), tell the owner, stop. Local-only details
  (agent IDs, scratch paths) go to `notes/orchestrator-state.md`. A reload costs ~45k; every call after it
  is cheaper.
- **Every time a ticket moves to In Review**, append a row to `docs/REVIEW_QUEUE.md` and start the
  `reviewer` in the background; implementation of the next ticket continues meanwhile. There is no
  separate review orchestrator.
- **One reviewer pass and one fixer per ticket.** The reviewer lists all findings at once (F1…Fn) in
  `notes/<KEY>-review.md`; one `fixer` fixes them all. No second review round; the fixer's checks
  (tests first per finding + verify commands) close it. Leftover low findings go to Jira as a comment,
  not to another loop.

## 1. Agent choice

- Use the lean agents in `.claude/agents/`: `implementer` (Sonnet), `fixer` (Sonnet), `reviewer` (Haiku),
  `validator` (Haiku). Their `tools:` list has no MCP, web or agent tools.
- `subagent_type: fork` only when the task genuinely needs the whole conversation (e.g. "summarise what
  we decided today"). **Never** fork to implement, fix or review a ticket.
- One ticket per agent. Disjoint directories for parallel agents; nobody touches go.mod/go.sum.

## 2. Prompt contract (≤ ~1.5k tokens ≈ 6,000 chars)

Contents, as pointers:
- Ticket ID and the acceptance criteria (copy the Jira AC list, ≤ 15 lines, or "read `notes/<KEY>-spec.md`").
- Branch / base commit, exact paths in scope, paths that are off-limits.
- Constraints that apply (🔒 tests first, stdlib only, no network, …) as one line each.
- Verify commands.
- Where to write the long report (`notes/<KEY>-<role>.md`).

Never paste file contents, diffs, test output or another agent's report. A fix task gets
"fix F1–F3 in `notes/<KEY>-review.md`", not the findings retyped. Going over 1.5k tokens needs a one-line
reason in the prompt (e.g. a decision table that exists nowhere else — then write it to `notes/` first).

## 3. Read hygiene (the biggest saving)

- No `cat` / `Read` of a whole file over ~150 lines. `grep -n` for the symbol, then `sed -n 'a,bp'` or
  Read with `offset`/`limit` around it. Read a whole file only when you are going to rewrite most of it.
- Don't re-read a file you just wrote or edited.
- Templates ("model this on e2e/thirdparty/vampi"): read the structure (`grep -n '^func '`) and only the
  functions you copy.

## 4. Output hygiene

- Tests: `go test ./... 2>&1 | grep -v '^ok\|no test files' | tail -30` (prints nothing when green).
- `make check 2>&1 | tail -15`; `make e2e 2>&1 | tail -5`; benchmarks: summary lines only.
- Goldens: `git diff --stat testdata/golden` first, then `git diff -U1 -- <one file>` only where needed.
- Long logs go to a file (`> notes/<KEY>-<step>.log 2>&1`), then `tail`/`grep` it.

## 5. Reviewer contract

- Input: `git diff <base>...HEAD -- <paths>` (or `git diff -- <paths>` for uncommitted work) + the
  acceptance criteria. The reviewer reads further code itself only to check a specific suspicion, with
  the read-hygiene rules.
- Read-only. Writes findings to `notes/<KEY>-review.md` (F1…Fn, severity, file:line, failing scenario).

## 6. Return contract (≤ 10 lines to the orchestrator)

```
STATUS: done | partial | blocked
FILES: <changed paths, one line>
CHECKS: <command → ok/fail>, …
FINDINGS/OPEN: <count + one line each, max 3> (details: notes/<KEY>-<role>.md)
```
Anything longer goes to `notes/<KEY>-<role>.md`; the orchestrator gets the path.

## 7. Resume vs. fresh agent

- `SendMessage` resumes keep the agent's whole context (KAN-92: 144k → 161k → 177k over two resumes).
- Resume only for a small follow-up when the agent is under ~80k. Otherwise start a fresh `fixer` with
  the notes path.

## 8. Orchestrator budget and hygiene

Every byte the orchestrator sees is re-read on every later turn, so the cost of an output is its size ×
the turns left in the session. Measured 2026-11-27: 4 Opus orchestrator sessions re-read 132M tokens
(peaks 336–492k) vs 62M for all 69 subagents together.

- **Never poll background agents** (no `sleep`, `until`, `tail` of agent output, TaskOutput loops): the
  harness notifies you when they finish. Measured: 12–15 poll turns per session ≈ 2.5M tokens each session.
  While waiting, do other work or end the turn.
- **Jira in one batch, at the end** (right before a restart or the end of a round), so the echoes are never
  re-read: transitions and `getJiraIssue` echo the full issue (~4–5k chars each; one session made 22).
  Go straight to In Review (31) — no intermediate In progress (21) transition for work finished in the
  same session. Request `fields: ["summary","status"]` / `responseFields` on searches; never re-fetch a
  description already in `notes/`; keep comments ≤ 10 lines.
- Startup: read only the newest progress shard; `grep` PLAN.md / older shards for specific facts.
- Batch independent tool calls into one turn (each turn re-reads the whole context).
- Own commands: same read/output hygiene as agents.
- Don't relay agent reports to the user verbatim; summarise from the ≤ 10-line return.
- `notes/` is git-ignored (local paths, review drafts); durable state goes to the progress shard and Jira.

## 9. Hooks (automatic, `.claude/settings.json`)

- `.claude/hooks/trim-output.py` (PreToolUse Bash): an unpiped `go test …` or `make check|test|e2e|fuzz|eval…`
  is rewritten to keep failures and the last 40 lines; the exit code is preserved. Pipe or redirect the
  command yourself to opt out.
- `.claude/hooks/context-warn.py` (PostToolUse): warns once at 80k, then every 20k from 100k on, with the current
  context size. At the 100k warning, follow §0 (restart).
