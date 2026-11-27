# AuthzCoverage — working rules for Claude

Read `docs/PLAN.md` (plan, decisions) and `docs/PROGRESS.md` (what is done) before starting work.

## Two orchestrators
Two Opus sessions may run at once. The user tells each session its role at start.
- **Implementation orchestrator**: plans and implements tickets via Sonnet agents. When a ticket
  is done it moves it to In Review in Jira and appends a row to `docs/REVIEW_QUEUE.md`
  (ticket, packages, acceptance criteria file/summary, status `queued`).
- **Review orchestrator**: watches `docs/REVIEW_QUEUE.md`; for each `queued` row sets `in review`,
  launches read-only Haiku reviewers (criteria → tests, run tests, 🔒 rule checks), writes
  findings to `docs/reviews/<KEY>.md`, comments in Jira, and sets the row to `passed` or
  `findings`. It does not edit code; fixes are requested from the implementation orchestrator
  (row status `findings`), which assigns a Sonnet agent.
- Neither orchestrator edits the other's files concurrently: implementation owns code and
  `docs/PROGRESS.md`/`docs/PLAN.md`; review owns `docs/reviews/` and the status column of the queue.

## Orchestration (default for every task)
- The main session (Opus) is the **orchestrator**: plans, writes contracts, reviews 🔒 code,
  updates Jira and docs. It does not write bulk implementation itself.
- **Sonnet subagents implement**; **Haiku subagents validate** (run `make check`, fuzz,
  greps for secrets, determinism checks) and report pass/fail.
- Each subagent gets only what it needs: exact file/package scope, the API contract to
  implement, rules that apply, and the verify commands. No conversation history, no
  unrelated specs. Parallel agents get disjoint directories and never touch go.mod/go.sum.
- Subagent reports are short (files, API, tests, command output; ≤ 70 lines).
- **Every time a ticket moves to In Review**, start a read-only Haiku review agent in the background:
  give it the ticket's acceptance criteria and the package paths; it maps each criterion to a test,
  runs the tests, and reports gaps. Implementation of the next task continues meanwhile.
  Findings are fixed by a Sonnet agent (or noted in Jira) before the owner reviews.
- Orchestrator context: when it grows past ~150k tokens, write state to `docs/PROGRESS.md`
  first, then compact (`/compact`), and continue from the docs.

## Project rules (summary; full spec in the implementation prompt / Jira KAN)
- GitHub: `origin` = https://github.com/foxy98PL/AuthzCoverage (public), branch `main`. The owner commits
  and pushes; agents never push, force-push, or change repo settings. GitHub files (`.github/`: Actions with
  SHA-pinned actions, Dependabot, templates) are allowed. Before any push: secrets/HAR scan clean
  (no `*.har`, nothing from `testdata/raw/`, no real tokens or personal data).
- No network in `coverage`; raw credentials never survive ingest; unknown never counts as covered.
- Direct deps only: cobra, kin-openapi, yaml/v3, golang-jwt/v5 (x/time/rate in Phase 4).
- 🔒 packages (match, identity, relate, matrix): tests first.
- `make check` green before reporting a task done; propose a Conventional Commit with the Jira key.
- Jira (KAN): finished work → **In Review** with a comment; partial → **In progress**. Owner moves to Done.
