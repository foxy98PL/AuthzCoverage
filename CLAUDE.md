# AuthzCoverage — working rules for Claude

## Main session (orchestrator) only — subagents skip this section
Start by reading the newest progress shard (`ls docs/progress/2*.md | tail -1`) and `.claude/delegation-rules.md`
(binding: models, agents, prompts, Jira, restarts). Grep `docs/PLAN.md` for decisions on demand; don't read it whole.
The orchestrator plans, writes contracts, updates Jira and docs; lean agents in `.claude/agents/` implement,
review and validate.

## Project rules (all agents; full spec in Jira KAN)
- GitHub: `origin` = https://github.com/foxy98PL/AuthzCoverage (public), branch `main`. The orchestrator
  commits and pushes on its own judgment (owner approval 2026-11-28); subagents never commit or push; nobody
  force-pushes or changes repo settings. GitHub files (`.github/`: Actions with
  SHA-pinned actions, Dependabot, templates) are allowed. Before any push: secrets/HAR scan clean
  (no `*.har`, nothing from `testdata/raw/`, no real tokens or personal data).
- No network in `coverage`; raw credentials never survive ingest, and raw object IDs never reach shareable artifacts (the opt-in `--har` plan is the only raw-ID output); unknown never counts as covered.
- Direct deps only: cobra, kin-openapi, yaml/v3, golang-jwt/v5 (x/time/rate in Phase 4).
- 🔒 packages (match, identity, relate, matrix): tests first.
- `make check` green before reporting a task done; the orchestrator commits as a Conventional Commit with the Jira key.
- Jira (KAN): finished work → **In Review** with a comment; partial → **In progress**. Owner moves to Done.
- Read and output hygiene: grep then read ranges (no whole files over ~150 lines); run `go test`/`make`
  unpiped (a hook trims the output).
