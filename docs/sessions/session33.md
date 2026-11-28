# Session 33 — Destructive mode and resume
Status: planned
Budget: ~75k of ~100k
Depends on: session 25 go/no-go by the owner (owner decision 2026-11-28: validation 19–25 runs before destructive mode); session 10 (read-only probing proven by the VAmPI oracle, KAN-65)

## Goal
Opt-in destructive mode (create as owner, attack, verify as owner) works on objects the probe created itself,
inconclusive results can be re-run, and `--resume` continues from the audit log.

## Work (in order)
1. KAN-47 ACV-4.12 Destructive mode: create-as-owner, attack, verify-as-owner — tests-first, security ~40k — implementer (tests first) → reviewer → fixer
   Only objects created in this run are attacked; separate explicit flag on top of `--execute`; safety module
   still gates every request. Advisor (Opus) for the guardrails (what counts as "own object", cleanup on failure).
2. KAN-48 ACV-4.13 Re-run inconclusive results; --resume from audit log — normal ~25k — implementer → reviewer
   Resume never re-sends a completed destructive step; a tampered/unknown audit log line stops the run.
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- None expected (scope-cut ladder allows dropping both if Phase 4 runs late).

## Done when
- `make check` green; VAmPI oracle still green; KAN-47, KAN-48 In Review.

## Out of scope
- Safety docs and v0.3.0 (session 34).
