# Session 8 — Dry-run parity, owner baselines, negative controls
Status: planned
Budget: ~75k of ~100k
Depends on: session 7 (executor)

## Replan note (session 7)
- Executor API exists (`internal/probe/exec`, KAN-39); no probe CLI command exists yet, so session 8's `--execute` work must also wire
  the command: `credentials.NewProvider(file.ProbeRecipes())`, `Provider.TokenEnv = file.ProbeTokenEnvs()`, `Provider.CheckEnv()` at start.
- Add the KAN-38 AC1 test there: probe has no token flag. Audit log has `path_fp` (no raw IDs); budget +8k for command wiring.

## Goal
Dry run is the default and provably sends exactly the planned requests; each probe has an owner baseline with
volatile fields detected and a negative control per ID type.

## Work (in order)
1. KAN-40 ACV-4.5 Dry-run default with plan/execution parity snapshot test — normal ~20k — implementer → reviewer
   `--execute` is required to send anything; snapshot test: dry-run plan == executed plan (Gate D evidence item).
2. KAN-41 ACV-4.6 Owner baseline replay with volatile-field detection — normal ~25k — implementer → reviewer → fixer
   Replay as the owner twice; fields that differ are volatile and excluded from comparison.
3. KAN-42 ACV-4.7 Negative controls per ID type (integer, UUID, slug) — normal ~20k — implementer → reviewer
   A non-existent ID of the same type gives the "denied/not found" shape; no control = inconclusive, never pass.
4. Jira batch + shard + commit — ~10k

## Owner / blocked
- None.

## Done when
- `make check` green; parity snapshot test in CI; KAN-40/41/42 In Review.

## Out of scope
- The Judge and reporting (session 9).
