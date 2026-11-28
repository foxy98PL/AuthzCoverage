# Session 7 — Probe credentials and executor
Status: done — shard 2026-11-29-0600-session7.md
Budget: ~80k of ~100k
Depends on: session 6 (safety module, plan generator)

## Replan note (session 6)
- Safety API: `safety.Check`/`CheckAddr`, exit code `cli.ExitProbeRefused` = 5; items from `internal/probe/items`.
- Advisor design (notes/KAN-37-opus-answer.md): exec must dial the checked IP and set TLS SNI and Host itself,
  record cross-host 3xx as the response (not followed), re-check every hop. Add a redirect and dial-pinning test to KAN-39; budget +5k.

## Goal
Probe credentials load only from env vars or login recipes, and `internal/probe/exec` (the only net/http user)
sends planned requests with rate limit, budget, safe redirects, circuit breaker and a redacted audit log.

## Work (in order)
1. KAN-38 ACV-4.3 Probe credentials from env vars or login recipes only — tests-first, security ~30k — implementer (tests first) → reviewer → fixer
   Never from the HAR (raw credentials never survive ingest); never written to logs, audit log or reports.
   Advisor (Opus) for the login-recipe design (what a recipe may do, secret lifetime).
2. KAN-39 ACV-4.4 Probe executor: rate limit, budget, redirects, breaker, audit log — normal+ ~40k — implementer → reviewer → fixer
   x/time/rate is the allowed Phase 4 dep. Every hop (incl. redirects) re-checked by the safety module; budget
   and breaker stop the run; audit log fields follow DOC-04 (KAN-61). Tests with httptest on loopback only.
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- None expected; Opus advisor answers are design decisions recorded in PLAN.md implementation decisions.

## Done when
- `make check` green; depguard still forbids net/http outside probe/exec; KAN-38, KAN-39 In Review.

## Out of scope
- Dry-run parity, baselines, controls (session 8); destructive requests (session 11).
