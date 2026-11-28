# Session 6 — Probe foundation: safety module, then plan generator
Status: planned
Budget: ~80k of ~100k
Depends on: session 5; Gate C passed (owner, see Owner / blocked); KAN-34 export --plan In Review/Done

## Goal
`internal/probe/safety` refuses every non-allowlisted target (fail-closed) and a probe plan generator turns
exported gaps into (object ID, attacker identity) probe items. No HTTP is sent yet.

## Work (in order)
1. KAN-37 ACV-4.2 Probe safety module (targets, allowlist, prod heuristics) — tests-first, security ~40k — implementer (tests first) → reviewer → fixer
   Safety first (KAN-65 order: 4.2 before 4.1). Pure package, no net/http. AC: the 40-URL safety table is green
   and 100% of non-allowlisted targets are refused; unknown/ambiguous host = refused. Advisor (Opus) for the
   prod-heuristics and allowlist-matching trade-offs (IP literals, IDN, ports, redirects to other hosts).
2. KAN-36 ACV-4.1 Probe plan generator (object ID + attacker per gap) — normal ~25k — implementer → reviewer
   Consumes the KAN-34 export --plan JSON. Raw object IDs only come from the opt-in `--har` plan (KAN-94
   option A); a hash-only plan yields items marked not-executable, never guessed IDs. Deterministic order.
3. Tighten depguard (PLAN.md J3): only `internal/probe/exec` may import net/http — trivial ~3k — implementer
4. Jira batch + shard + commit — ~10k

## Owner / blocked
- Gate C (2027-01-31). Assumption: Phase 4 starts only after the owner records Gate C as passed, or waives it
  in writing; until then /start stops here and reports.
- KAN-37 and KAN-36 Jira texts disagree on order (KAN-65 note); this plan follows safety first.

## Done when
- `make check` green; safety table test and no-network test pass; KAN-37, KAN-36 In Review.

## Out of scope
- Credentials and the executor (session 7); any real HTTP.
