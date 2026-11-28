# Session 34 — Probe safety docs, v0.3.0 prep, migrate placeholder
Status: planned
Budget: ~40k of ~100k
Depends on: session 33; session 25 go/no-go by the owner

## Goal
Probe safety is documented, v0.3.0 is ready to tag, and `authzcov migrate` exists as a v1 no-op placeholder.

## Work (in order)
1. KAN-49 ACV-4.14 Safety documentation and v0.3.0 release — prep only — normal ~20k — implementer → reviewer
   docs/probe-safety.md (allowlist, dry run, budget, destructive mode, audit log), CHANGELOG, known limitations,
   releasing checklist. No tag.
2. KAN-77 ACV-5.7 authzcov migrate command (placeholder until a v2 schema exists) — trivial ~8k — implementer
   For v1 inputs: report "already current", exit 0; unknown versions fail with a clear error.
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- Push the v0.3.0 tag and verify the signed release.
- Gate D (Sun 2027-02-28, KAN-65: continue / OSS-only / archive) decides whether sessions 36–41 run.

## Done when
- `make check` green; KAN-49 In progress until the owner tags; KAN-77 In Review.

## Out of scope
- Phase 5 extensions and AI spikes (sessions 36–41).
