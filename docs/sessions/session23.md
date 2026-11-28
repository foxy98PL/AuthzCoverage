# Session 23 — Validation apps: extras kept by triage
Status: planned
Budget: ~70k of ~100k
Depends on: session 22; session 19 triage (this session is deleted by /planner if triage keeps no extra app)

## Goal
Up to two further vulnerable apps scored, so the aggregate rests on at least six vulnerable apps.
Each app reports passive coverage and read-only probe confirmation via Judge (kit probe step, session 20).

## Work (in order)
1. VAL-7 first extra app kept by triage (candidates: BrokenCrystals, Pixi, Juice Shop only if triage found a usable
   spec for its REST API) — normal ~30k — implementer (ground truth first) → reviewer → fixer
2. VAL-8 second extra app kept by triage — normal ~30k — implementer (ground truth first) → reviewer → fixer
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- Docker daemon and RAM.
- Juice Shop's basket test in session 10 (KAN-46) is a probe test, independent of this passive suite.

## Done when
- `make check` green; result files for every kept extra; VAL-7, VAL-8 In Review (or closed as dropped with reason).

## Out of scope
- Apps dropped in candidates.md; fixing misses.
