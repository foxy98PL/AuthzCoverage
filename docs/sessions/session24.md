# Session 24 — Validation controls: Gitea and a second bug-free app
Status: planned
Budget: ~70k of ~100k
Depends on: session 20 (kit); session 19 triage kept the controls

## Goal
False-alarm rate measured on real apps that enforce authorization, beyond RealWorld.
Each app reports passive coverage and read-only probe confirmation via Judge (kit probe step, session 20).

## Work (in order)
1. VAL-9a Gitea control suite — normal ~30k — implementer (ground truth first) → reviewer → fixer
   Swagger 2.0 served by Gitea (authzcov loads Swagger 2); sqlite, pinned image; users, private repos, issues,
   org team roles. Ground truth = expected denials (tn) and public-by-design reads (quirk); recall undefined.
2. VAL-9b second control kept by triage (Vikunja or another) — normal ~30k — implementer → reviewer → fixer
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- Docker daemon and RAM.
- RealWorld already shows 7 false alarms, all public-by-design reads or feature writes; identities.yaml has no way
  to declare a resource public. Record it, do not add the feature here (feature freeze); it is a candidate for
  the go/no-go list in session 25.

## Done when
- `make check` green; control result files; VAL-9 In Review.

## Out of scope
- Any config feature to silence public-by-design flags.
