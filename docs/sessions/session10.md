# Session 10 — Probe end-to-end oracles (VAmPI in CI, crAPI, Juice Shop)
Status: planned
Budget: ~75k of ~100k
Depends on: session 9; Docker daemon for local runs

## Goal
CI proves the probe on VAmPI (vulnerable=1 finds one leak, vulnerable=0 finds zero), and crAPI vehicle-location
and Juice Shop basket e2e tests exist.

## Work (in order)
1. KAN-45 ACV-4.10 VAmPI end-to-end probe oracle in CI (vulnerable=1 / 0) — normal ~30k — implementer → reviewer → fixer
   Extend e2e/thirdparty/vampi; CI job with the image pinned by digest, SHA-pinned actions, loopback allowlist.
2. KAN-46 ACV-4.11 crAPI vehicle-location and Juice Shop basket e2e tests — normal+ ~35k — implementer → reviewer
   crAPI reuses e2e/thirdparty/crapi; Juice Shop is a new harness mirroring it (own go.mod, Dependabot entry).
   Scope-cut ladder (KAN-65): Juice Shop and crAPI e2e may be cut before correctness work.
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- Docker daemon and RAM (KAN-75) for crAPI and Juice Shop; without it the harness lands with unit tests and the
  owner runs it. CI result is visible only after a push.

## Done when
- `make check` green; VAmPI oracle job green in CI; KAN-45, KAN-46 In Review.

## Out of scope
- Destructive mode (session 11).
