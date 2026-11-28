# Session 3 — RealWorld harness (last v0.1.0 golden)
Status: active
Budget: ~60k of ~100k
Depends on: session 2 (goldens must be stable); Docker daemon for the run

## Goal
A scripted RealWorld (Conduit) recorder and groundtruth exist under e2e/thirdparty/, wired into `make eval`,
following O8 (goldens are outputs of scripted recorders; no HAR committed).

## Work (in order)
1. KAN-12 ACV-0.3 Recording harness — RealWorld part — normal+ ~40k — implementer → reviewer → fixer
   Mirror e2e/thirdparty/crapi (compose by image digest, Go recorder, groundtruth.yaml, identities.yaml,
   run.sh, own go.mod added to Dependabot). Pick one RealWorld backend with a published image and use the
   official RealWorld OpenAPI spec; record the choice in PLAN.md implementation decisions.
   Covers the RealWorld parts of KAN-29 AC3/AC4 (scripted Go recorder instead of Playwright: no node here)
   and KAN-19 real-app goldens.
2. KAN-100 RealWorld size AC — trivial ~5k — none
   Measure the HTML report size on the RealWorld run and comment on KAN-100.
3. Jira batch + shard + commit — ~10k
   Comments on KAN-12, KAN-19, KAN-29 (and KAN-90 if results go into the validation tables).

## Owner / blocked
- Docker daemon (and RAM, KAN-75) for the RealWorld run; without it the harness is committed with unit tests
  and the owner runs `make eval`.
- KAN-29 AC3 says examples/crapi and examples/realworld; O8 puts goldens under e2e/thirdparty. Owner to amend the AC.

## Done when
- `make check` green; harness unit tests pass; `make eval` green with RealWorld if Docker is available.

## Out of scope
- Juice Shop harness (KAN-46, Phase 4); the validation article (KAN-90).
