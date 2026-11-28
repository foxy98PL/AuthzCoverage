# Session 38 — GraphQL adapter and spec-less mode spike
Status: planned
Budget: ~80k of ~100k
Depends on: session 37; owner decision on parser dependencies (see Owner / blocked)

## Goal
GraphQL operations in a HAR map to coverage endpoints (step a of KAN-54), and the spec-less mode spike has a
written recommendation with a bug-bounty checklist.

## Work (in order)
1. KAN-54 ACV-5.5 GraphQL and gRPC adapters — step a: GraphQL — normal+ ~45k — implementer → reviewer → fixer
   Endpoint = operation type + root field (operationName is caller-controlled, not trusted); object IDs from
   variables; batched/persisted queries fail to unknown. Assumption: no new direct dependency (minimal SDL
   reader for root fields only).
2. KAN-82 SPIKE ACV-5.8 Spec-less mode and bug-bounty hunting checklist — spike ~25k — implementer → reviewer
   Write-up under docs/ (route inference from HAR paths, its false-coverage risk, the checklist); prototype
   only behind a hidden flag if cheap. No publication.
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- Direct-deps rule allows only cobra, kin-openapi, yaml/v3, golang-jwt/v5, x/time/rate. A GraphQL parser
  (e.g. gqlparser) would be a new dep: owner decides; default is the minimal hand-written reader.

## Done when
- `make check` green; GraphQL adapter fuzzed; KAN-82 write-up committed; KAN-54 stays In progress (step b left).

## Out of scope
- gRPC (session 39).
