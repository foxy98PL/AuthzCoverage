# Session 22 — Validation apps: dvws-node and Checkmarx c{api}tal
Status: planned
Budget: ~75k of ~100k
Depends on: session 21; session 19 triage kept both (else /planner swaps in the next kept app)

## Goal
Two more vulnerable apps scored under the protocol.
Each app reports passive coverage and read-only probe confirmation via Judge (kit probe step, session 20).

## Work (in order)
1. VAL-5 dvws-node suite — normal ~30k — implementer (ground truth first) → reviewer → fixer
   Swagger served by the app; horizontal (IDOR) and vertical (BFLA) access-control items; it also has GraphQL and
   SOAP parts, which are out_of_scope (REST only).
2. VAL-6 c{api}tal suite — normal ~30k — implementer (ground truth first) → reviewer → fixer
   Built on the RealWorld Conduit API: reuse the RealWorld public-by-design items so the two results are comparable.
   If no image is published, build from a pinned commit with base images pinned by digest and record the built digest.
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- Docker daemon and RAM, one stack at a time.

## Done when
- `make check` green; two new result files; VAL-5, VAL-6 In Review.

## Out of scope
- GraphQL/SOAP endpoints of dvws-node; fixing misses.
