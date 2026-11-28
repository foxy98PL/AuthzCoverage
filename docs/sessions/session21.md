# Session 21 — Validation apps: DVAPI and Damn Vulnerable RESTaurant
Status: planned
Budget: ~75k of ~100k
Depends on: session 20 (kit); session 19 triage kept both (else /planner swaps in the next kept app)

## Goal
Two more vulnerable apps scored under the protocol: digest-pinned image, multi-identity HAR, pre-registered ground
truth, eval result in eval/results/.
Each app reports passive coverage and read-only probe confirmation via Judge (kit probe step, session 20).

## Work (in order)
1. VAL-3 DVAPI suite — normal ~30k — implementer (ground truth first) → reviewer → fixer
   Step a: groundtruth.yaml from DVAPI's documented challenges + source citations, committed before any scoring.
   Step b: compose, spec (as served or in repo, unchanged), identities.yaml (minimal, then tuned), recorder, result.
2. VAL-4 Damn Vulnerable RESTaurant suite — normal ~30k — implementer (ground truth first) → reviewer → fixer
   FastAPI serves its own OpenAPI: save it once from the pinned image and commit it (licence permitting).
   Its role chapters are BFLA: declare `min_role` in the tuned config only.
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- Docker daemon and RAM: run one stack at a time. A miss or false alarm becomes a Bug (orchestrator, bug session of the
  session whose ticket introduced it); never tune authzcov inside this session.

## Done when
- `make check` green; two new result files, groundtruth sha256 recorded; VAL-3, VAL-4 In Review.

## Out of scope
- Fixing detection misses found here.
