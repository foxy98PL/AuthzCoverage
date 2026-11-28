# Session 37 — NestJS/Express routes and OTLP input
Status: planned
Budget: ~80k of ~100k
Depends on: session 36 (shared route-extractor interface)

## Goal
NestJS swagger documents and an Express route dump load as endpoint sources, and OTLP JSON spans
(http.route + an identity attribute) can replace a HAR as input without a spec.

## Work (in order)
1. KAN-51 ACV-5.2 NestJS (swagger doc) and Express route dumper — normal ~30k — implementer → reviewer
   NestJS: the generated OpenAPI JSON goes through the existing loader. Express: a small documented JS dumper
   script whose JSON output Go parses; the script can't be run here (no node).
2. KAN-53 ACV-5.4 OTLP JSON input (http.route + identity attribute) — tests-first ~40k — implementer (tests first) → reviewer → fixer
   Touches identity (🔒): failing tests first. Identity attribute values are fingerprinted at ingest like
   credentials; spans without the attribute = unknown caller. Advisor (Opus) for identity semantics.
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- Run the Express dumper against a real app (needs node) and attach the output as a fixture after pseudonymising.

## Done when
- `make check` green; KAN-9 exit "OTel spans with http.route ingest without a spec" shown by a test; KAN-51, KAN-53 In Review.

## Out of scope
- GraphQL and gRPC (sessions 38–39).
