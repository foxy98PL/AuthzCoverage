# Session 27 — Route extraction without a spec: Spring Actuator and Next.js
Status: planned
Budget: ~65k of ~100k
Depends on: session 25 (validation report; owner: validation before any further feature growth); Gate D "continue" (owner); user demand for these inputs (KAN-9 scope rule)

## Goal
`authzcov` can build its endpoint list from Spring `/actuator/mappings` JSON and from a Next.js project tree,
feeding the same matcher as OpenAPI.

## Work (in order)
1. KAN-50 ACV-5.1 Spring route extraction via Actuator /actuator/mappings — normal ~30k — implementer → reviewer → fixer
   Input is a saved mappings JSON file (no network in coverage). KAN-9 exit: PetClinic REST routes match its
   OpenAPI for at least 95% of operations; security info absent = unknown, never public.
2. KAN-52 ACV-5.3 Next.js route scanning (app/api, pages/api) — normal ~25k — implementer → reviewer
   Pure filesystem walk; dynamic segments `[id]`, `[...slug]` mapped to trie params; no symlink escape.
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- Gate D outcome and which extensions users asked for (KAN-9: only requested ones). Assumption: if Gate D says
  "continue" without a pick, run sessions 27–30 in this order.
- A PetClinic mappings dump (needs Docker/Java) for the 95% check; the owner records it if Docker is down.

## Done when
- `make check` green; new loaders fuzzed like the spec loader; KAN-50, KAN-52 In Review.

## Out of scope
- NestJS/Express and OTLP (session 28).
