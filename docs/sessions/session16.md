# Session 16 — gRPC adapter and hosted dashboard spike
Status: planned
Budget: ~75k of ~100k
Depends on: session 15; Gate D passed for the dashboard spike (KAN-9 out-of-scope rule)

## Goal
gRPC calls (path `/pkg.Service/Method`) map to coverage endpoints (step b of KAN-54), and the hosted dashboard
spike has a go/no-go write-up.

## Work (in order)
1. KAN-54 ACV-5.5 GraphQL and gRPC adapters — step b: gRPC — normal+ ~40k — implementer → reviewer → fixer
   Endpoints from .proto service definitions (minimal reader, services/methods only) or from observed paths;
   object IDs inside protobuf bodies are out of scope (unknown, never covered). Same no-new-deps assumption.
2. KAN-55 ACV-5.6 Hosted dashboard spike (only if Gate D passes) — spike ~20k — implementer
   Write-up only: data that may leave the machine (shareable artifacts only, no raw IDs), hosting cost, threat
   model delta. Skip and comment on Jira if Gate D did not pass.
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- Gate D result for KAN-55; protobuf parser dependency (default: none).

## Done when
- `make check` green; KAN-54 and KAN-55 In Review (or KAN-55 commented as skipped).

## Out of scope
- AI spikes (sessions 17–18).
