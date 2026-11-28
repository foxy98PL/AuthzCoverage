# Session 31 — AI spikes: MCP server and identities.yaml assistant
Status: planned
Budget: ~60k of ~100k
Depends on: session 25 (validation report; owner: validation before any further feature growth); session 12 (stable v0.3.0 CLI surface); owner interest in the AI epic (KAN-83, Low)

## Goal
A prototype MCP server exposes coverage, explain and gate as agent tools, and the identities.yaml assistant
spike has a design write-up.

## Work (in order)
1. KAN-84 SPIKE AI-1 MCP server for authzcov (coverage, explain, gate as agent tools) — spike ~30k — implementer → reviewer
   Assumption: stdio JSON-RPC with the standard library only (no MCP SDK dep), behind a hidden or experimental
   subcommand; tools return shareable artifacts only (no raw IDs, no credentials); no network.
2. KAN-86 SPIKE AI-3 identities.yaml configuration assistant — spike ~15k — implementer
   Design write-up: build on `discover`; what the model may see (pseudonymised HAR summary only).
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- Whether AI features may ship in the binary at all, and whether an MCP SDK dependency is acceptable.

## Done when
- `make check` green; spike write-ups under docs/; KAN-84, KAN-86 In Review.

## Out of scope
- LLM calls from the authzcov binary.
