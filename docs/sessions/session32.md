# Session 32 — AI spikes: gap-to-test and finding triage
Status: planned
Budget: ~50k of ~100k
Depends on: session 31; session 9 (probe findings exist for AI-4)

## Goal
Both remaining AI spikes have a written recommendation and, where cheap, an offline prototype that works on
coverage.json / probe findings without network access from authzcov.

## Work (in order)
1. KAN-85 SPIKE AI-2 Gap → generated test (close coverage gaps with AI-written tests) — spike ~20k — implementer → reviewer
   Input: export --plan gap items; output: a prompt/template the user's own agent consumes. Generated tests never
   embed real tokens; placeholders only.
2. KAN-87 SPIKE AI-4 AI triage of suspicious_allow and probe findings — spike ~20k — implementer → reviewer
   Triage may rank or explain, never downgrade a finding to covered/safe (unknown never counts as covered).
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- Same AI-in-binary decision as session 31.

## Done when
- `make check` green; KAN-85, KAN-87 In Review; KAN-83 epic summary comment.

## Out of scope
- Shipping AI features in a release.
