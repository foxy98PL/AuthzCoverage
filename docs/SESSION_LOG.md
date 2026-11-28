# Session log (write-only)

Append one block per orchestrator session (rules: `.claude/delegation-rules.md` §9). Agents and the orchestrator
do **not** read this file at startup; it exists for the owner's later investigation. No secrets or HAR content.

Block format: date, session file, outcome, commits, Jira, eval results, replan, tokens (subagents by role,
orchestrator context), estimated cost, Pro plan estimate, surprises.

## 2026-11-28 session 1 (session1.md) — KAN-104 + leftovers
- Outcome: done. Commits a9a563b (KAN-104), 708d8d9 (KAN-93/99/94 leftovers), shard 2026-11-28-2330. Jira: KAN-104 In Review, comments on KAN-93/99/94.
- Eval (make eval-crapi, docker): precision 0.833, recall 0.833 (tp 10, fp 2, fn 2, tn 8). KAN-102 flips CONFIRMED (U2-USERS-ALL, U1-ORDER-OTHER, C1/C7 honest are tp). C2 (query-param report_id) still fn: crapi identities.yaml has no object_param override and no rule that learns the report owner (needs POST contact_mechanic create rule). Follow-up, not done. VAmPI eval not run (no ingest/identity change affecting it beyond KAN-104; run next session).
- Replan: session2.md replanned for KAN-104 (QueryKeys in both HAR passes, compact record keeps query object value, +5k budget).
- Tokens (estimate): subagents by `subagent_tokens`: implementer KAN-104 40.9k, reviewer 23.7k, fixer 28.5k, implementers KAN-93 13.1k / KAN-99 21.2k / KAN-94 9.5k, jira 17.6k = ~154.5k. Orchestrator: ~35 turns, context grew to roughly 70-90k (not measured exactly).
- Cost estimate (API-equivalent, assumed Sonnet-class list prices $3/$15 per M in/out, cache read $0.30/M): orchestrator ~1.75M cache-read ($0.5) + ~100k cache-write ($0.4) + ~25k output ($0.4) ≈ $1.3; subagents ≈ $0.6-1.5. Total ≈ $2-3.5. Prices are assumptions, verify.
- Pro plan estimate: very rough, ~30-50% of one 5-hour window (one long orchestrated session with 7 subagents); weekly impact a few percent.
- Surprises: reviewer named a nonexistent test (TestNewGapsKnownEndpointOnly); agents refuse to write notes/*-impl.md in this environment.

## Session 1.1 (2026-11-28)
Done: KAN-103/100/98 agent-doable parts (SARIF step in action-test.yml; fuzz verified; README checked). Commit 911f3a2. No external-app eval (no detection code touched). Next session 2 not affected. Agents: jira (Haiku) x1, tokens pending notification. Orchestrator context small (~40k, estimate).

## 2026-11-29 session 2 (session2.md) — KAN-91
- Outcome: done. Commit 630e196 (pushed) + docs commit. KAN-91 -> In Review. RSS 1M 1664.9 -> 255.7 MiB, time 14.1 -> 10.8 s.
- Eval: VAmPI tp16/fp3/fn2/tn11; crAPI tp10/fp2/fn2/tn8, no flips. Replan: no (session 3 unaffected).
- Tokens (subagent_tokens): implementer KAN-91 149.8k, reviewer 37.2k, fixer 16.0k + 19.4k resume. Orchestrator: ~50k context (estimate).
- Cost (estimate, Sonnet list $3/$15 per M, cache read $0.30/M): implementer ~$1.5, reviewer ~$0.3, fixer ~$0.3, orchestrator ~$0.5; total ~$2.6.
- Pro plan: roughly 30-40% of a 5-hour window (rough).
- Surprises: GC-restore fix regressed RSS 256 -> 380 MiB; caught by re-running eval-scaling myself.
