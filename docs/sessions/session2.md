# Session 2 — Bounded memory in the coverage pipeline
Status: active
Budget: ~65k of ~100k
Depends on: session 1 (done, a9a563b: KAN-104 landed; replanned 2026-11-28 for its effects, see Replan note)

## Goal
Peak RSS at 1M HAR entries is at least 5x lower than today with byte-identical output.

## Work (in order)
1. KAN-91 Bounded memory in the coverage pipeline (peak RSS linear in HAR size today) — normal+ ~45k — implementer → reviewer → fixer
   Step a: record the before numbers (`make eval-scaling`, `rss_ratio` in eval/results/scaling.json).
   Step b: stop holding every `*model.Exchange` (`readHARsByFile`) and the full `[]*model.Observation`
   (`matchExchanges`): read the HAR twice from disk (pass 1 learns ownership/tokens, pass 2 classifies) and keep
   only compact per-observation data; fold matrix cells and evidence (cap 5) while streaming. If folding touches
   matrix or relate (🔒), tests first there.
   AC: RSS ≥5x lower at 1M, byte-identical goldens and `make eval`, determinism (shuffled input) and no-network
   tests pass, 1M time no more than 20% slower. Report before/after in the Jira comment.
   Advisor (Opus) only if two-pass reading changes what pass 1 may learn (identity/ownership semantics).
   Replan note (KAN-104 effects): ingest now keeps only declared object query keys (`har.Options.QueryKeys`) and
   `Observation.Params` can hold a query-derived value (`queryObjectValue`: repeated/empty/array/comma/whitespace
   -> unknown). Pass 1 and pass 2 must both pass the same QueryKeys; the compact per-observation record must carry
   the query-derived object value (or its hash) so memory does not regress; add a determinism case with a
   query-object endpoint (tests in internal/cli/queryparam_test.go are the baseline). Budget +~5k.
2. Jira batch + shard + commit — ~10k

## Owner / blocked
- `make eval` third-party parts (VAmPI, crAPI) need the Docker daemon; if it's down, run tenantshop + goldens and
  list the Docker run for the owner.

## Done when
- `make check` green, goldens unchanged, scaling.json updated with before/after; KAN-91 In Review.

## Out of scope
- New pipeline features; benchmark CI ratio tuning (KAN-96 follow-up after real CI data).
