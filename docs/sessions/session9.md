# Session 9 — compare.Judge and probe findings in reports
Status: planned
Budget: ~70k of ~100k
Depends on: session 8 (baselines, negative controls)

## Goal
The Judge decides leak / no leak / inconclusive from baseline + control + attack response, and probe findings
appear in JSON, Markdown, HTML and SARIF with placeholder curl repros.

## Work (in order)
1. KAN-43 ACV-4.8 compare.Judge with automatic marker learning — tests-first ~35k — implementer (tests first) → reviewer → fixer
   Fail to inconclusive on any doubt (unknown never counts as covered/safe). Advisor (Opus) only if marker
   learning can turn an inconclusive into a pass.
2. KAN-44 ACV-4.9 Probe findings in all reporters with placeholder curl repros — normal ~25k — implementer → reviewer
   Repros use placeholders for tokens and raw IDs (no raw IDs in shareable artifacts); schema bump noted in
   coverage.json JSON Schema; goldens regenerated and the diff reviewed.
3. Jira batch + shard + commit — ~10k

## Owner / blocked
- First `--execute` on VAmPI (Docker) to see the book BOLA flagged; if Docker is down, the owner runs it.

## Done when
- `make check` green; goldens updated; KAN-43, KAN-44 In Review.

## Out of scope
- CI oracles (session 10).
