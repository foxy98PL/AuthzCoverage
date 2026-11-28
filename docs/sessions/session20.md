# Session 20 — Shared validation harness kit; re-baseline VAmPI, crAPI, RealWorld
Status: planned
Budget: ~95k of ~100k
Depends on: session 19 (protocol); session 10 (probe results for VAmPI, crAPI, Juice Shop); Docker daemon (KAN-75)

## Goal
New apps need only compose.yaml, spec, identities.yaml, groundtruth.yaml and a recorder scenario; the three existing
suites run on the shared kit with unchanged scores and now report the protocol's metrics and setup cost. Every kept
app reports both passive coverage (gap / suspicious_allow) and read-only probe confirmation via compare.Judge.

## Work (in order)
1. VAL-1 Shared harness kit (`e2e/thirdparty/kit`, own go.mod, Dependabot entry) — normal+ ~35k — implementer → reviewer → fixer
   Extract the duplicated groundtruth.go / har.go and the compose lifecycle (digest pull, unique project, random
   127.0.0.1 ports, `down -v` before `up`, signal cleanup, 3 setup retries) plus a multi-identity HAR recorder
   (per-identity login, tagged steps, honest/attack suites, destructive last). Ground-truth schema v2 adds `class`
   (bola|bfla|other) and `public_by_design`; v1 files still parse. Result `extra` gains groundtruth sha256 and setup cost.
   Probe step: after the passive run, read-only `authzcov probe --execute` (loopback allowlist) on the GAP and
   `suspicious_allow` cells, Judge verdict per cell into the result; no destructive mode.
2. VAL-2 Port vampi, crapi, realworld onto the kit — normal ~25k — implementer → reviewer
   Acceptance: tp/fp/fn/tn per case identical to the committed eval/results (only generated_at, metrics fields new).
   Any case flip is a bug in the port, not a new result. Probe confirmation for VAmPI, crAPI and Juice Shop is
   imported from session 10's committed results (KAN-45, KAN-46), not re-run; RealWorld gets the kit's probe step.
   If the budget runs out, the RealWorld port moves to the head of session 21.
3. Run `make eval-vampi`, `make eval-crapi`, eval realworld (background, logs in notes/eval-<app>-s20.log) — ~5k
4. Jira batch + shard + commit — ~10k

## Owner / blocked
- Docker daemon and RAM; without it items 1–2 land with unit tests and the owner runs item 3.

## Done when
- `make check` green; the three result files regenerated with unchanged verdicts; VAL-1, VAL-2 In Review.

## Out of scope
- Destructive mode (session 33). New apps (sessions 21–24); fixing known FN/FP (KAN-101, KAN-102, KAN-104 stay as they are).
