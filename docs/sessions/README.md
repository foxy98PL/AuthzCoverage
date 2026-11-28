# Session plans

One file per planned orchestrator session, written by `/planner` (the Opus `planner` agent). Progress shards
(`docs/progress/`) record what happened; session files record what is planned.

## Names and order

- `session<N>.md`: planned work, N = 1, 2, 3 … New sessions take the next integer after the highest one.
- `session<N>.<k>.md`: bug fixes for bugs introduced by session N's work, k = 1, 2 … They sort right after
  session N, so they run before any later planned session.
- Order: `ls docs/sessions/session*.md | sort -V` (gives 1, 1.1, 1.2, 1.10, 2, 10). Numbers are never reused or
  renumbered.

## Picking up (/start, /resume)

The session to work on is the **first file in `sort -V` order whose Status isn't `done`**:

```sh
for f in $(ls docs/sessions/session*.md | sort -V); do grep -q '^Status: done' "$f" || { echo "$f"; break; }; done
```

- `planned`: set it to `active`, then work its list in order. The list is the approved plan, same as a shard's "Next".
- `active`: a restart in the middle. The newest shard says what's left; continue from there.
- None left: follow the shard's "Next" and suggest `/planner`.

## Lifecycle

`planned` → `active` (orchestrator, at start) → `done — shard <shard file name>` (orchestrator, when the list is
finished). At a restart with work left, it stays `active` and the shard lists the remainder. Only the planner
rewrites or deletes `planned` files; nobody edits `active` or `done` files except their Status line. Commit
Status changes with the shard.

## Bugs found mid-session

When a Jira Bug is created (review finding split out, eval failure, owner report), the orchestrator adds it to
the open bug session of the session that introduced it (`session<N>.<k>.md` with Status `planned`), or creates
the next `session<N>.<k>.md` from the template below. That's a mechanical step: no `/planner` run needed. A bug
that blocks the current session's goal is fixed in the current session instead.

## Budget

An orchestrator context restarts at ~150k and a reload costs ~45k, so a session has **~100k** of work.
Starting estimates for the orchestrator's own context (calibrate from how many tickets fit in past shards):
trivial ticket (docs, config, CI, < 30 lines) ~5–10k; normal ticket (implementer → reviewer → fixer) ~20–30k;
🔒 package ticket or one with an Opus advisor question ~30–40k; Jira batch + shard + commit at the end ~10k.

## Template

```markdown
# Session <N> — <goal in a few words>
Status: planned
Budget: ~<est>k of ~100k
Depends on: <session / owner decision / none>

## Goal
<1–3 lines: what is true when this session ends>

## Work (in order)
1. KAN-xx <summary> — <trivial | normal | 🔒> ~<k>k — <agents: implementer → reviewer → fixer | none>
   <one line: key constraint, AC pointer or split step>

## Owner / blocked
- <decision or missing capability; what to do if it's still open>

## Done when
- <checks: make check, eval, Jira In Review …>

## Out of scope
- <what's deliberately left for later sessions>
```
