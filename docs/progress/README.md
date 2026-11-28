# Progress shards

One file per orchestrator session or round, named `YYYY-MM-DD-HHMM-<slug>.md` (UTC+local as written; names sort
chronologically). **Read only the newest one:**

```sh
ls docs/progress/2*.md | tail -1
```

Rules
- The newest shard is the full resume state: done, in progress, next (ordered), open decisions, gotchas. ≤ ~60 lines.
- Write a **new** shard at each orchestrator restart (~100k tokens) or end of round; carry forward only what is
  still open. Older shards are frozen history — never edit them, never read them unless chasing a specific fact
  (`grep -l KAN-xx docs/progress/*.md`).
- Durable decisions go to `docs/PLAN.md`, not into shards.
- No secrets, tokens, HAR content or personal data (shards are committed and public).
