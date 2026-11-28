# Session 26 — CONDITIONAL STUB: live report (`authzcov watch`) and identity-switch recording
Status: planned
Budget: ~? of ~100k (stub: /planner sizes it after the go decision)
Depends on: session 25 go decision by the owner; if no-go, /planner deletes this file

## Goal
If validation shows the engine is worth it and setup cost is the bottleneck: a localhost-only HTML report that
re-aggregates HARs as they land, and a documented workflow for recording several identities in one session.

## Work (in order) — to be sized and split after the go decision
1. Proposed VAL-12 `authzcov watch` — 🔒-adjacent normal — watch a directory of HARs, rerun coverage offline, serve
   the existing HTML report on 127.0.0.1 only; no network in coverage, no raw credentials or IDs in what it serves.
2. Proposed VAL-13 identity-switch recording workflow — docs + import — mitmproxy and Burp export as the
   recording path (one HAR per identity or a tagged session); own MITM proxy `authzcov record` stays deferred.

## Owner / blocked
- Go/no-go from session 25. UI/proxy scope beyond the above needs a new owner decision.

## Done when
- Defined when the stub is planned for real.

## Out of scope
- `authzcov record` (own MITM proxy), hosted dashboard (KAN-55, session 30).
