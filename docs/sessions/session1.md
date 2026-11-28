# Session 1 — Query-param object IDs and review leftovers
Status: done
Budget: ~75k of ~100k
Depends on: none (crAPI groundtruth check needs a Docker run, see Owner / blocked)

## Goal
Object-level detection works for object IDs passed as `in: query` parameters (crAPI C2 is no longer an
expected miss in the code path), and the open low findings from the KAN-93, KAN-99 and KAN-94 reviews are closed.

## Work (in order)
1. KAN-104 Object-level detection for query-param IDs (object_param on in:query parameters) — 🔒 ~40k — implementer (tests first) → reviewer → fixer
   `requirements.overrides[].object_param` may name a declared `in: query` parameter; populate the object params
   from the query (cli/pipeline.go, ownership.go, model Endpoint.Kind). Failing tests first in identity, relate,
   matrix and suspicious. Validation errors for an object_param that names no declared path/query param.
   Update docs/identities.md and the crAPI groundtruth note for C2 (flip to expected TP only once the crAPI run confirms it).
   Advisor (Opus) only if a security trade-off appears (e.g. repeated query keys, array params: fail to unknown).
2. KAN-93 CLI end-to-end test for `gate --fail-on new-gaps` (new uncovered cell on an existing endpoint) — normal ~10k — implementer → reviewer
   Open low from the KAN-93 review: only unit tests exist today.
3. KAN-99 review lows F6 (bare hosts), F7, F9 — normal ~10k — implementer → reviewer
   Findings are in the KAN-99 review notes; keep the fixturecheck allowlist fail-closed.
4. KAN-94 leftover F3: miss-note wording in export --plan — trivial ~5k — implementer
5. Jira batch (jira agent) + shard + commit — ~10k
   KAN-104 In Review with comment; comments on KAN-93, KAN-99, KAN-94 for the leftovers.

## Owner / blocked
- crAPI Docker eval (~5 min) to confirm the KAN-102 flips (bola_vehicle, users/all) and the KAN-104 C2 flip.
  If the Docker daemon is up in the agent environment, the orchestrator runs it; otherwise leave the groundtruth
  as expected-miss for C2 and list the run in the shard.

## Done when
- `make check` green; new 🔒 tests were written and failing before the implementation.
- KAN-104 In Review with a Jira comment; leftover comments on KAN-93/99/94.

## Out of scope
- Owner-gated parts of KAN-97/98/100/103 (session 1.1), bounded memory KAN-91 (session 2).
