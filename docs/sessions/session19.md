# Session 19 — Real-world validation: protocol and candidate triage
Status: planned
Budget: ~65k of ~100k
Depends on: session 10 (read-only probe proven on VAmPI/crAPI/Juice Shop); owner decision 2026-11-28: validation runs after read-only probing and before destructive mode (33), v0.3.0 (34) and any further feature growth

## Goal
A written, pre-registered validation protocol exists (metrics, ground-truth format, setup-cost measure, keep/drop
rules) and every candidate app is triaged keep or drop with the reason, so sessions 20–24 build only kept apps.

## Work (in order)
1. Proposed KAN epic "Phase 6: Real-world validation" + VAL-0 tickets — trivial ~5k — jira agent (orchestrator creates them)
   Proposed stories, one per line in the session files below: VAL-0 protocol + triage, VAL-1 shared harness kit,
   VAL-2 re-baseline VAmPI/crAPI/RealWorld, VAL-3..VAL-8 one per new app, VAL-9 controls, VAL-10 aggregate report,
   VAL-11 go/no-go for Phase 7, VAL-12/13 Phase 7 stub (create only after a go). The next /planner run swaps the
   "VAL-n" labels in sessions 20–25 and 35 for the real keys.
2. VAL-0a Validation protocol `docs/validation/PROTOCOL.md` — normal ~20k — implementer → reviewer
   Defines, before any new app is scored:
   - recall_gap: known authz vulns whose cell is a GAP in the honest recording; recall_allow: known vulns that raise
     `suspicious_allow` in the attack recording. Reported separately, never merged.
   - gap density (gaps / required cells) next to recall_gap, because flagging every cell gives 100% recall_gap.
   - false-alarm rate: `suspicious_allow` on items that are not authz failures (quirk, public-by-design, control) /
     all flagged; on control apps every flag is a false alarm.
   - setup cost: spec source (upstream unchanged / patched N lines / unusable), identities.yaml lines and number of
     `requirements.overrides`, config-error iterations until the first valid run, recorder steps; minimal config and
     tuned config scored separately (the tuned delta is the cost).
   - probe confirmation: per kept app, read-only `authzcov probe --execute` against the local stack, compare.Judge
     verdict (confirmed / refuted / inconclusive) per GAP and `suspicious_allow` cell; confirmed-vuln rate and
     inconclusive rate reported next to the passive metrics, never merged. Destructive mode is out of scope.
   - classes: BOLA/IDOR (object-level), BFLA (function-level; needs declared `min_role`, PLAN O5), out_of_scope.
   - pre-registration: groundtruth.yaml (with citations to upstream source or docs) is committed before the first
     scoring run; the result records its sha256; later edits need a changelog line, first-run numbers stay headline.
   - no tuning of authzcov during the phase: a miss becomes a Bug for a bug session, the report shows before/after.
3. VAL-0b Candidate triage `docs/validation/candidates.md` — normal ~25k — general-purpose/web-fetch research agent → reviewer
   Per candidate: upstream repo + licence, last commit/image date, image published or reproducible build from a
   pinned commit, OpenAPI/Swagger availability (served at runtime or in repo; Postman-only = drop), documented
   BOLA/IDOR/BFLA list, multi-user seeding, RAM. Keep rule: usable OpenAPI 2/3 spec without hand-writing + image
   that starts today pinned by digest + at least 2 documented authz vulns (controls: authz enforced, multi-user).
   Vulnerable: crAPI, VAmPI (kept, already scored), DVAPI, Juice Shop, dvws-node, Pixi, vAPI, Damn Vulnerable
   RESTaurant, Checkmarx c{api}tal, BrokenCrystals. Controls: RealWorld (kept), Gitea, Vikunja.
   Expected drops to confirm or refute, not assume: vAPI (Postman collection only), Juice Shop (spec covers only
   the B2B order API), Pixi (unmaintained image). Licence must allow committing the spec; otherwise the harness
   fetches it at run time pinned by commit and sha256.
4. Jira batch + shard + commit — ~10k
   Shard "Next": run /planner to fit the app slots of sessions 21–24 to the triage result.

## Owner / blocked
- Network access for the research agent (repos, registries); without it triage stays partial and is listed in the shard.
- Owner may veto drops or add apps; default is the keep rule above.

## Done when
- PROTOCOL.md and candidates.md reviewed and committed; every candidate has keep/drop + reason; VAL tickets exist
  (In Review for VAL-0).

## Out of scope
- Any harness code (session 20) and any authzcov change.
