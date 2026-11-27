# KAN-19 review (Haiku, read-only, 2026-11-27)

`make check` PASS; `make fuzz FUZZTIME=10s` PASS (5 targets).

| Criterion | Result | Evidence |
| --- | --- | --- |
| (a) tenant param → other_tenant even with unknown owner | proven (unit) / weak (e2e) | relate "param tenant differs owner unknown", matrix TenantParam tests; no CLI case with unknown owner |
| (b) list-learned object → cell marked inferred | proven | TestLearnFromLists, TestInferredMarker, golden lists-fixture `ok~` |
| (c) --strict, inferred only → not covered | proven | TestStrict, TestStrictFlagEffect, golden lists-fixture-strict |
| (d) unknown owner → unknown column, never coverage | proven | matrix tests |
| (e) three hand-labelled goldens | partial | 4 fixture goldens; no real-app recordings yet |

Rules R1–R5 pass (covered condition, tenant-param still needs IDConf ≥ learned, copies not mutated,
reversed-order goldens, no JWTs in goldens).

## Findings
- F1 (owner decision): anonymous on object-level endpoints follows rule 4.2 literally (needs owner conf ≥ inferred;
  `ok~` / GAP under --strict). Option: exempt anonymous from the owner condition.
- F2: fixed — `TestOtherTenantUnknownOwner` (carol GET /orgs/OrgA/projects/nope → OTHER_TENANT `ok 403`, no `~`).
- F3: real-app golden after the VAmPI recording exists.
