# KAN-89 review — learn_from_create response_json

Reviewer: Haiku (read-only), 2026-11-27, commit 4e9a7cf. Tests and `make e2e` pass.

| # | Criterion | Evidence | Verdict |
|---|---|---|---|
| 1 | 2xx create by known caller → owner, learned | ownership_test.go:TestCreateResponseLearned | PASS |
| 2 | non-2xx / non-scalar / missing / redacted / truncated → nothing learned | TestCreateResponseNotLearned (11 cases) | PARTIAL → F2 |
| 3 | both or neither source → file:line error; `[]` rejected | config_test.go TestParseErrors | PASS |
| 4 | Location header (optional) | skipped, not half-implemented | PASS |
| 5 | tenantshop response_json: id, golden unchanged | identities.yaml, shop.go, golden diff empty | PASS |
| 6 | docs + schema match config keys | identities.md, identities.v1.json oneOf | PASS |

## Findings
- F1 (important, fixed): TestCreateRequestRedactedNotLearned.
- F2 (important, fixed): TestLearnFromCreateResponseOversizedNotLearned (har.MaxBody+1).
- F3 (nit, fixed): TestLearnFromCreateResponseJSON asserts the object entry exists, then no raw id anywhere.
- F4 (nit): request_json placeholder rejection is a behaviour change; noted in commit message.

Result: passed after fix.
