# KAN-74 review — tenantshop demo

Reviewer: Haiku (read-only), started by the implementation orchestrator (no review orchestrator running), 2026-11-27.

| # | Criterion | Evidence | Verdict |
|---|---|---|---|
| 1 | compose up serves spec + OrgA/OrgB × 2 customers + 1 admin | compose.yaml, Dockerfile, shop seed; `shop_test.go:TestSeedShape`, `TestOpenAPIServed` (added in fix); compose build ok | PASS |
| 2 | HAR JWTs carry org_id | `e2e_test.go:TestTenantshopEndToEnd` (decodes every Authorization header) | PASS |
| 3 | seeded bug → suspicious_allow other_tenant, none elsewhere | e2e findings loop; `shop_test.go:TestSeededBugAdminBReadsOrgAOrder` | PASS |
| 4 | `go test -tags e2e` OTHER_TENANT column vs golden | e2e golden compare `testdata/golden/tenantshop.txt` | PASS |

Checks: `make e2e` ok; `go test -tags e2e -count=3` ok; go.mod has no requires; no net/http leak in root; no HAR tracked; only demo key/password as secrets.

## Findings
- F1 (nit, fixed): no automated check of seed shape / `/openapi.yaml` → TestSeedShape, TestOpenAPIServed.
- F2 (nit, accepted): only suspicious_allow kind asserted; golden table covers the rest.
- F3 (nit, fixed): `openapi.yaml` symlink (breaks on Windows) removed; spec path is `shop/openapi.yaml`.
- F4 (nit, accepted): full-table golden is intentionally strict.

Result: passed after fix.
