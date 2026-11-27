# KAN-88 review (Haiku, read-only, 2026-11-27)

All 6 acceptance criteria pass with tests (suspicious_test.go, suspicious_e2e_test.go, reporter tests). Rules R1, R2,
R5, R6 pass; R3, R4 were test gaps.

## Findings and handling (fixed by orchestrator)
1. **F1 (test gap, R4)**: no test that waivers keep suspicious_allow. → TestApplyKeepsSuspiciousAllow (waivers).
2. **F2 (test gap, R3)**: no negative test for raw IDs in messages. → TestReviewFixes asserts object ID, path and
   body never appear. Note: the object *tenant* value (from a declared `tenancy.tenant_params` path param) does appear
   ("in tenant OrgB") — intended; tenant params are declared by the user as tenant names/ids, not object ids.
3. **F3 (latent)**: an anonymous identity skipped the caller-confidence check under any relationship. → guard:
   anonymous only counts under RelAnonymous. Test added.
4. **F4**: other_tenant with a known tenant and a learned owner named only the owner. → message names both:
   "bob (tenant t2) received 200 for an object owned by alice in tenant t1". Test added.
5. **F5 (by design, documented)**: false negatives — GET 200 with a non-JSON or > 64 KiB body, HEAD 200 without a
   body are not flagged (no captured body = no evidence; "unknown never counts").
6. **F6**: POST 201 to a tenant-param create endpoint is object-level and flagged as other_tenant — correct.
7. **F7**: other_tenant with neither known tenant nor learned owner → no finding (unknown never counts) — intended.
8. **F8–F10 (low)**: empty-name identity labelled "anonymous"; writes count on any 2xx; markdown error if even the
   minimal build is too big (unreachable). → noted.

Status: passed after fix.
