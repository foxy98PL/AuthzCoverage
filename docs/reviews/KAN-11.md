# KAN-11 review — GitHub CI

Reviewer: Haiku (read-only), 2026-11-27. CI run 46007918706 (3c291d8): 6/6 jobs green. actionlint clean.

| # | Criterion | Verdict |
|---|---|---|
| 1 | vet, lint, test -race, govulncheck on PR/push to main, failing the run | PASS |
| 2 | every `uses:` SHA-pinned (verified vs tags), contents: read, persist-credentials false, no pull_request_target, no event interpolation in run | PASS |
| 3 | branch protection on main | owner repo setting (not verifiable from files) |
| 4 | Dependabot gomod + github-actions | PASS |

## Findings
- N1 (fixed): Dependabot gomod entry for nested module e2e/apps/tenantshop.
- N2 (fixed): Dependabot docker entry for tenantshop Dockerfile (`FROM golang:1.27`).
- N3 (accepted): govulncheck pinned by module version; bump by hand.
- N4 (accepted): local actionlint @latest; CI does not run it.
- N5 (accepted): setup-go cache on PR runs; no untrusted-PR workflows exist.

Result: passed after fix.
