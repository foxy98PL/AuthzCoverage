# Changelog

All notable changes to authzcov are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). Pre-release versions (`-rc.N`) may change behaviour
between candidates.

## [0.1.0-rc.2] - unreleased

Changes since v0.1.0-rc.1. Coverage percentages for the same inputs can differ from rc.1; see
"Changed".

### Added

- `requirements.overrides[].min_role` in `identities.yaml`: declares the lowest role allowed to call
  a function-level or tenant-scoped endpoint. `object_param` is now optional when `min_role` is set
  (KAN-92). See `docs/identities.md`.
- `suspicious_allow` on function-level and tenant-scoped endpoints, from declared facts only: an
  anonymous 2xx on an operation whose effective OpenAPI `security` requires authentication, and a
  `lower_role` 2xx below a declared `min_role` (KAN-92).
- Validation benchmark (`make eval`, `eval/README.md`): tenantshop mutants (one removed check each),
  cell ablation, VAmPI against a hand-written ground truth, and a scaling run from 1k to 1M entries.
  Results are written to `eval/results/*.json` (KAN-90).
- crAPI v1.1.6 benchmark (`make eval-crapi`): scripted recorder, images pinned by digest,
  ground truth with citations, teardown on exit or signal (KAN-12, KAN-90).
- `authzcov export --base-path`, same validation as `coverage --base-path` (KAN-34).
- `export --plan` warns when the `--har`, `--spec` or `--identities` file differs from the hash
  recorded in `coverage.json` (KAN-34).
- `CHANGELOG.md`; "Known limitations" section in the README.

### Changed

- Anonymous requests now cover the `anonymous` cell without a known object owner. An anonymous caller
  is never the owner, so the relationship is certain. Unknown callers still never count as covered
  (KAN-92).
- Tenant-scoped endpoints (the object parameter is a `tenancy.tenant_params` parameter, for example
  `/orgs/{orgId}/orders`) have new required cells: `owner` (a member of the addressed tenant with at
  least the minimum role), `lower_role`, `other_tenant` and `anonymous`. The `owner` and
  `same_role_other_user` cells that no recording could cover are no longer required. Percentages for
  specs with such endpoints change (KAN-92).
- `lower_role` is no longer required on a function-level or tenant-scoped endpoint when the minimum
  role (declared `min_role`, else learned) is already the lowest defined role, because no identity can
  test it. It is still required when the minimum is unknown (KAN-92).
- New `min_role` key under `requirements.overrides`. When set, it replaces the learned minimum role
  for that endpoint. A `min_role` that is not a key of `roles` is an error with `file:line` (exit 2)
  (KAN-92).
- `authzcov export --plan --har ...` now requires `--out`. Plans with raw object IDs are never written
  to stdout; omitting `--out` is a usage error (exit 2). The file is written with mode 0600
  (KAN-34).
- Golden outputs under `testdata/golden/` and `e2e/apps/tenantshop/testdata/golden/` were regenerated
  for the changes above.

### Fixed

- `export --plan`: raw-ID plans could previously be sent to stdout; they now need `--out` (KAN-34).
- Plan schema test now checks `plan_version`, patterns and `additionalProperties`; plan sort wording
  corrected; the no-credentials test covers cookie, API key and query-string tokens (KAN-34).
- VAmPI benchmark recorder: waits for `/createdb` and admin login before recording, and retries a
  session that loses a user to VAmPI's book-title collision (KAN-90).

- GitHub Action self-test asserted the pre-KAN-92 tenantshop numbers (KAN-92).

### Security

- Raw object IDs from `export --plan --har` are only written to a 0600 file, never to stdout
  (KAN-34).

Not in this release: bounded memory for large HARs (KAN-91). Memory is still linear in HAR size.

## [0.1.0-rc.1] - 2026-11-27

First published pre-release.

- Commands: `coverage`, `report`, `baseline write|diff`, `gate`, `discover`, `explain`, `export --plan`,
  `redact --pseudonymize`, `version`. Offline: `coverage` sends no requests.
- Inputs: HAR and `.har.zip`, OpenAPI 3.x (external `$ref` rejected), `identities.yaml` v1 (JWT claims,
  token hash, environment variable name, learned logins, Basic, cookie and API-key callers, tenants,
  ownership hints).
- Engine: segment-trie matcher, ownership learning, relationship classifier, endpoint by relationship
  matrix (owner, same role, lower role, other tenant, anonymous), `--strict`, `suspicious_allow` on
  object-level endpoints, waivers and baselines.
- Reports: terminal table, `coverage.json` v1, Markdown, HTML (single file, CSP), SARIF.
- Gate: `authzcov gate` with new-gaps, regressions, drop and expired-waivers rules.
- CI: composite GitHub Action (checksum and cosign verification, job summary, optional SARIF upload).
- Releases: six archives (linux, darwin, windows; amd64, arm64), SBOMs, `checksums.txt`, cosign
  keyless bundle and GitHub build provenance.
- Probe plan: `export --plan` writes gaps as a versioned JSON plan (`schema/plan.v1.json`).

[0.1.0-rc.2]: https://github.com/foxy98PL/AuthzCoverage/compare/v0.1.0-rc.1...HEAD
[0.1.0-rc.1]: https://github.com/foxy98PL/AuthzCoverage/releases/tag/v0.1.0-rc.1
