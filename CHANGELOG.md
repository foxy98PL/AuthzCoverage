# Changelog

All notable changes to authzcov are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). Pre-release versions (`-rc.N`) may change behaviour
between candidates.

## [Unreleased]

### Added

- `authzcov fingerprint` prints the full SHA-256 of a cookie, API key or token read from stdin, for
  `token_sha256` in `identities.yaml`; `discover` points to it (KAN-33).

## [0.1.0] - YYYY-MM-DD

First stable release. Changes since v0.1.0-rc.2. Set the date when the tag is pushed
(see `docs/releasing.md`).

### Added

- `object_param` on `in: query` parameters in `identities.yaml`, so objects addressed by a query
  parameter can be tracked (KAN-104).
- Exclusive list rules in ownership learning: an object seen only in one caller's list response is
  owned by that caller (KAN-102).
- `export --plan` resolve hint and a note when a plan hash does not match (hash-miss note); object ID
  handling documented (KAN-94).
- HTML report: filter controls with a tested JS contract and CSP-safe markup (KAN-100).
- crAPI evaluation results refreshed after KAN-102 (precision 0.833, recall 0.833; `make eval-crapi`).

### Changed

- Coverage pipeline memory is bounded: the 1M-entry HAR run peaks at 256 MiB RSS instead of
  1665 MiB (KAN-91).
- CI runs the 10k-entry benchmark gate (`scripts/bench.sh`, `BENCH_MAX_RATIO`) and a hard 5 s test
  (KAN-96); fuzzing runs 30 s per target (KAN-103).

### Fixed

- Gate: `new-gaps` also fails on a new uncovered cell on an existing endpoint, not only on new
  endpoints (KAN-93).
- fixturecheck scans every text fixture for non-demo hosts, not only HAR files (KAN-99), and covers
  oversize files.
- Corrected `suspicious_allow` reason text in the eval report (KAN-101).

### Known limitations

- **Unknown never counts as covered.** A request whose caller cannot be identified, or whose object
  owner is not known, leaves the cell uncovered. Coverage can read lower than reality; add identities
  or ownership hints to raise it.
- **crAPI challenge C2 (mechanic report by query parameter) is still a false negative** in
  `make eval-crapi`. KAN-104 allows `object_param` on query parameters, but the crAPI identities file
  has no such override and no rule learns the report owner (it needs a create rule on
  `contact_mechanic`). Follow-up, not in this release.
- **VAmPI `_debug` is a false negative.** The spec declares no `security` on `GET /users/v1/_debug`, so
  the endpoint looks public and a missing check on it is not found. Workaround: declare the
  intended security in the spec or a `min_role` override.
- `suspicious_allow` uses status and body only; apps that ignore the path parameter produce false
  alarms (VAmPI `PWCHANGE`, `U2-EMAIL`). See the README "Known limitations".

## [0.1.0-rc.2] - 2026-11-28

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

[0.1.0]: https://github.com/foxy98PL/AuthzCoverage/compare/v0.1.0-rc.2...v0.1.0
[0.1.0-rc.2]: https://github.com/foxy98PL/AuthzCoverage/compare/v0.1.0-rc.1...v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/foxy98PL/AuthzCoverage/releases/tag/v0.1.0-rc.1
