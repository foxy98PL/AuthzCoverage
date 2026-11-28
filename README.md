# AuthzCoverage

> Code coverage for API authorization: find the access-control tests you never wrote.

`authzcov` reads the traffic your API tests already produce (a HAR file), matches it to your OpenAPI
spec, and shows which "who may touch whose data" combinations your tests never tried. It sends no
requests and runs offline, so it fits in CI.

**Status:** pre-release. The coverage engine and reports work. Signed pre-release binaries are on the
[Releases](https://github.com/foxy98PL/AuthzCoverage/releases) page (`v0.1.0-rc.*`); see
[CHANGELOG.md](CHANGELOG.md). You can also build from source.

<!-- GIF: owner to record -->
_A short demo recording is coming. Until then, the [quickstart](docs/quickstart.md) shows the real output._

## Why

API test suites routinely check that alice can read her own order. Few check that bob, or a user from
another tenant, cannot. Broken object level authorization (BOLA, also called IDOR) is number 1 in the
OWASP API Security Top 10, and it hides in exactly those untested combinations. authzcov makes them
visible, the way line coverage shows code your tests never ran.

## Quickstart

Needs Go, git and curl. Full walkthrough with real output: [docs/quickstart.md](docs/quickstart.md).

```
git clone https://github.com/foxy98PL/AuthzCoverage
cd AuthzCoverage
make build
(cd e2e/apps/tenantshop && go run . -addr :8090) &     # demo API with one planted bug
until curl -fs localhost:8090/openapi.yaml >/dev/null; do sleep 1; done   # wait until it is up
BASE=http://localhost:8090 e2e/recorders/tenantshop.sh  # record a test session to a HAR
./bin/authzcov coverage \
  --spec e2e/apps/tenantshop/shop/openapi.yaml \
  --identities e2e/apps/tenantshop/identities.yaml \
  --har testdata/raw/tenantshop.har
./bin/authzcov report --format html --in authzcov-out/coverage.json > report.html
lsof -ti :8090 | xargs kill                             # stop the demo API
```

## How it works

1. Record your existing tests to a HAR file.
2. authzcov matches each request to an endpoint in your OpenAPI spec.
3. It works out who made the request (from your `identities.yaml`) and who owns the object.
4. It builds an endpoint by relationship matrix: owner, same role, lower role, other tenant,
   anonymous. Each cell is covered (with the status codes seen), a gap, or not applicable.
5. It flags suspicious allows: a request that should have been refused but got a 2xx.

authzcov sends no requests. It only reads files. Unknown is never counted as covered.

## Identities

`identities.yaml` names your test users and their roles. It holds no secrets: callers are matched by
decoded JWT claims, a token hash, an environment variable name, or learned from login traffic.

```yaml
version: 1
roles: {user: 10, admin: 100}
identities:
  - {name: alice, role: user, match: {jwt: {sub: alice}}}
  - {name: bob, role: user, match: {jwt: {sub: bob}}}
  - {name: root, role: admin, match: {jwt: {sub: root}}}
```

`authzcov discover --har my.har --write identities.yaml` proposes a file from your recording.
Full format, including tenants and ownership: [docs/identities.md](docs/identities.md).

## Use it in CI

Record a HAR in your test job, then:

```
authzcov coverage --spec openapi.yaml --identities identities.yaml --har tests.har
authzcov baseline write                  # once; commit .authzcov/baseline.json
authzcov gate                            # later runs: exit 1 if coverage got worse
authzcov report --format markdown --in authzcov-out/coverage.json   # for a PR comment
authzcov report --format sarif --in authzcov-out/coverage.json > authzcov.sarif
authzcov export --plan --in authzcov-out/coverage.json --out plan.json   # gaps as a probe plan (docs/plan.md)
```

`gate` fails on new gaps, regressions, a coverage drop, or expired waivers (`--fail-on` and
`--max-drop` tune this). Accepted gaps go in `.authzcov/waivers.yaml`. Upload the SARIF file with
GitHub code scanning.

Or use the GitHub Action, which verifies the release checksum, writes the report to the job summary
and runs the gate. With `sigstore/cosign-installer` before it, the checksum file's signature is
verified too; without cosign only the checksum is checked (protects against corruption, not a
tampered release):

```yaml
- uses: sigstore/cosign-installer@881c63bd87e38389154debd8331404ce7ca8a3ab # v4.1.4
- uses: foxy98PL/AuthzCoverage@v0
  with:
    spec: openapi.yaml
    identities: identities.yaml
    har: tests.har
    baseline: .authzcov/baseline.json
```

Inputs, outputs and permissions: [docs/action.md](docs/action.md).

Other commands: `authzcov explain` shows how one request is matched to the spec
([docs/explain.md](docs/explain.md)). Speed numbers: [docs/benchmarks.md](docs/benchmarks.md).

## Recording HARs

- Playwright: `browser.newContext({ recordHar: { path: 'tests.har' } })`.
- mitmproxy: run `mitmdump` with a HAR export and point your test client at the proxy.
  `e2e/recorders/vampi.sh` is a working example.
- Browser devtools: Network tab, "Save all as HAR".

**Never commit HAR files.** They contain real tokens, cookies and passwords. This repository
git-ignores them. authzcov redacts credentials when it reads a HAR, but the file itself is not
redacted.

## Security

See [SECURITY.md](SECURITY.md).

- Credentials are hashed at ingest (only a 12-character fingerprint is kept). Raw credentials,
  passwords and token-like values are never written to `coverage.json` or any report.
- Query strings are dropped and bodies are size-limited and scrubbed before use.
- `coverage`, `report` and `gate` make no network calls.

### Privacy and telemetry

authzcov has no telemetry. It does not phone home, check for updates, or send usage data. The
`coverage`, `report` and `gate` commands make no network calls. You can check this: run them with
the network off, or read the test suite, which runs the command with a transport that fails on any
request.

### Releases and signatures

This applies from the first tagged release onward; no release has been published yet. Each release on
[GitHub Releases](https://github.com/foxy98PL/AuthzCoverage/releases) contains archives for linux,
darwin and windows (amd64 and arm64), a per-archive SBOM (SPDX, from syft), `checksums.txt`, and a
keyless [Sigstore](https://www.sigstore.dev/) signature bundle `checksums.txt.sigstore.json`. Build
provenance is attested by GitHub for the archives.

To verify a download, put the archive, `checksums.txt` and `checksums.txt.sigstore.json` in one
directory, then:

```sh
# 1. The checksums file was signed by this repository's release workflow
#    (needs cosign v3 or newer; releases are signed with cosign v3).
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/foxy98PL/AuthzCoverage/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 2. The archive matches the signed checksums.
sha256sum --ignore-missing -c checksums.txt

# 3. GitHub build provenance for the archive (needs the gh CLI).
gh attestation verify authzcov_<version>_linux_amd64.tar.gz --repo foxy98PL/AuthzCoverage
```

Do not use a release whose signature or checksum check fails. Release builds use `-trimpath` and
commit timestamps; they are designed so that a rebuild from the tag gives the same binaries (not yet
checked independently).

## Known limitations

authzcov is pre-release. Measured numbers (mutants, ablation, VAmPI, crAPI, scaling) are in
[eval/README.md](eval/README.md); they are regenerated for each release.

- **Object IDs come from path parameters only.** Objects addressed by a query or body parameter are
  not seen (for example crAPI's mechanic report via a query parameter is missed). Workaround: none yet;
  `requirements.overrides` only picks among path parameters.
- **`suspicious_allow` looks at status and body only.** It fires on a 2xx (and a non-empty JSON body
  for GET/HEAD) on another user's object. Apps that ignore the path parameter and act on the caller's
  own record cause false alarms: on VAmPI, `PWCHANGE` (v0) and `U2-EMAIL` (v0 and v1) are flagged
  although nothing of another user was changed. Workaround: waive the finding with a reason.
- **Function-level `suspicious_allow` needs declared facts.** It fires only on an anonymous 2xx where
  the spec's `security` requires auth, or on a 2xx below a declared `min_role`. Without either, a
  missing check on such an endpoint is not found (VAmPI `_debug` is a miss). Workaround: declare
  `security` in the spec and `min_role` in `identities.yaml`.
- **Learned minimum roles are circular.** Without `min_role`, the minimum is the lowest role that got a
  2xx, so an endpoint that is too permissive looks correct. Workaround: declare `min_role`.
- **External `$ref` is rejected** (exit 3). Workaround: bundle the spec first (`redocly bundle` or
  `swagger-cli bundle`).
- **Memory is linear in HAR size** (about 1.7 KB per entry: 1.6 GiB at 1M entries). Time is close to
  linear. Workaround: split large recordings, or record only the authorization tests (KAN-91).
- **No active probing yet.** authzcov only reads recordings; `export --plan` lists the gaps for another
  tool to probe. Active probing is planned for Phase 4.
- **A role with one identity cannot cover `same_role_other_user`**, which needs two users of that role.
  Workaround: add a second identity for the role.
- **No `cross_parent` checks** (an object reached through a parent it does not belong to, for example
  `/users/{u}/orders/{o}`).
- **Basic, cookie and API-key callers are `unknown`** unless `identities.yaml` has a matching
  `credentials` rule. Unknown never counts as covered.

Measured at 3ef6707 (`eval/results/`): tenantshop mutants 11 of 11 detected, no false alarm on the
unmutated app; ablation 16 of 16 dropped requests turn exactly their cell into a gap; VAmPI precision
0.842 and recall 0.889 (16 tp, 3 fp, 2 fn, 11 tn, 12 out of scope); crAPI v1.1.6 precision 0.8 and
recall 0.667 (8 tp, 2 fp, 4 fn, 8 tn, 11 out of scope); scaling 1k / 10k / 100k / 1M entries in
45 ms / 184 ms / 1.3 s / 16.2 s with 20 / 34 / 186 / 1654 MiB peak RSS.

## Roadmap

| Phase | Scope | Status |
| --- | --- | --- |
| 0 Setup | Local repo, quality gate, VAmPI recording | in progress |
| 1 Coverage engine | Spec loader, matcher, HAR ingest, identities, ownership, classifier, terminal matrix | done |
| 2 Reports and gate (v0.1) | JSON, Markdown, HTML, SARIF, baseline, CI gate | done locally; GitHub Action and signed releases planned |
| 3 Launch | Quickstart, examples (VAmPI, crAPI, RealWorld), redact command | in progress (quickstart written) |
| 4 Probe (gated) | Run only missing combinations against test environments, dry-run by default | planned |
| 5 Extensions | Spec-less mode, Spring/NestJS/Next.js route extraction, OpenTelemetry, GraphQL | ideas |

## Development

Requirements: Go (see go.mod), make. Docker is optional (demo apps).

```
make build   # ./bin/authzcov
make test    # unit tests
make check   # vet + lint + tests (-race) + govulncheck
make e2e     # tenantshop end-to-end test
make hooks   # install pre-commit hook
```

Setup: [docs/dev-setup.md](docs/dev-setup.md). Plan and progress: `docs/PLAN.md`, `docs/PROGRESS.md`.

## License

Apache-2.0. Bundled third-party demo specs are credited in NOTICE.
