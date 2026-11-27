# Contributing to AuthzCoverage

Thanks for wanting to help. This page covers what you need for a first pull request.

Correctness beats features. A false "covered" is the worst bug this project can have. An unknown result must never count as covered.

## Ground rules

- Never commit real traffic. No real HAR files, tokens, cookies or customer data.
- Never record systems you do not own or have permission to test.
- No network in the coverage path. `net/http` may only be used in `internal/probe/exec`. The `depguard` rule in `.golangci.yml` enforces this for all non-test code, so `make lint` fails if you break it.
- Determinism. The same input must give byte-identical output. No map-order, clock or random dependence in reports.
- Raw credentials must never survive ingest. Only redacted fingerprints are kept.
- Do not report security problems in a public issue. See [SECURITY.md](SECURITY.md); it uses GitHub private vulnerability reporting.

## Set up

You need Go (the version in the `toolchain` line of `go.mod`), `make` and `git`. `golangci-lint` v2 is needed for `make lint`; without it the target prints a warning and skips. `govulncheck` is needed for `make vuln`. See [docs/dev-setup.md](docs/dev-setup.md) for details.

```
git clone https://github.com/foxy98PL/AuthzCoverage
cd AuthzCoverage
make hooks   # optional but recommended: installs the pre-commit hook
make build
make test
```

## Commands

| Command | What it does | Network |
| --- | --- | --- |
| `make build` | Builds `bin/authzcov`. | no |
| `make test` | `go test ./...` | no |
| `make lint` | `golangci-lint run ./...` | no |
| `make e2e` | Vet and test the `tenantshop` demo app plus the end-to-end tests. | no |
| `make golden` | Rewrites `testdata/golden/*.txt`. Review the diff by hand. | no |
| `make fuzz FUZZTIME=5s` | Runs every `Fuzz*` target for 5 seconds each (default 30s). | no |
| `make check-offline` | `vet`, `lint`, `fixturecheck` and `go test -race ./...`. | no |
| `make vuln` | `govulncheck ./...` | yes (vulnerability DB) |
| `make check` | `check-offline` plus `vuln`. | yes |

`make e2e` does not need Docker. The `tenantshop` app runs in-process. Docker is only needed for the compose demo.

The pre-commit hook (`make hooks`) refuses to commit `*.har` files and anything under `testdata/raw/`, then runs `make check-offline`.

CI runs on every pull request: `go vet`, `golangci-lint`, `go test -race`, `govulncheck`, the `tenantshop` end-to-end tests (`make e2e`), a fuzz smoke run (`make fuzz FUZZTIME=10s`) and `fixturecheck`. The separate `Action self-test` workflow (`.github/workflows/action-test.yml`) exercises the composite GitHub Action end to end. A pull request needs all of them green.

## Code layout

`cmd/authzcov` is the entry point. Packages under `internal/`:

- `baseline`: stores the coverage state of each required cell for the gate.
- `basepath`: detects the URL prefix under which recorded traffic reaches the API.
- `cli`: cobra commands and flags; no business logic.
- `config`: loads and validates `identities.yaml`.
- `gate`: decides whether a coverage result passes the CI gate.
- `identity`: extracts redacted credentials from request headers and tokens.
- `ingest/har`: streams HAR files into redacted exchanges.
- `match`: maps a method and path to an OpenAPI endpoint.
- `matrix`: builds the endpoint by relationship coverage matrix.
- `model`: structs shared by all stages.
- `ownership`: learns who owns which object from recorded traffic.
- `redact`: turns secrets into fingerprints and redacts traffic-derived text.
- `relate`: classifies the relationship between a caller and an object.
- `report/*`: renderers for `coverage.json`, HTML, Markdown, SARIF and a text table.
- `spec`: loads an OpenAPI 3.x document.
- `suspicious`: finds `suspicious_allow` findings.
- `testutil/hartest`: builds synthetic HAR fixtures for tests.
- `waivers`: loads and validates `waivers.yaml`.

Format docs: [docs/identities.md](docs/identities.md), [docs/quickstart.md](docs/quickstart.md), [docs/action.md](docs/action.md), [docs/releasing.md](docs/releasing.md).

## Workflow

1. Open an issue, or pick an existing one. Say you are working on it.
2. Branch from `main`.
3. Write a failing test first. This is required for `match`, `identity`, `relate` and `matrix`, where a mistake can produce a false "covered".
4. Every bug fix adds a table-test row or a fuzz seed that fails without the fix.
5. Keep pull requests under about 400 lines of change. Split larger work.
6. Use [Conventional Commits](https://www.conventionalcommits.org/), for example `fix(match): handle trailing slash`. Reference the issue number in the body or the pull request.
7. Sign off every commit (DCO): `git commit -s`.

## Test fixtures

Fixtures are generated in Go tests with `internal/testutil/hartest`. Do not check in recorded traffic. Real recordings must never be committed. The pre-commit hook rejects `*.har` files and `testdata/raw/`. `make fixturecheck` (part of `make check-offline` and a CI job) fails on any JWT-shaped string in any file (binary files and zip members included) whose `iss` is not `authzcov-test`, and on any HAR request host outside the demo allowlist (`localhost`, `127.0.0.1`, `::1`, `example.com`, `example.test`, `*.example.com`, `*.test`). It treats any JSON with a top-level `log.entries` array as a HAR whatever its file name, and looks inside `.zip` files the same way. Files over 50 MiB fail unless their path is in the allow list. The few existing exceptions are listed, one token each, in `tools/fixturecheck/allow.txt` with a reason. Test tokens use the issuer `authzcov-test` and a key that is not a secret.

If you need to share a reproduction, build it with `hartest`. When `authzcov redact --pseudonymize` is available, it can help turn a recording you own into a shareable one, but check the result by hand before you share it.

## Pull request checklist

- [ ] Tests added or updated; the failing-first test is in the history or described.
- [ ] Golden files regenerated with `make golden` and the diff reviewed, if output changed.
- [ ] A fuzz seed or table row added, if a parser or a bug fix is involved.
- [ ] `make check-offline` passes (and `make check` if you have network).
- [ ] Docs updated if a file format or flag changed.
- [ ] File-format changes are additive within a schema version.
- [ ] No new dependency, or the dependency was agreed in an issue first.
- [ ] No real traffic, credentials or personal data in the diff.
- [ ] Security-relevant change (redaction, probe guardrails, parsers) is called out in the description so a maintainer can review it with extra care.

## Dependencies

Direct dependencies are limited to: cobra, kin-openapi, yaml/v3 and golang-jwt/v5. A new dependency needs discussion in an issue before you write code. Prefer the standard library.

## Licence

The project is under the Apache License 2.0 (see [LICENSE](LICENSE)). Your contributions are licensed under the same terms. Do not paste or port code from AGPL or other copyleft projects. Interoperate through file formats only.
