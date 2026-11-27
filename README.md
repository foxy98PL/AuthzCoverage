# AuthzCoverage

> Code coverage for API authorization: find the access-control tests you never wrote.

**Status:** pre-alpha, under active development. Not ready for use.

## Why
API test suites routinely check that alice can read her own order, but almost none check that bob *cannot*.
Broken object level authorization (BOLA/IDOR) is #1 in the OWASP API Security Top 10, and it hides in
exactly those untested combinations. AuthzCoverage makes them visible.

## How it works
1. Record your existing tests to HAR (proxy or Playwright).
2. AuthzCoverage matches each request to an OpenAPI endpoint, identifies the caller and the object owner.
3. It builds an endpoint × relationship matrix and reports combinations your tests never tried.

It sends no requests.

## Roadmap
| Phase | Scope | Status |
| --- | --- | --- |
| 0 Setup | Local repo, quality gate, VAmPI recording | in progress |
| 1 Coverage engine | Spec loader, matcher, HAR ingest, identities, ownership, classifier, terminal matrix | in progress (v0 slice working on fixtures) |
| 2 Reports and gate (v0.1) | JSON, Markdown, HTML, SARIF, baseline, CI gate, GitHub Action, signed releases | planned |
| 3 Launch | Quickstart, examples (VAmPI, crAPI, RealWorld), redact command | planned |
| 4 Probe (gated) | Run only missing combinations against test environments, dry-run by default | planned |
| 5 Extensions | Spec-less mode, Spring/NestJS/Next.js route extraction, OpenTelemetry, GraphQL | ideas |

## Design principles
- Passive by default: no network access in the coverage path.
- Raw credentials are hashed at ingest and never written anywhere.
- "Unknown" is never reported as covered.
- Deterministic, CI-friendly output.

## Development
Requirements: Go (see go.mod toolchain), make, Docker (for demo apps).

    make build   # ./bin/authzcov
    make test    # unit tests
    make check   # vet + lint + tests (-race) + govulncheck
    make hooks   # install pre-commit hook (runs make check-offline)

    make fuzz    # all fuzz targets, FUZZTIME=30s each

Setup: docs/dev-setup.md. Plan and progress: docs/PLAN.md, docs/PROGRESS.md.

Try it (after recording with `e2e/recorders/vampi.sh`):

    ./bin/authzcov coverage --spec testdata/specs/vampi.yml \
      --har testdata/raw/vampi.har --identities testdata/identities/vampi.yaml

## Security
No telemetry. Private local project for now; see SECURITY.md.

## License
Apache-2.0. Bundled third-party demo specs are credited in NOTICE.
