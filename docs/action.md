# GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only with sarif: true

steps:
  - uses: actions/checkout@<sha>
  # ... run your tests and record a HAR (never commit it) ...
  - uses: foxy98PL/AuthzCoverage@v0
    with:
      spec: openapi.yaml
      identities: identities.yaml
      har: tests.har
      baseline: .authzcov/baseline.json   # optional: gate on regressions
      sarif: true                         # optional: code scanning
```

The action downloads the release archive, checks it against `checksums.txt` before extracting
anything, verifies the cosign signature of `checksums.txt` when `cosign` is on `PATH` (otherwise it
prints a notice; install it with `sigstore/cosign-installer`), runs `coverage`, writes the Markdown
report to the job summary, optionally uploads SARIF, and runs `gate` last so a failing gate does not
hide the report. Pin the action to a commit SHA for the strongest guarantee.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `spec` | required | OpenAPI 3.x spec |
| `identities` | required | `identities.yaml` |
| `har` | required | HAR file(s); newline- or space-separated, each becomes `--har` |
| `version` | `latest` | `latest`, a tag like `v0.1.0`, or `source` (build from the action checkout with Go; needs Go on the runner; for development) |
| `baseline` | empty | baseline path; when set, `gate` runs and fails the step on regressions |
| `waivers` | empty | `waivers.yaml` (also passed to `gate`) |
| `fail-on` | empty | `gate --fail-on` rules; empty uses the CLI default |
| `max-drop` | empty | `gate --max-drop` (percentage points) |
| `sarif` | `false` | upload SARIF to code scanning |
| `out-dir` | `authzcov-out` | where `coverage.json` and `authzcov.sarif` go |
| `github-token` | `github.token` | only used to resolve `latest` through the releases API |

## Outputs

| Output | Meaning |
| --- | --- |
| `coverage-percent` | required-cell coverage, e.g. `36.4` |
| `gaps` | number of uncovered required cells |
| `report-dir` | directory holding `coverage.json` |

## Permissions

`contents: read` is enough. `sarif: true` needs `security-events: write` (and is not available to
pull requests from forks, whose token is read-only). The action makes no network calls beyond
downloading the release and, for `latest`, one releases-API request. `coverage`, `report` and `gate`
themselves stay offline. Inputs reach scripts only through environment variables, never by
interpolation into shell code.

Runners need `bash`, `curl`, `jq` and `tar` (`unzip` on Windows); GitHub-hosted runners have them.
