# KAN-26 review — composite GitHub Action

Reviewer: Haiku (read-only), 2026-11-27, commit 2859777. CI + Action self-test green on 2859777.

| # | Criterion | Verdict |
|---|---|---|
| 1 | checksum verified before extraction/execution | PASS in code; needs a release to run |
| 2 | cosign bundle verified when cosign is present | PASS in code; needs a release to run |
| 3 | Markdown in job summary; coverage-percent / gaps outputs | PASS (self-test asserts 36.4 / 21) |
| 4 | sarif: true uploads SARIF (codeql-action v4.39.5 pinned) | PASS in code; not in self-test (needs security-events: write) |
| 5 | failing gate fails the job | PASS (self-test) |

Security: no `${{ }}` in run bodies; set -euo pipefail everywhere; token only for the releases API; temp files in RUNNER_TEMP.

## Findings
- F1 (important, fixed): tag check was a glob; now strict semver regex for user and API tags, fixed error text (tested: accepts v0.1.0, v0.1.0-rc.1; rejects v1/../../x, "v1 foo", v1.2, v1.2.3;id, v1.2.3-$(id)).
- F2 (important, fixed): failing-gate assertion now checks new output `gate-result` (pass/fail/error).
- F3 (important, deferred): download/checksum/cosign path untested until the first release; documented under "Not yet tested".
- F4 (important, fixed): docs/README example installs cosign; notice explains checksum-only protects against corruption only.
- F5 (release blocker): `v0` tag does not exist yet.
- N1 (fixed): `jq -er`. N2 (fixed): fork identity note. N3 (accepted): background server on ephemeral runner.

Result: passed after fix; F3/F5 wait for the first release.
