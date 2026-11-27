# authzcov validation benchmark (KAN-90)

`make eval` regenerates every file in `eval/results/` (never edit them by hand). All files share one
schema, `eval/schema/result.v1.json`, written by the Go package `eval/result`:
`schema_version`, `suite`, `generated_at` (honours `SOURCE_DATE_EPOCH`), `app`, `authzcov` (version,
commit), `machine` (os, arch, cpus, go_version), `summary`, `cases`, `extra`.

## Suites

| Suite | File | Needs | Measures |
|---|---|---|---|
| `tenantshop-mutants` | `tenantshop-mutants.json` | go | Does `suspicious_allow` fire on the right (endpoint, relationship) when exactly one authorization check of the correct tenantshop is removed? Does it stay quiet on the unmutated app? |
| `tenantshop-ablation` | `tenantshop-ablation.json` | go | Cell-level precision/recall of the coverage matrix: drop one attacker request from the recording and see whether exactly that cell turns from covered to GAP and nothing else changes. |
| `vampi` | `vampi.json` | docker | Third-party app VAmPI (pinned image digest) against a hand-written ground truth, honest and attack recordings, vulnerable=1 and vulnerable=0. |

Run: `make eval` (all), `make eval-tenantshop` (vet, tests, then the two tenantshop suites; no
docker), `make eval-vampi` (docker). `go run ./cmd/tenantshop -v -out DIR` (in `eval/`) prints every
authzcov run.

## Reading a result

`cases[].result` is one of `tp`, `fp`, `fn`, `tn`, `out_of_scope`; `expected` and `flagged` list the
matrix cells involved and `reason` says why. `summary.precision = tp/(tp+fp)` and
`summary.recall = tp/(tp+fn)`, rounded to 3 decimals, `null` when the denominator is 0.

- Mutants: `mutant/<id>` is `tp` when a `suspicious_allow` exists on the mutant's endpoint AND
  relationship, else `fn` with the reason from `coverage.json`. Any other `suspicious_allow` in that
  run is a `mutant/<id>/unexpected/<endpoint>|<rel>` false positive. `fixed/no-alarm` is `tn` when the
  unmutated app raises nothing; `seeded/get-tenant` is the app's own seeded bug (KAN-74).
- Ablation: `ablation/<cell>` is `tp` when dropping that request moved the cell covered to missing.
  Another cell whose state or status counts changed is `ablation/<cell>/side-effect/<other>` (`fp`).
  Cells that are not covered in the baseline have nothing to lose; they are listed in
  `extra.skipped_steps`. Precision and recall are over the ablatable cells only
  (`extra.ablatable`, of `extra.attacker_steps` attacker requests in `FullScript`); the remaining
  attacker steps are not required cells (or not covered in the baseline), so nothing was measured
  for them.

Every tenantshop variant is recorded with `record.FullScript` (one attacker request per required
object-level cell, dedicated victim orders, destructive attacks last) against a fresh in-process
server; HARs live only in temp dirs and result files contain endpoints, relationships, statuses and
counts, never tokens. Two runs give byte-identical files except `generated_at`. The authzcov version
string is `git describe --dirty`, so it reads `-dirty` while the tree has uncommitted changes.

## Scaling

`make eval-scaling` (`go run ./cmd/scaling` in `eval/`) measures how `authzcov coverage` scales with
HAR size. It builds authzcov once, then for each size generates the synthetic benchmark HAR of
`internal/cli/bench_test.go` (44-operation spec, 6 identities, 2 tenants; the same entry mix at every
size) by running `TestWriteBenchFixture` with `AUTHZCOV_BENCH_ENTRIES=<n>`, and runs the binary
`-runs` times (default 3) under `/usr/bin/time -v`. Without `/usr/bin/time` only wall time is
recorded and `peak_rss_mib` is `null`. Fixtures are deleted after each size.

- Flags: `-sizes 1000,10000,100000,1000000`, `-runs 3`, `-out DIR`, `-v`. Makefile override:
  `make eval-scaling SIZES=1000,10000`. The default 1k to 1M run takes about a minute and needs about
  1 GB of temp disk for the 1M HAR.
- `extra.points[]`: `entries`, `har_bytes`, `wall_ms` (median over runs), `wall_ms_min/max`,
  `peak_rss_mib` (maximum over runs), `ns_per_entry`, and the `required/covered/percent` of
  `coverage.json` (identical at every size here, which shows the analysis did real work).
- `cases` is empty and `summary.precision/recall` are `null`: this suite has no detection metrics.

`scaling.json` is machine-dependent (CPU, disk, load) and is exempt from the byte-identical
determinism rule of the other suites; `machine` records where it was produced. Compare numbers only
between runs on the same machine.

Reading it: `extra.fits.time_slope` is the least-squares slope of ln(wall_ms) against ln(entries);
1.0 means linear time, clearly above 1 means super-linear. Small sizes include process start-up, which
pulls the slope slightly below 1. `extra.fits.rss_ratio` is peak RSS at the largest size divided by the
smallest: near 1 means flat memory; a ratio that grows with the entry ratio means memory is linear in
the input. Streaming JSON parsing alone does not make that ratio flat if the pipeline keeps the
exchanges or observations in memory afterwards.

## Known limits

- Mutants are single removed checks in one small app written by the same team; the numbers show that
  the matrix and `suspicious_allow` work on these patterns, not how common the patterns are.
- `customers-role` (admin-only role check removed) is an honest false negative: authzcov classifies a
  caller's role only against a learned minimum role, and for the tenant-scoped endpoint
  `GET /orgs/{orgId}/customers` every call has relationship `unknown`, which never counts.
- Tenant-scoped endpoints (resource `orgs`: list/create orders, customers) have no learned object
  owner, so `owner` and `same_role_other_user` cells cannot be covered, and `anonymous` cells are
  recorded but stay uncovered; those anonymous cells are therefore not ablated.
- The ablation drops one request at a time, so it says nothing about interactions of several missing
  requests.
- VAmPI ground truth is hand-labelled; see `e2e/thirdparty/vampi/groundtruth.yaml`.
- VAmPI `VAMPI-DEBUG` is a miss (fn) in both runs: it is a function-level endpoint with no object
  parameter, and `suspicious_allow` is only raised for object-level endpoints, so an unauthenticated
  200 there is not flagged.
- VAmPI path-ignored false positives: `VAMPI-PWCHANGE` on v0 (the secure build) and `VAMPI-U2-EMAIL`
  on both builds are flagged although the 2xx only changed the caller's own record (the handler
  ignores the path's username). authzcov sees a 2xx on another user's path and cannot tell that the
  path was ignored, so these count as `fp`.
- VAmPI runs mix honest and attack suites in the top-level summary; use `extra.runs[].summary` for
  the per-run numbers (honest = "gap reported" tp/fn, attack = detections against ground truth).
