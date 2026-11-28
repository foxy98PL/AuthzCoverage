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
| `crapi` | `crapi.json` | docker compose | Third-party app OWASP crAPI v1.1.6 (digest-pinned compose stack) against a ground truth of its documented challenges, honest and attack recordings. |

Run: `make eval` (all), `make eval-tenantshop` (vet, tests, then the two tenantshop suites; no
docker), `make eval-vampi` (docker), `make eval-crapi` (docker compose, about 3 minutes). `go run ./cmd/tenantshop -v -out DIR` (in `eval/`) prints every
authzcov run.

## crAPI

`make eval-crapi` (`e2e/thirdparty/crapi`, module `crapieval`) vets and tests the harness, then runs it.
`run.sh` pulls the images of `compose.yaml` by digest; the Go program builds authzcov from source, starts a
fresh crAPI stack per suite (unique compose project `crapieval-<pid>-<n>`, host ports random on 127.0.0.1,
`docker compose down -v` registered before `up`, so a failure still cleans up), waits until nginx reaches
the identity, community and workshop services and MailHog answers (`up --wait`, then a probe, 3 minute
limit), records a HAR and scores it. Start-up takes about a minute per suite; the whole run about 3 minutes.

- Pin: crAPI tag `v1.1.6` (commit `700f03d`, 2025-09-22). Only `crapi-identity` has a `1.1.6` image; the
  other crAPI services have no release tag on Docker Hub, so every `crapi/*` image is the `main` build of
  2025-09-22 (the day of the tag commit), pinned by digest in `compose.yaml`, as are `postgres:14` and
  `mongo:4.4`. `extra.images` in the result lists the digests, `app.image_digest` is crapi-web's.
- Dropped from crAPI's compose: `crapi-chatbot` and `chromadb` (LLM, needs an API key; challenges 16 to 18
  are `out_of_scope`), `api.mypremiumdealership.com` (payment and SSRF target; without it the payment call
  of `GET /orders/{id}` fails inside the app, which catches it, the order is still returned). Resource
  limits, TLS and fixed host ports are removed. `crapi-web` still needs a `CHATBOT_SERVICE` host to resolve
  at start-up, so it points at `crapi-identity` (never called).
- Spec: `openapi.json` is crAPI's own `openapi-spec/crapi-openapi-spec.json` at the tag, unchanged
  (OpenAPI 3.0.1, no external `$ref`); authzcov loads it as is.
- Identities (`identities.yaml`): alice, bob, carol (role user) and crAPI's seeded admin; matched by JWT
  `sub`, which crAPI sets to the e-mail address (`@example.test`, throwaway passwords). Each customer gets
  a vehicle through the welcome e-mail: the recorder polls MailHog's API for the VIN and pin code and calls
  `add_vehicle`. Ownership: `learn_from_create` for orders, videos and posts (ids in the response),
  `learn_from_lists` for vehicles (`add_vehicle` returns no id).
- Suites: honest = each customer uses only their own order, video, post, vehicle and mechanic report;
  the admin lists users and deletes a video. Attack = honest plus cross-user, anonymous and mass-assignment
  requests, destructive ones last. `extra.runs[].probes` has the status of every tagged attack request.
- Ground truth (`groundtruth.yaml`): one item per crAPI challenge plus items found in the source, each with
  a citation; categories `documented`, `undocumented`, `query_param` (BOLA by query parameter, authzcov only
  reads path parameters, so counted as `fn`), `control`, `quirk` (2xx that is no authz failure: flagged = `fp`)
  and `non_authz` (`out_of_scope`).
- Recorder setup failures (a login that is not accepted yet, a mail that does not arrive) retry the whole
  session on a fresh stack (3 attempts); entries of a failed attempt are discarded. A failed `up` or readiness
  wait is fatal. The stack is removed on success, failure and SIGINT/SIGTERM (Go signal handler plus a trap in
  `run.sh`); a failed teardown is printed and makes the run exit non-zero.
- No mechanic identity: the recorder only files the mechanic report (`contact_mechanic`) as a customer and
  has no mechanic login; whether crAPI offers one in this stack is not verified offline.

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
- `customers-role` (admin-only role check removed) is detected since KAN-92 (lower-role 2xx below a
  declared `min_role` on a tenant-scoped endpoint).
- The ablation drops one request at a time, so it says nothing about interactions of several missing
  requests.
- VAmPI ground truth is hand-labelled; see `e2e/thirdparty/vampi/groundtruth.yaml`.
- VAmPI `VAMPI-DEBUG` is a miss (fn) in both runs, and that is expected: `testdata/specs/vampi.yml`
  declares no `security` on `GET /users/v1/_debug`, so the spec marks it public. Function-level
  `suspicious_allow` for anonymous callers needs the spec to require auth, and an unknown or public
  endpoint never counts. The app has no token check there, so the label is right and the spec is wrong;
  authzcov cannot see that from the spec. Left as an honest FN.
- VAmPI path-ignored false positives: `VAMPI-PWCHANGE` on v0 (the secure build) and `VAMPI-U2-EMAIL`
  on both builds are flagged although the 2xx only changed the caller's own record (the handler
  ignores the path's username). authzcov sees a 2xx on another user's path and cannot tell that the
  path was ignored, so these count as `fp`.
- crAPI: `CRAPI-C1-VEHICLE` (challenge 1) is a miss in the attack run although vehicle ownership is learned from the
  vehicle list; the cause is not determined yet (needs a docker run). `CRAPI-C2-REPORT` is a query-parameter
  BOLA and `CRAPI-U2-USERS-ALL` is function-level; both are expected misses. `CRAPI-Q1-POST-OTHER` (public
  community posts) and `CRAPI-Q2-VIDEO-PUT` (path ignored) are `fp`: authzcov cannot tell public data or an
  ignored path parameter from a leak. Challenge 14 is mapped to the anonymous order lookup by us (the
  challenge text names no endpoint). Only one release was evaluated, on one machine.
- VAmPI runs mix honest and attack suites in the top-level summary; use `extra.runs[].summary` for
  the per-run numbers (honest = "gap reported" tp/fn, attack = detections against ground truth).

## Not yet covered: Juice Shop target, validation article

KAN-90 asked for two things that are not done yet:

- a Juice Shop target (no recorder, spec or ground truth exists for it);
- the validation article that presents these results.
