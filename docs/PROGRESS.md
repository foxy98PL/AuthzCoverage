# Progress log

What has been built, per task, with Jira keys. Newest state first in "Now"; history below.
Plan and open decisions: `docs/PLAN.md`.

## Now (2026-11-27, end of implementation round 3: Phase 2 local work)

- Phase 1 code done through KAN-19 (code part). All reviews passed after fixes (`docs/reviews/`).
- Owner decisions pending: (1) KAN-18 credential-handling change sign-off; (2) caller without tenant vs DOC-03
  "empty = global"; (3) KAN-19 F1 — exempt anonymous from the owner-confidence condition?; (4) E2 SECURITY contact;
  (5) D7 local $ref.
- Blocked on owner: mitmproxy + real VAmPI recording → real-app goldens (KAN-12, KAN-19e); crAPI (8 GB RAM).
- Phase 2: KAN-20 coverage.json v1 + `report` → In Review (agent review passed after fix). KAN-21 Markdown → In Review (passed after fix). KAN-24 baseline/waivers → In Review (passed after fix).
- KAN-25 gate → In Review (passed after fix). KAN-23 SARIF → In Review (passed after fix; owner: GitHub upload AC3). KAN-22 HTML → In Review (owner: browser check AC1/AC4).
- KAN-88 suspicious_allow (new story) → In Review (passed after fix). KAN-73 benchmark → In Review (passed after fix; 138 ms/op, 31.7 MiB RSS on 10k entries).
- All agent reviews passed (docs/reviews/, REVIEW_QUEUE.md). Owner manual checks: KAN-23 AC3 SARIF upload; KAN-22 AC1/AC4 browser.
- KAN-74 tenantshop demo → In Review (agent review passed after fix). `make e2e` green; seeded bug → 1 suspicious_allow other_tenant.
- Next: KAN-28 README/quickstart.
- Product gap found by KAN-74: `learn_from_create.id_from` only supports `request_json`; server-generated IDs (`response_json`) cannot be learned. Follow-up ticket proposed.
- 2026-11-27: project moved to GitHub (`origin` https://github.com/foxy98PL/AuthzCoverage, branch `main`). First push 2026-11-27: fcda7ad (all Phase 1–2 work + KAN-74), via a repo-scoped SSH deploy key.
- Remaining Phase 2 now unblocked: KAN-11 GitHub parts (CI, Dependabot), KAN-26 GitHub Action, KAN-27 release (KAN-71/72), KAN-23 AC3.

## Earlier state (round 1)

- Tasks 0–5 implemented and validated; Task 6 scripts written, not yet run (needs mitmproxy).
- Validation (Haiku, 2026-11-27): `make check` green, `make fuzz` (3 targets) clean, no net/http outside
  tests, no HAR tracked, no git remote, 4 allowed direct deps, determinism tests ×3 ok. JWT-shaped
  literals in tests are synthetic (`sub: a/x/alice/bob`) plus the upstream VAmPI spec example.
- G5 evidence: VAmPI's spec example token has `sub: "John.Doe"` → sub is the username.
- Nothing committed yet: Task 1 files are staged, the rest is untracked. Owner commits.
- Blocked on owner: SECURITY.md contact (E2), local `$ref` (D7), mitmproxy install + first real VAmPI run.
- Jira: KAN-10, 14, 15, 16, 68, 69, 70 In Review; KAN-4, 5, 11, 12, 75 In progress.

## Task 0 — Environment (KAN-75, In progress)
Go 1.27.4, gopls 0.24.0, golangci-lint 2.15.0, govulncheck 1.10.0, Docker 28.4.0 verified.
Missing: mitmproxy, Node (WSL). `docs/dev-setup.md` written.

## Task 1 — Skeleton (KAN-10 In Review, KAN-11 In progress)
Git repo (no remote), `go.mod` with toolchain, layout, LICENSE/NOTICE/SECURITY/README,
cobra `coverage` + `version`, exit codes, Makefile (`build test lint vet vuln fuzz check check-offline hooks clean`),
golangci-lint v2 with depguard (net/http only in `internal/probe/exec`), pre-commit hook
(runs `check-offline`, refuses `*.har` and `testdata/raw/`), `.vscode/`.
KAN-11 GitHub parts (Actions, Dependabot, branch protection) deferred until public.

## Task 2 — Spec loader (KAN-68, KAN-70 In Review)
`internal/spec`: kin-openapi with all external `$ref` refused (flag + deny-all reader),
endpoints sorted by ID, ObjectParam/Resource/Kind inference, duplicate shape → exit 3,
Swagger 2.0 and partial-segment params rejected, `SpecLine` via yaml.Node (YAML + JSON).
`testdata/specs/`: VAmPI spec (MIT, credited in NOTICE) + 8 edge-case specs.

## Task 3 — Matcher 🔒 (KAN-69, KAN-14 In Review)
`internal/match`: segment trie, literal beats param, Ambiguous, MethodMiss, per-segment unescape,
`;matrix` dropped, trailing slash ignored. 27 match rows + 7 Add rows; FuzzMatch 30 s clean (13.2M execs).

## Task 4 — HAR ingest + identity 🔒 (KAN-15)
- `internal/redact`: Fingerprint (12 hex SHA-256), sensitive header list, `JSON` body scrubber
  (password/token/secret keys and JWT-shaped values → `[redacted:<fp>]`), `StripControl`, safe `Writer`.
- `internal/ingest/har`: streaming `json.Decoder` reader returning `iter.Seq2`, drops static/OPTIONS/status 0/bad URL
  with counts, query string and userinfo dropped, bodies ≤ 64 KiB redacted.
- `internal/identity`: Bearer extraction, claims decoded unverified (≤ 16 KiB, json.Number), resolver
  (declared / anonymous / `unknown-<fp8>`); Basic, cookie and API-key requests are recognised so they are
  unknown, never anonymous.
- `internal/config`: identities.yaml v0 with node-based validation (file:line: key path), anchors/aliases
  and raw secrets rejected.
- `internal/testutil/hartest`: HAR + JWT fixture builder (test key, `iss: authzcov-test`).

## Task 5 — Ownership, classifier, matrix, table 🔒 (KAN-16)
- `internal/ownership`: self_params (declared for self, learned for other seen subjects), learn_from_create
  (2xx and known creator only), conflict rules, order independent.
- `internal/relate`: classifier per spec 5.5 (+ unknown caller → unknown), `MinRanks` (v0 function-level rule).
- `internal/matrix`: requirements, covered rule (IDConf ≥ learned, OwnerConf ≥ inferred on object-level),
  evidence cap 5, summary; 50-shuffle order-independence property test.
- `internal/report/table`: tabwriter output, hidden columns, `ok <status>`, control chars stripped.
- `internal/cli/pipeline.go`: two-pass pipeline (config → spec/trie → HAR ingest → match → pass 1 learn →
  pass 2 classify → matrix → table). Tests: acceptance on VAmPI-shaped fixture, no-network (failing transport
  + resolver), no raw secret in output, shuffled-order identical output, exit codes 2/3.

## Task 6 — VAmPI run (KAN-12)
`e2e/recorders/vampi.sh` (mitmdump on :8081, no cross-user calls) and `testdata/identities/vampi.yaml` written;
waiting for mitmproxy and a real run.

## KAN-16 review fix
`internal/cli/same_role_e2e_test.go`: bob reads alice's book → SAME_ROLE `ok` / `ok 403` end to end.

## KAN-17 — base path, .har.zip, unmatched shapes, explain (In Review, review passed after fixes)
- `--base-path auto|none|/prefix` (default auto; per host, ≤ 4 leading segments, ties → shortest); stderr line per host.
- `.har.zip`: `*.har` members, 2 GiB total decompressed (counted while reading), 100:1 ratio (header-based; total cap is the real bound).
- Unmatched requests grouped by shape (`<id>` segments), top 20.
- `authzcov explain --spec s 'GET /path'`: candidates, winner, params, reason; `match.Trie.Explain` (Result == Match, fuzzed).
- Review: `docs/reviews/KAN-17.md` — 4 findings fixed.

## KAN-18 — identities.yaml v1 (In progress)
- Part A done: config v1 keys (`credentials`, `jwt.subject`, `learn_tokens`, match keys `token_sha256`/`apikey_sha256`/`token_env`/`basic_user`/`login`, `markers`), `Warnings()`; identity `NewExtractor` (bearer schemes, cookie by name, API-key header, basic user), resolver declared → learned → unknown, `LoginToken` reads the token fingerprint from the redacted login response.
- Part B done: CLI wiring (token learning before resolution), `discover --write`, `schema/identities.v1.json`, `docs/identities.md`.
- Review fixes (security): Basic fingerprint from username only; password-like JSON fields → `[redacted]` without hash. Owner sign-off pending.

## KAN-19 — tenancy, overrides, list learning, --strict, goldens (In progress)
- `jwt.tenant`, `tenancy.tenant_params`, `requirements.overrides[{endpoint, object_param}]`, `ownership.learn_from_lists` (Inferred).
- `ok~` for inferred-only cells + footer; `--strict` needs owner confidence ≥ learned.
- Golden harness (`make golden`), 4 fixture goldens in `testdata/golden/`. Real-app goldens (VAmPI, crAPI, RealWorld) blocked on recordings.
- Follow-up: tenant-param-only endpoints (`/orgs/{orgId}/projects`) are object-level on the tenant id.

## KAN-20 — coverage.json v1, report command (In Review)
- `internal/report/coveragejson`: Build (pure, clock injected) / Write / Read (schema check, 256 MiB cap) / ToMatrix; DOC-04 fields.
- `coverage --out DIR` (default `authzcov-out`, `""` disables), atomic write; `report --in FILE --format table|json`.
- `ownership.Registry.Objects()` (conflicted claims skipped; self claims as resource `subject`); `id_hash` only, raw IDs never written.
- Findings now: gap, unmatched_request, ambiguous_match, undocumented_method. suspicious_allow / waivers later (additive within v1).
- `generated_at` from SOURCE_DATE_EPOCH when set; goldens `testdata/golden/*.coverage.json`. Makefile passes `cli.commit`.

## KAN-21 — Markdown reporter (In Review)
- `internal/report/markdown`: Render(*coveragejson.Report), first line = one-sentence summary, top 20 gaps by risk
  (other_tenant, same_role, lower_role, anonymous, owner, …), rest in <details>, other findings in <details>, ≤ 60000 bytes.
- `Escape`: \ | ` * _ ~ [ ] ( ) # ! . escaped; & < > → entities; @ → &#64;; : → &#58;; control → space; Unicode Cf dropped.
- `report --format markdown`; goldens `testdata/golden/*.md`.
- Also KAN-20 review fix: unmatched shapes mask segments with a digit and ≥ 6 bytes, or ≥ 24 bytes.

## KAN-24 — baseline + waivers (In Review)
- `internal/waivers`: Parse/Load (node validation, file:line, reason 10–500, expires ≤ 365 d, `*` glob, bare list ok), Apply (waived cells, summary, gap findings removed, waiver_expired/waiver_unused warnings).
- `internal/baseline`: FromReport (required cells only, no timestamps), Write/Read, Compare → Diff (new endpoints, new gaps, removed, regressions, improvements, waived, expired).
- CLI: `baseline write`, `baseline diff` (exit 0), `coverage --waivers`; default `.authzcov/waivers.yaml` if present; `var now` for tests.
- Waiver valid through its expiry date; waived→missing counts as regression; first matching waiver wins.

## KAN-25 — gate (In Review)
- `internal/gate`: pure Evaluate over baseline.Diff; rules new-gaps (only endpoints absent from the baseline), regressions (covered → missing only), drop (one-decimal percents, > max-drop), expired-waivers; removed never fails; disabled-but-failing rules listed as `ignored:`.
- `authzcov gate --in --baseline --waivers --fail-on --max-drop`; exit 1 fail, 2 usage/waivers, 3 bad report or missing/bad baseline (hint: baseline write).

## KAN-23 — SARIF (In Review)
- `internal/report/sarif`: one rule per kind (+ `authzcov/other` for unknown kinds), location = spec file + endpoint line (1 if none), partialFingerprints = finding fingerprint, plain-text messages, no timestamps.
- Spec URIs: absolute / URL / `..` / drive paths reduced to the file name (no local paths in uploads).

## KAN-22 — HTML report (In Review)
- `internal/report/html` (htmlreport): html/template, one hashed inline script + style, CSP default-src 'none'; filters by relationship / endpoint / gaps only via data-* + class toggle.
- 300×7 cells + 3000 findings = 486 KB (< 500 KB); evidence refs omitted in HTML.

## KAN-88 — suspicious_allow (In Review)
- `internal/suspicious.Find`: object-level, rel ∈ {same_role_other_user, other_tenant, lower_role, anonymous}, 2xx, caller ≥ learned (or anonymous), owner ≥ learned (or tenant-param other_tenant), GET/HEAD need non-empty JSON body; one finding per (endpoint, rel).
- Table footer `! N suspicious allow(s)`, markdown section before gaps, SARIF/HTML generic. Waivers never hide them. `model.Observation.ObjectTenant` added.

## KAN-73 — benchmark (In Review)
- `make bench` (scripts/bench.sh): median of 5, peak RSS, > 20% vs docs/benchmarks.md baseline → REGRESSION exit 1. 10k entries: 138 ms/op, 31.7 MiB.

## KAN-74 — tenantshop demo (In Review)
- `e2e/apps/tenantshop`: separate Go module (stdlib only, outside root `./...`), OrgA/OrgB × 2 customers + 1 admin each, HS256 JWT with `org_id`, fixed iat.
- Seeded bug: `GET /orgs/{orgId}/orders/{orderId}` checks owner-or-admin only (no tenant check) → adminB reads OrgA orders.
- Recorder writes HAR itself (`record.RecordAs`, URLs rewritten to `http://tenantshop.test`); `e2e/recorders/tenantshop.sh`; no mitmproxy needed.
- `go test -tags e2e` (via `make e2e`): golden table, exactly one suspicious_allow (other_tenant on the seeded GET), determinism. Docker compose build verified.
- POST orders accepts a client-chosen `id` because learn_from_create cannot read response bodies (see gap above).

## KAN-11 — GitHub CI (In Review)
- `.github/workflows/ci.yml`: jobs vet, lint (golangci-lint v2.15.0), test (-race), govulncheck v1.10.0, e2e, fuzz (10 s) on push/PR to main; `permissions: contents: read`, persist-credentials false, concurrency cancel.
- Pins: actions/checkout v7.0.1 3d3c42e, actions/setup-go v7.1.0 d8cbb80, golangci-lint-action v9.3.0 ba0d7d2 (verified vs tags).
- `.github/dependabot.yml`: weekly gomod + github-actions, grouped minor/patch.
- First run 46007918706 on 3c291d8: all 6 jobs green (~35 s each, fuzz 100 s). Branch protection (AC3) = owner.

## KAN-89 — learn_from_create response_json (In Review)
- `id_from: {response_json: <dot path>}` (exactly one of request_json/response_json; no `[]`); learned from 2xx response, one scalar.
- Redaction placeholders (`[redacted]`, `[redacted:…]`) never learned as ids, for request and response sources.
- tenantshop uses server-generated ids now; golden unchanged. Optional Location-header source skipped.

## KAN-28 — README + quickstart (In Review)
- README rewritten (pitch, why, quickstart, how it works, identities, CI, recording HARs, security, privacy/telemetry, signatures-planned, roadmap). GIF placeholder for owner.
- `docs/quickstart.md` on tenantshop (no mitmproxy/Docker); verified end to end on the working tree: table == golden, HTML 9.8 KB; ~2 s warm.
- SECURITY.md: GitHub private vulnerability reporting (owner must enable it in repo settings).

## KAN-71/72 — release pipeline (In Review; needs a tag run)
- `.goreleaser.yaml` (goreleaser v2.20.3): linux/darwin/windows × amd64/arm64, trimpath, ldflags version+commit, CommitTimestamp, tar.gz/zip, checksums.txt, syft SBOM per archive, cosign keyless bundle `checksums.txt.sigstore.json`.
- `release.yml` on `v*` tags: permissions {} + job contents/id-token/attestations write; check-offline; cosign v3.1.6, syft v1.57.2; attest-build-provenance on checksums; no Go cache.
- `authzcov version` prints `authzcov <v> (commit <c>)`. README verify commands; `docs/releasing.md` (rc tag first).
- Verified locally: goreleaser check, snapshot → 6 archives, actionlint. Signing/SBOM/attestation only verifiable on a real tag (owner approval).

## KAN-26 — composite GitHub Action (In Review)
- Root `action.yml` (`uses: foxy98PL/AuthzCoverage@v0`): resolve release → download archive + checksums.txt + bundle → checksum verified before extraction → cosign verify-blob when cosign on PATH (else notice) → coverage → Markdown to job summary, outputs coverage-percent/gaps/report-dir → optional SARIF upload (codeql-action v4.39.5) → gate last.
- `version: source` builds from the action checkout; `.github/workflows/action-test.yml` runs it on tenantshop: outputs 36.4 / 21, passing gate, deliberately failing gate (outcome failure).
- All inputs via env (no `${{ }}` in run:). Download path + `v0` moving tag only testable after the first release.

## KAN-30 — fixture checks, demo tape, Pages (In Review)
- `tools/fixturecheck` (stdlib): any JWT with iss ≠ authzcov-test fails unless allowlisted per path + sha256-12 (`tools/fixturecheck/allow.txt`, 7 entries); HAR hosts must be demo hosts; .har.zip scanned. In `check-offline` and a CI job.
- `docs/demo.tape` + `make gif` (discover, coverage, failing gate); GIF not rendered (no ttyd/ffmpeg here).
- `.github/workflows/pages.yml`: tenantshop HTML report → Pages; deploy only on manual run or `vars.PAGES_ENABLED == 'true'`.

## KAN-64 — CONTRIBUTING.md (In Review)
- DOC-08 adapted: real commands (all verified), package map, fixture rules incl. fixturecheck; deps discussed in an issue (no ADR dir); DCO sign-off kept.

## KAN-29 — redact --pseudonymize (command part, In Review)
- `authzcov redact --pseudonymize --in --out [--keep-claims] [--key-file] [--force]`: atomic 0600 write, streaming per entry.
- JWTs re-signed with the test key (iss authzcov-test), only kept claims, e-mails in kept claims pseudonymised; opaque tokens → tok_<HMAC8> (random per-run key unless --key-file); Basic → user_<hash8>, password dropped.
- Headers default-deny (benign allowlist keeps scrubbed values; everything else masked); e-mails → user_<hash8>@example.test; hosts → h<N>.test; query values → x; whitelist rebuild of entries.
- Coverage invariance tested on hartest fixtures + real tenantshop recording; no-secret-survives tests; FuzzPseudonymize 30 s.
- Shared test key moved to `internal/testkey`. Examples (crAPI, RealWorld) still blocked on recordings.

## Decisions made during implementation (review these)
1. Non-bearer credentials (Basic, cookie, API key) → identity unknown, never anonymous.
2. Request/response JSON bodies are scrubbed of password/token/secret fields at ingest.
3. Multiple identity rules matching one token → unknown.
4. learn_from_create only learns from 2xx responses by a known creator.
5. self_params for another user's subject → owner with confidence `learned` if that subject was seen in pass 1.
6. Unknown caller → relationship unknown; function-level with no 2xx observed → unknown.
7. Table status suffix: all distinct statuses when any is non-2xx (`ok 200,401`).
8. Partial-segment path templates (`/{id}.json`) rejected with exit 3.
9. `--base-path` defaults to `auto`; a non-empty prefix is not credited when the remainder is only `/`.
10. learn_tokens never needs the raw token: the login response is redacted at ingest to `[redacted:<fp12>]`, and that fingerprint is what later bearer requests carry.
11. `token_sha256` is matched on its first 12 hex chars (the stored fingerprint length).
13. Basic fingerprint = Fingerprint("basic:"+user); password-like body fields redacted without hash (offline-guessing risk).
14. Tenancy: a caller with no tenant vs a known object tenant → other_tenant (only `*` is exempt). Note DOC-03 said `""` = global; conflict to decide.
15. coverage.json: same HAR → byte-identical; reordered HAR changes only har sha256 + evidence refs. Percent is rounded like the table's %.1f.
12. JSON Schema is shipped for editors only; validation stays in the Go validator (a JSON Schema library would be a new dependency).
