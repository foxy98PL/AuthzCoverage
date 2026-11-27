# Review queue

Implementation orchestrator appends rows; review orchestrator updates **Status** and writes
`docs/reviews/<KEY>.md` (or a batch file). Status: `queued` → `in review` → `passed` | `findings` → (fixed) `queued`.

| Ticket | Scope (packages) | Acceptance criteria | Status |
| --- | --- | --- | --- |
| KAN-10 | repo skeleton, internal/cli | Jira KAN-10 | queued (not agent-reviewed yet) |
| KAN-68 | internal/spec | Jira KAN-68 | passed — reviews/batch-2026-11-27.md |
| KAN-70 | internal/spec/lines.go | Jira KAN-70 | passed — reviews/batch-2026-11-27.md |
| KAN-69 | internal/match 🔒 | Jira KAN-69 | passed — reviews/batch-2026-11-27.md |
| KAN-15 | internal/{ingest/har,redact,identity 🔒,config,testutil/hartest} | Jira KAN-15 | passed (R1/R3 nits) — reviews/batch-2026-11-27.md |
| KAN-16 | internal/{ownership,relate 🔒,matrix 🔒,report/table,cli/pipeline.go} | Jira KAN-16 | passed after fix (internal/cli/same_role_e2e_test.go: bob reads alice's book → SAME_ROLE ok / ok 403) — reviews/batch-2026-11-27.md |
| KAN-17 | internal/{match 🔒 Explain,ingest/har/zip.go,basepath,cli/{explain,unmatched,pipeline}.go} | Jira KAN-17 | passed after fix (4 findings fixed) — reviews/KAN-17.md |
| KAN-18 | internal/{config,identity 🔒,cli/{pipeline,discover}.go}, schema/, docs/identities.md | Jira KAN-18 | passed after fix (3 findings fixed; security change needs owner sign-off) — reviews/KAN-18.md |
| KAN-19 | internal/{config,ownership,relate 🔒,matrix 🔒,report/table,cli}, testdata/golden | Jira KAN-19 (code part) | passed after fix; F1 owner decision, F3 blocked on recordings — reviews/KAN-19.md |
| KAN-20 | internal/report/coveragejson, internal/ownership (Objects), internal/cli/{coverage,pipeline,report,unmatched,version}.go, schema/coverage.v1.json, testdata/golden/*.coverage.json | Jira KAN-20 (4 ACs) + DOC-04 coverage.json field table | passed after fix (F1 unmatched ID leak, F3 clock, F4 Basic e2e, F5 schema test) — reviews/KAN-20.md |
| KAN-21 | internal/report/markdown, internal/cli/{report.go,report_markdown_test.go,golden_test.go}, testdata/golden/*.md | Jira KAN-21 (4 ACs) + escaping rules | passed after fix (F1 MaxBytes overrun fixed) — reviews/KAN-21.md |
| KAN-24 | internal/{waivers,baseline}, internal/report/coveragejson (Cell.Waiver), internal/cli/{baseline,coverage,pipeline,root}.go, schema/{baseline,waivers}.v1.json | Jira KAN-24 (5 ACs) + DOC-04 baseline/waivers | passed after fix (F1–F4 test gaps closed) — reviews/KAN-24.md |
| KAN-25 | internal/gate, internal/cli/{gate,gate_test,root}.go | Jira KAN-25 (5 ACs) + DOC-04 gate rules | passed after fix (F1 --max-drop Inf rejected) — reviews/KAN-25.md |
| KAN-23 | internal/report/sarif, internal/cli/{report.go,report_sarif_test.go,golden_test.go}, testdata/golden/*.sarif | Jira KAN-23 (AC1,2,4; AC3 owner upload) | passed after fix (F1 uri, F2 dropped kinds) — reviews/KAN-23.md |
| KAN-22 | internal/report/html, internal/cli/{report.go,report_html_test.go,golden_test.go}, testdata/golden/*.html | Jira KAN-22 (5 ACs; AC1/AC4 browser check by owner) | passed after fix (F2 control-char filter) — reviews/KAN-22.md |
| KAN-88 | internal/suspicious 🔒-style, coveragejson, cli/pipeline.go, report/{table,markdown} | Jira KAN-88 (6 ACs) | passed after fix (F3 anonymous guard, F4 message) — reviews/KAN-88.md |
| KAN-73 | internal/cli/bench_test.go, scripts/bench.sh, Makefile (bench), docs/benchmarks.md | Jira KAN-73 (local: < 5 s, > 20% regression, peak RSS) | passed after fix (bench.sh args, RSS warning) — reviews/KAN-73.md |
| KAN-74 | e2e/apps/tenantshop (separate stdlib module: shop, record, cmd/record, e2e_test.go, identities.yaml, golden), e2e/recorders/tenantshop.sh, Makefile (e2e) | Jira KAN-74 (4 ACs) | passed after fix (F1 seed/openapi tests, F3 symlink removed) — reviews/KAN-74.md |
| KAN-11 | .github/workflows/ci.yml, .github/dependabot.yml | Jira KAN-11 (AC1 jobs gate, AC2 SHA pins + least privilege, AC4 Dependabot; AC3 branch protection = owner repo setting) | passed after fix (N1/N2 Dependabot nested gomod + docker) — reviews/KAN-11.md |
| KAN-89 | internal/{config,ownership,cli/pipeline.go,cli/create_response_test.go}, schema/identities.v1.json, docs/identities.md, e2e/apps/tenantshop | Jira KAN-89 (AC1–3, 5–6; AC4 Location header skipped) | passed after fix (F1–F3 tests added) — reviews/KAN-89.md |
| KAN-28 | README.md, docs/quickstart.md, SECURITY.md | Jira KAN-28 (AC1 < 10 min, AC2 sections, AC3 telemetry/signatures; GIF = owner) | passed (nits F2/F3 pending) — reviews/KAN-28.md |
| KAN-71/72 | .goreleaser.yaml, .github/workflows/release.yml, docs/releasing.md, README (Releases and signatures), internal/cli/version.go | Jira KAN-71 (AC1 needs a tag run; AC2 version+commit; AC3 pins), KAN-72 (AC1–3 need a tag run) | passed after fix (F1–F3 docs); needs rc tag run — reviews/KAN-71-72.md |
| KAN-26 | action.yml, .github/workflows/action-test.yml, docs/action.md, README (Use it in CI) | Jira KAN-26 (AC1–2 download/verify need a release; AC3–5 self-test) | passed after fix (F1/F2/F4/N1/N2); F3 + v0 tag need a release — reviews/KAN-26.md |
| KAN-30 | tools/fixturecheck, Makefile (fixturecheck, gif), ci.yml (fixturecheck job), .github/workflows/pages.yml, docs/demo.tape | Jira KAN-30 (AC1–2 fixturecheck; AC3 tape written, GIF not rendered — needs vhs/ttyd/ffmpeg; AC4 tenantshop report on Pages, owner enables) | passed after fix (F1a/F1b closed; GIF + Pages enable = owner) — reviews/KAN-30-64.md |
| KAN-64 | CONTRIBUTING.md | Jira KAN-64 (DOC-08 adapted to the repo) | passed after fix (nits F4–F6) — reviews/KAN-30-64.md |
| KAN-29 | internal/redact/pseudo.go, internal/testkey, internal/testutil/hartest, internal/cli/{redact,root}.go, docs/redact.md | Jira KAN-29 (AC1–2 redact command; AC3–4 crAPI/RealWorld examples blocked on recordings) | passed after fix (8 leak paths closed, 0513df7); examples blocked — adversarial review 2026-11-27 |
| KAN-34 | internal/plan, internal/cli/{export,pipeline,root}.go, coveragejson.ObjectHash, schema/plan.v1.json, docs/plan.md, testdata/golden/*.plan.json | Jira KAN-34 (3 ACs) | queued (not agent-reviewed yet) |
| KAN-90 | eval/ (module authzcoveval: result, harness, tenantshop, cmd/tenantshop, schema, README), e2e/apps/tenantshop/{shop/variants*.go,shop/shop.go,record/*}, e2e/thirdparty/vampi, Makefile (eval*) | Jira KAN-90 (mutants, ablation, VAmPI, results; 'Later' items out of scope; VAmPI re-run needs docker) | queued |
| KAN-92 | internal/{model,spec,config,relate 🔒,matrix 🔒,suspicious,cli/pipeline.go}, schema/identities.v1.json, docs/identities.md, testdata/golden, e2e/apps/tenantshop, eval/tenantshop | Jira KAN-92 (O3, O4, O5a, O5b; plus O11) | queued |
