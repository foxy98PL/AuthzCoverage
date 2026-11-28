# Review queue

Open reviews only. The implementation orchestrator appends a row when a ticket goes to In Review and starts a
`reviewer` agent; the row is removed (moved to `docs/reviews/queue-archive.md`) once it passes.
Status: `queued` → `in review` → `passed` | `findings` → (fixed) `passed`.

| Ticket | Scope (packages) | Acceptance criteria | Status |
| --- | --- | --- | --- |
| KAN-10 | repo skeleton, internal/cli | Jira KAN-10 | queued (not agent-reviewed yet) |
| KAN-34 | internal/plan, internal/cli/{export,pipeline,root}.go, coveragejson.ObjectHash, schema/plan.v1.json, docs/plan.md, testdata/golden/*.plan.json | Jira KAN-34 (3 ACs) | queued (not agent-reviewed yet) |
| KAN-90 | eval/ (module authzcoveval: result, harness, tenantshop, cmd/tenantshop, schema, README), e2e/apps/tenantshop/{shop/variants*.go,shop/shop.go,record/*}, e2e/thirdparty/vampi, Makefile (eval*) | Jira KAN-90 (mutants, ablation, VAmPI, results; 'Later' items out of scope; VAmPI re-run needs docker) | queued |
| KAN-92 | internal/{model,spec,config,relate 🔒,matrix 🔒,suspicious,cli/pipeline.go}, schema/identities.v1.json, docs/identities.md, testdata/golden, e2e/apps/tenantshop, eval/tenantshop | Jira KAN-92 (O3, O4, O5a, O5b; plus O11) | queued |
