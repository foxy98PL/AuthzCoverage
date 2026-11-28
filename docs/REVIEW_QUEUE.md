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
| KAN-102 | internal/{config,ownership 🔒,suspicious,cli/pipeline.go}, docs/identities.md, e2e/thirdparty/crapi | Jira KAN-102 (exclusive list rules; crapi min_role) | reviewed (Haiku), F1/F3/F4 fixed; F2 groundtruth flip unverified until crapi eval |
| KAN-94 | internal/{plan,cli/export*.go}, docs/plan.md, README | Jira KAN-94 (option A, hint, hash-miss note) | reviewed (Haiku), F1/F2/F4 fixed; F3/F5 left |
| KAN-104 | internal/{model,spec,ingest/har,cli/pipeline.go}, docs/identities.md, e2e/thirdparty/crapi | Jira KAN-104 (object_param on in:query) | reviewed (Sonnet), F1-F3 fixed |
| KAN-91 | bounded memory (uncommitted, base 09d70c0) | reviewer running | notes/KAN-91-review.md |
| KAN-12 | e2e/thirdparty/realworld, Makefile, docs/PLAN.md | Jira KAN-12 (RealWorld harness, notes/KAN-12-impl.md) | reviewer running, base 13dae128dc0ab3b4dfc8f7990c09c9782ac68233 |
