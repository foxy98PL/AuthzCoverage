package cli

import (
	"strings"
	"testing"

	"authzcov/internal/testutil/hartest"
)

const reposSpec = `openapi: 3.0.3
info: {title: repos, version: "1"}
paths:
  /orgs/{orgId}/repos/{repo}:
    get:
      parameters:
        - {name: orgId, in: path, required: true, schema: {type: string}}
        - {name: repo, in: path, required: true, schema: {type: string}}
      responses: {"200": {description: ok}}
`

func reposIDs(overrides string) string {
	return `version: 1
roles: {user: 10}
identities:
  - {name: alice, role: user, match: {jwt: {sub: alice}}}
  - {name: bob, role: user, match: {jwt: {sub: bob}}}
resources: {orgId: orgs}
ownership:
  self_params: {orgId: subject}
` + overrides
}

func runInline(t *testing.T, spec, ids string, es []hartest.Entry, extra ...string) (int, string, string) {
	t.Helper()
	har := hartest.WriteHAR(t, t.TempDir(), "t.har", es...)
	args := []string{"coverage", "--spec", writeFile(t, "s.yml", spec), "--har", har, "--identities", writeFile(t, "ids.yaml", ids)}
	return runCLI(t, append(args, extra...)...)
}

func TestObjectParamOverride(t *testing.T) {
	a := hartest.Bearer(hartest.JWT(t, "alice", nil))
	es := []hartest.Entry{{Method: "GET", URL: base + "/orgs/alice/repos/r1", Status: 200, Headers: a}}
	const row = "GET     /orgs/{orgId}/repos/{repo}"
	code, out, errs := runInline(t, reposSpec, reposIDs(""), es)
	if code != ExitOK || cells(t, out, row)["OWNER"] != "GAP" {
		t.Fatalf("without override: exit %d, owner %q\n%s%s", code, cells(t, out, row)["OWNER"], out, errs)
	}
	ov := "requirements:\n  overrides:\n    - {endpoint: \"GET /orgs/{orgId}/repos/{repo}\", object_param: orgId}\n"
	code, out, errs = runInline(t, reposSpec, reposIDs(ov), es)
	if code != ExitOK || cells(t, out, row)["OWNER"] != "ok" {
		t.Fatalf("with override: exit %d\n%s%s", code, out, errs)
	}
}

func TestOverrideErrors(t *testing.T) {
	tests := []struct{ name, ov, msg string }{
		{"unknown endpoint", `{endpoint: "GET /nope/{x}", object_param: x}`, `endpoint "GET /nope/{x}" is not in the spec`},
		{"bad param", `{endpoint: "GET /orgs/{orgId}/repos/{repo}", object_param: nope}`, `object_param "nope" is not a path parameter`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ids := reposIDs("requirements:\n  overrides:\n    - " + tc.ov + "\n")
			code, out, errs := runInline(t, reposSpec, ids, nil)
			if code != ExitUsage || out != "" || !strings.Contains(errs, tc.msg) || !strings.Contains(errs, "ids.yaml:") {
				t.Fatalf("exit %d out %q err %q", code, out, errs)
			}
		})
	}
}

func TestJWTTenantClaim(t *testing.T) {
	ids := `version: 1
roles: {user: 10}
identities:
  - {name: alice, role: user, match: {jwt: {sub: alice}}}
  - {name: bob, role: user, match: {jwt: {sub: bob}}}
  - {name: carol, role: user, match: {jwt: {sub: carol}}}
jwt: {subject: sub, tenant: org_id}
tenancy:
  tenant_params: {orgId: name}
`
	tok := func(sub string, extra map[string]any) map[string]string {
		return hartest.Bearer(hartest.JWT(t, sub, extra))
	}
	u := base + "/orgs/OrgA/projects"
	es := []hartest.Entry{
		{Method: "GET", URL: u, Status: 403, Headers: tok("carol", map[string]any{"org_id": "OrgB"})},
		{Method: "GET", URL: u, Status: 200, Headers: tok("alice", map[string]any{"org_id": "OrgA"})},
		{Method: "GET", URL: u, Status: 403, Headers: tok("bob", nil)}, // no claim: no tenant, treated as other tenant
	}
	code, out, errs := runInline(t, tenantsSpec, ids, es)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	row := cells(t, out, "GET     /orgs/{orgId}/projects")
	if row["OTHER_TENANT"] != "ok 403" {
		t.Errorf("OTHER_TENANT = %q\n%s", row["OTHER_TENANT"], out)
	}
	if strings.Contains(out, "eyJ") {
		t.Error("output contains a token")
	}
}

func TestStrictFlagEffect(t *testing.T) {
	ids := writeFile(t, "ids.yaml", listsIDs)
	har := hartest.WriteHAR(t, t.TempDir(), "t.har", listsEntries(t)...)
	_, loose, _ := runCLI(t, "coverage", "--spec", vampi, "--har", har, "--identities", ids)
	_, strict, _ := runCLI(t, "coverage", "--spec", vampi, "--har", har, "--identities", ids, "--strict")
	const row = "GET     /books/v1/{book_title}"
	if cells(t, loose, row)["OWNER"] != "ok~" || cells(t, strict, row)["OWNER"] != "GAP" {
		t.Fatalf("loose:\n%s\nstrict:\n%s", loose, strict)
	}
	if strings.Contains(strict, "~") {
		t.Errorf("strict output has inferred marker:\n%s", strict)
	}
}

func TestOtherTenantUnknownOwner(t *testing.T) {
	carol := hartest.Bearer(hartest.JWT(t, "carol", nil))
	es := []hartest.Entry{
		{Method: "GET", URL: base + "/orgs/OrgA/projects/nope", Status: 403, Headers: carol},
	}
	code, out, errs := runInline(t, tenantsSpec, tenantsIDs, es)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	row := cells(t, out, "GET     /orgs/{orgId}/projects/{id}")
	if row["OTHER_TENANT"] != "ok 403" || row["OWNER"] != "GAP" || row["SAME_ROLE"] != "GAP" {
		t.Errorf("cells = %v\n%s", row, out)
	}
}
