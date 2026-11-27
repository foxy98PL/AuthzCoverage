package cli

import (
	"strings"
	"testing"

	"authzcov/internal/testutil/hartest"
)

const secSpec = `openapi: 3.0.3
info: {title: sec, version: "1"}
security: [{bearer: []}]
components:
  securitySchemes:
    bearer: {type: http, scheme: bearer}
paths:
  /orgs/{orgId}/customers:
    get:
      parameters: [{name: orgId, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: ok}}
  /orgs/{orgId}/public:
    get:
      security: []
      parameters: [{name: orgId, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: ok}}
  /admin/stats:
    get:
      responses: {"200": {description: ok}}
`

const secIDs = `version: 1
roles: {customer: 10, admin: 100}
jwt: {subject: sub, tenant: org_id}
tenancy:
  tenant_params: {orgId: name}
identities:
  - {name: ann, role: customer, match: {jwt: {sub: ann}}}
  - {name: adm, role: admin, match: {jwt: {sub: adm}}}
  - {name: ben, role: customer, match: {jwt: {sub: ben}}}
`

func secEntries(t *testing.T) []hartest.Entry {
	tok := func(sub, org string) map[string]string {
		return hartest.Bearer(hartest.JWT(t, sub, map[string]any{"org_id": org}))
	}
	body := `{"items":[1]}`
	e := func(path string, st int, h map[string]string) hartest.Entry {
		return hartest.Entry{Method: "GET", URL: base + path, Status: st, Headers: h, RespJSON: body}
	}
	return []hartest.Entry{
		e("/orgs/OrgA/customers", 200, tok("ann", "OrgA")),
		e("/orgs/OrgA/customers", 200, tok("adm", "OrgA")),
		e("/orgs/OrgA/customers", 403, tok("ben", "OrgB")),
		e("/orgs/OrgA/customers", 401, nil),
		e("/orgs/OrgA/public", 200, nil),
		e("/admin/stats", 200, tok("adm", "OrgA")),
		e("/admin/stats", 200, nil),
	}
}

func TestTenantScopedCLI(t *testing.T) {
	code, out, errs := runInline(t, secSpec, secIDs, secEntries(t))
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	row := cells(t, out, "GET     /orgs/{orgId}/customers")
	// Learned min is customer, the lowest role: lower_role is not required (O11).
	if row["OWNER"] == "GAP" || row["LOWER"] != "-" || row["OTHER_TENANT"] != "ok 403" || row["ANON"] != "ok 401" {
		t.Errorf("learned min cells = %v\n%s", row, out)
	}
	// Anonymous 200 on the auth-required function-level endpoint is a finding; public endpoint is not.
	if !strings.Contains(out, "! 1 suspicious allow(s)") {
		t.Errorf("want exactly one suspicious allow (anonymous on /admin/stats):\n%s", out)
	}
}

func TestMinRoleDeclaredCLI(t *testing.T) {
	ids := secIDs + "requirements:\n  overrides:\n    - {endpoint: \"GET /orgs/{orgId}/customers\", min_role: admin}\n"
	code, out, errs := runInline(t, secSpec, ids, secEntries(t))
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	row := cells(t, out, "GET     /orgs/{orgId}/customers")
	// ann (customer) is below the declared admin minimum: her 200 is a lower_role cell and a finding.
	if !strings.HasPrefix(row["LOWER"], "ok") || !strings.HasPrefix(row["OWNER"], "ok") {
		t.Errorf("cells = %v\n%s", row, out)
	}
	if !strings.Contains(out, "! 2 suspicious allow(s)") {
		t.Errorf("want 2 suspicious allows (anonymous /admin/stats, lower_role customers):\n%s", out)
	}
}

func TestMinRoleErrorsCLI(t *testing.T) {
	ids := secIDs + "requirements:\n  overrides:\n    - {endpoint: \"GET /nope\", min_role: admin}\n"
	code, _, errs := runInline(t, secSpec, ids, nil)
	if code != ExitUsage || !strings.Contains(errs, "is not in the spec") {
		t.Fatalf("exit %d err %q", code, errs)
	}
}

func TestMinRoleWithObjectParamCLI(t *testing.T) {
	spec := `openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /orgs/{orgId}/reports/{rid}:
    get:
      parameters:
        - {name: orgId, in: path, required: true, schema: {type: string}}
        - {name: rid, in: path, required: true, schema: {type: string}}
      responses: {"200": {description: ok}}
`
	ids := secIDs + "requirements:\n  overrides:\n    - {endpoint: \"GET /orgs/{orgId}/reports/{rid}\", object_param: orgId, min_role: admin}\n"
	tok := func(sub, org string) map[string]string {
		return hartest.Bearer(hartest.JWT(t, sub, map[string]any{"org_id": org}))
	}
	es := []hartest.Entry{
		{Method: "GET", URL: base + "/orgs/OrgA/reports/r1", Status: 200, Headers: tok("adm", "OrgA"), RespJSON: `{"a":1}`},
		{Method: "GET", URL: base + "/orgs/OrgA/reports/r1", Status: 403, Headers: tok("ann", "OrgA")},
		{Method: "GET", URL: base + "/orgs/OrgA/reports/r1", Status: 403, Headers: tok("ben", "OrgB")},
	}
	code, out, errs := runInline(t, spec, ids, es)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	row := cells(t, out, "GET     /orgs/{orgId}/reports/{rid}")
	if !strings.HasPrefix(row["OWNER"], "ok") || row["LOWER"] != "ok 403" || row["OTHER_TENANT"] != "ok 403" {
		t.Errorf("cells = %v\n%s", row, out)
	}
	if strings.Contains(out, "suspicious") {
		t.Errorf("unexpected finding:\n%s", out)
	}
}

func TestMinRoleOnPlainObjectEndpointRejected(t *testing.T) {
	ids := secIDs + "requirements:\n  overrides:\n    - {endpoint: \"GET /orgs/{orgId}/repos/{repo}\", min_role: admin}\n"
	code, out, errs := runInline(t, reposSpec, strings.Replace(ids, "jwt: {subject: sub, tenant: org_id}\n", "", 1), nil)
	if code != ExitUsage || out != "" || !strings.Contains(errs, "ids.yaml:") ||
		!strings.Contains(errs, "min_role applies only to function-level or tenant-scoped endpoints") {
		t.Fatalf("exit %d out %q err %q", code, out, errs)
	}
}
