package cli

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authzcov/internal/report/coveragejson"
	htmlreport "authzcov/internal/report/html"
	"authzcov/internal/report/markdown"
	"authzcov/internal/report/sarif"
	"authzcov/internal/testutil/hartest"
)

// update rewrites the golden files: go test ./internal/cli -run TestGolden -update
var update = flag.Bool("update", false, "rewrite testdata/golden/*.txt, *.coverage.json, *.md, *.sarif and *.html")

const goldenDir = "../../testdata/golden"

const tenantsSpec = `openapi: 3.0.3
info: {title: tenants, version: "1"}
paths:
  /orgs/{orgId}/projects:
    get:
      parameters: [{name: orgId, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: ok}}
    post:
      parameters: [{name: orgId, in: path, required: true, schema: {type: string}}]
      responses: {"201": {description: created}}
  /orgs/{orgId}/projects/{id}:
    get:
      parameters:
        - {name: orgId, in: path, required: true, schema: {type: string}}
        - {name: id, in: path, required: true, schema: {type: string}}
      responses: {"200": {description: ok}}
`

const tenantsIDs = `version: 1
roles: {user: 10}
identities:
  - {name: alice, role: user, tenant: OrgA, match: {jwt: {sub: alice}}}
  - {name: bob, role: user, tenant: OrgA, match: {jwt: {sub: bob}}}
  - {name: carol, role: user, tenant: OrgB, match: {jwt: {sub: carol}}}
resources: {id: projects}
tenancy:
  tenant_params: {orgId: name}
ownership:
  learn_from_create:
    - match: {method: POST, path: "/orgs/{orgId}/projects"}
      resource: projects
      id_from: {request_json: id}
`

const listsIDs = `version: 1
roles: {user: 10, admin: 100}
identities:
  - {name: alice, role: user, match: {jwt: {sub: alice}}}
  - {name: bob, role: user, match: {jwt: {sub: bob}}}
resources: {book_title: books}
ownership:
  learn_from_lists:
    - match: {method: GET, path: /books/v1}
      resource: books
      ids_from: {response_json: "Books[].book_title"}
`

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func tenantsEntries(t *testing.T) []hartest.Entry {
	t.Helper()
	tok := func(sub string) map[string]string { return hartest.Bearer(hartest.JWT(t, sub, nil)) }
	b := base + "/orgs/OrgA/projects"
	return []hartest.Entry{
		{Method: "POST", URL: b, Status: 201, Headers: tok("alice"), ReqJSON: `{"id":"p1"}`},
		{Method: "GET", URL: b + "/p1", Status: 200, Headers: tok("alice")},
		{Method: "GET", URL: b + "/p1", Status: 200, Headers: tok("bob")},
		{Method: "GET", URL: b + "/p1", Status: 403, Headers: tok("carol")},
		{Method: "GET", URL: b + "/p1", Status: 401},
		{Method: "GET", URL: b, Status: 403, Headers: tok("carol")},
	}
}

func listsEntries(t *testing.T) []hartest.Entry {
	t.Helper()
	a := hartest.Bearer(hartest.JWT(t, "alice", nil))
	b := hartest.Bearer(hartest.JWT(t, "bob", nil))
	return []hartest.Entry{
		{Method: "GET", URL: base + "/books/v1", Status: 200, Headers: a, RespJSON: `{"Books":[{"book_title":"a1"}]}`},
		{Method: "GET", URL: base + "/books/v1", Status: 200, Headers: b, RespJSON: `{"Books":[{"book_title":"b1"}]}`},
		{Method: "GET", URL: base + "/books/v1/a1", Status: 200, Headers: a},
		{Method: "GET", URL: base + "/books/v1/a1", Status: 200, Headers: b},
		{Method: "GET", URL: base + "/books/v1/a1", Status: 401},
	}
}

func TestGolden(t *testing.T) {
	// runCoverageIn changes the working directory, so resolve the golden dir first.
	goldenAbs, err := filepath.Abs(goldenDir)
	if err != nil {
		t.Fatal(err)
	}
	vampiEntries, _ := entries(t)
	tenantsSpecFile := writeFile(t, "tenants.yml", tenantsSpec)
	tenantsIDsFile := writeFile(t, "ids.yaml", tenantsIDs)
	listsIDsFile := writeFile(t, "ids.yaml", listsIDs)
	tests := []struct {
		name      string
		spec, ids string
		es        []hartest.Entry
		extra     []string
	}{
		{"vampi-fixture", vampi, idsFx, vampiEntries, nil},
		{"tenants-fixture", tenantsSpecFile, tenantsIDsFile, tenantsEntries(t), nil},
		{"lists-fixture", vampi, listsIDsFile, listsEntries(t), nil},
		{"lists-fixture-strict", vampi, listsIDsFile, listsEntries(t), []string{"--strict"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := func(es []hartest.Entry) []string {
				har := hartest.WriteHAR(t, t.TempDir(), "t.har", es...)
				return append([]string{"coverage", "--spec", tc.spec, "--har", har, "--identities", tc.ids}, tc.extra...)
			}
			code, out, errs := runCLI(t, args(tc.es)...)
			if code != ExitOK {
				t.Fatalf("exit = %d; stderr=%s", code, errs)
			}
			// HAR order must not change the matrix.
			if code, rev, errs := runCLI(t, args(reverse(tc.es))...); code != ExitOK || rev != out {
				t.Fatalf("reversed HAR differs (exit %d, stderr %s):\n%s\nvs\n%s", code, errs, rev, out)
			}
			cov := runCoverageIn(t, tc.spec, tc.ids, tc.es, tc.extra...)
			if cov.stdout != out {
				t.Errorf("table differs when run with --out:\n%s\nvs\n%s", cov.stdout, out)
			}
			checkGolden(t, filepath.Join(goldenAbs, tc.name+".txt"), out)
			checkGolden(t, filepath.Join(goldenAbs, tc.name+".coverage.json"), cov.json)
			rep, err := coveragejson.Read(strings.NewReader(cov.json))
			if err != nil {
				t.Fatal(err)
			}
			var md bytes.Buffer
			if err := markdown.Render(&md, rep); err != nil {
				t.Fatal(err)
			}
			checkGolden(t, filepath.Join(goldenAbs, tc.name+".md"), md.String())
			var sf bytes.Buffer
			if err := sarif.Render(&sf, rep); err != nil {
				t.Fatal(err)
			}
			checkGolden(t, filepath.Join(goldenAbs, tc.name+".sarif"), sf.String())
			var hf bytes.Buffer
			if err := htmlreport.Render(&hf, rep); err != nil {
				t.Fatal(err)
			}
			checkGolden(t, filepath.Join(goldenAbs, tc.name+".html"), hf.String())
		})
	}
}

// checkGolden compares got with the golden file, or rewrites it with -update.
func checkGolden(t *testing.T, path, got string) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil { //nolint:gosec // golden files are meant to be readable
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // fixed test path
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/cli -run TestGolden -update)", err)
	}
	if string(want) != got {
		t.Errorf("golden %s differs (run with -update to accept):\ngot:\n%s\nwant:\n%s", filepath.Base(path), got, want)
	}
}
