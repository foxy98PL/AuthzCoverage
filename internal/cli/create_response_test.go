package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"authzcov/internal/ingest/har"
	"authzcov/internal/report/coveragejson"
	"authzcov/internal/testutil/hartest"
)

// KAN-89: ownership learned from a server-generated id in the create response
// gives the same matrix as the request-side id, and the raw id is not written.
func TestLearnFromCreateResponseJSON(t *testing.T) {
	spec := writeFile(t, "tenants.yml", tenantsSpec)
	reqIDs := writeFile(t, "req.yaml", tenantsIDs)
	respIDs := writeFile(t, "resp.yaml", strings.Replace(tenantsIDs, "request_json: id", "response_json: id", 1))

	es := tenantsEntries(t)
	es[0].ReqJSON = `{"name":"x"}`
	es[0].RespJSON = `{"id":"p1"}`

	_, want, _ := runCLI(t, "coverage", "--spec", spec, "--har", hartest.WriteHAR(t, t.TempDir(), "a.har", tenantsEntries(t)...), "--identities", reqIDs)
	code, got, errs := runCLI(t, "coverage", "--spec", spec, "--har", hartest.WriteHAR(t, t.TempDir(), "b.har", es...), "--identities", respIDs)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if got != want {
		t.Fatalf("response_json table differs from request_json:\n%s\nvs\n%s", got, want)
	}
	cov := runCoverageIn(t, spec, respIDs, es)
	var rep coveragejson.Report
	if err := json.Unmarshal([]byte(cov.json), &rep); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range rep.Objects {
		if o.Resource == "projects" && o.Owner == "alice" && o.Source == "create" && o.IDHash != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("coverage.json has no projects object owned by alice: %+v", rep.Objects)
	}
	if strings.Contains(cov.json, "p1") {
		t.Errorf("raw id leaked into coverage.json")
	}
}

// KAN-89: a create response larger than har.MaxBody is dropped at ingest, so
// the id is not learned and no object is owned.
func TestLearnFromCreateResponseOversizedNotLearned(t *testing.T) {
	spec := writeFile(t, "tenants.yml", tenantsSpec)
	respIDs := writeFile(t, "resp.yaml", strings.Replace(tenantsIDs, "request_json: id", "response_json: id", 1))
	es := tenantsEntries(t)
	es[0].ReqJSON = `{"name":"x"}`
	es[0].RespJSON = `{"id":"p1","pad":"` + strings.Repeat("a", har.MaxBody+1) + `"}`
	cov := runCoverageIn(t, spec, respIDs, es)
	var rep coveragejson.Report
	if err := json.Unmarshal([]byte(cov.json), &rep); err != nil {
		t.Fatal(err)
	}
	for _, o := range rep.Objects {
		if o.Resource == "projects" {
			t.Fatalf("oversized create response must not own an object: %+v", o)
		}
	}
}
