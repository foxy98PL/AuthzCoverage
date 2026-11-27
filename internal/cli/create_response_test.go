package cli

import (
	"strings"
	"testing"

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
	if strings.Contains(cov.json, `"p1"`) {
		t.Errorf("raw id leaked into coverage.json")
	}
}
