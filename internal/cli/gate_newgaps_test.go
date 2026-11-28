package cli

import (
	"strings"
	"testing"

	"authzcov/internal/report/coveragejson"
)

// A new Missing cell on an endpoint already in the baseline must fail new-gaps.
func TestGateNewGapOnExistingEndpointFails(t *testing.T) {
	cov := gateFixture(t)
	var ep string
	mutateReport(t, cov, func(r *coveragejson.Report) {
		ep = r.Cells[0].Endpoint
		r.Cells = append(r.Cells, coveragejson.Cell{Endpoint: ep, Relationship: "brand_new_rel", Required: true})
	})
	code, out, errs := runCLI(t, "gate", "--in", cov, "--fail-on", "new-gaps")
	if code != ExitGate || !strings.Contains(out, "new-gaps (1)\n  "+ep+"  brand_new_rel") || !strings.Contains(errs, "gate failed") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
}

func TestGateNoNewGapsPasses(t *testing.T) {
	cov := gateFixture(t)
	code, out, errs := runCLI(t, "gate", "--in", cov, "--fail-on", "new-gaps")
	if code != ExitOK || !strings.HasPrefix(out, "gate: pass\n") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
}
