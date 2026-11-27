package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authzcov/internal/report/coveragejson"
)

// gateFixture runs coverage, writes a baseline from it and returns the path of
// the coverage.json.
func gateFixture(t *testing.T) string {
	t.Helper()
	es, _ := entries(t)
	runCoverageIn(t, vampi, idsFx, es)
	cov := filepath.Join("out", "coverage.json")
	if code, _, errs := runCLI(t, "baseline", "write", "--in", cov); code != ExitOK {
		t.Fatalf("baseline write: %d %s", code, errs)
	}
	return cov
}

func mutateReport(t *testing.T, path string, fn func(r *coveragejson.Report)) {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	r, err := coveragejson.Read(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	fn(r)
	out, err := os.Create(path) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	if err := coveragejson.Write(out, r); err != nil {
		t.Fatal(err)
	}
}

func uncoverFirst(r *coveragejson.Report) (string, string) {
	for i := range r.Cells {
		if r.Cells[i].Required && r.Cells[i].Covered {
			r.Cells[i].Covered = false
			return r.Cells[i].Endpoint, r.Cells[i].Relationship
		}
	}
	return "", ""
}

func TestGateUnchangedPasses(t *testing.T) {
	cov := gateFixture(t)
	code, out, errs := runCLI(t, "gate", "--in", cov)
	if code != ExitOK || !strings.HasPrefix(out, "gate: pass\ncoverage ") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
}

func TestGateNewEndpointGap(t *testing.T) { // AC1
	cov := gateFixture(t)
	mutateReport(t, cov, func(r *coveragejson.Report) {
		r.Cells = append(r.Cells, coveragejson.Cell{Endpoint: "GET /orders/{orderId}", Relationship: "same_role_other_user", Required: true})
	})
	code, out, errs := runCLI(t, "gate", "--in", cov)
	if code != ExitGate || !strings.Contains(out, "gate: FAIL (new-gaps") ||
		!strings.Contains(out, "new-gaps (1)\n  GET /orders/{orderId}  same_role_other_user") || !strings.Contains(errs, "gate failed") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
}

func TestGateRegression(t *testing.T) { // AC2
	cov := gateFixture(t)
	var ep, rel string
	mutateReport(t, cov, func(r *coveragejson.Report) { ep, rel = uncoverFirst(r) })
	code, out, _ := runCLI(t, "gate", "--in", cov, "--fail-on", "regressions")
	if code != ExitGate || !strings.Contains(out, "gate: FAIL (regressions)") ||
		!strings.Contains(out, "regressions (1)\n  "+ep+"  "+rel) {
		t.Fatalf("%d\n%s", code, out)
	}
}

func TestGateDrop(t *testing.T) { // AC3
	cov := gateFixture(t)
	mutateReport(t, cov, func(r *coveragejson.Report) { uncoverFirst(r) })
	code, out, _ := runCLI(t, "gate", "--in", cov, "--fail-on", "drop")
	if code != ExitGate || !strings.Contains(out, "drop\n  coverage ") || !strings.Contains(out, "% -> ") ||
		!strings.Contains(out, "(max drop 0)") {
		t.Fatalf("%d\n%s", code, out)
	}
	// A generous --max-drop lets it pass.
	if code, out, _ := runCLI(t, "gate", "--in", cov, "--fail-on", "drop", "--max-drop", "100"); code != ExitOK {
		t.Fatalf("%d\n%s", code, out)
	}
}

func TestGateFailOnSubsetIgnores(t *testing.T) { // AC4
	cov := gateFixture(t)
	mutateReport(t, cov, func(r *coveragejson.Report) { uncoverFirst(r) })
	code, out, errs := runCLI(t, "gate", "--in", cov, "--fail-on", "new-gaps")
	if code != ExitOK || !strings.HasPrefix(out, "gate: pass\n") || !strings.Contains(out, "ignored: regressions (1)") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
}

func TestGateUnreadableInputs(t *testing.T) { // AC5
	cov := gateFixture(t)
	if err := os.WriteFile("bad.json", []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{"bad.json", "missing.json"} {
		if code, _, errs := runCLI(t, "gate", "--in", in); code != ExitInput {
			t.Errorf("%s: %d %s", in, code, errs)
		}
	}
	code, _, errs := runCLI(t, "gate", "--in", cov, "--baseline", "nope.json")
	if code != ExitInput || !strings.Contains(errs, "authzcov baseline write") {
		t.Errorf("missing baseline: %d %s", code, errs)
	}
	if err := os.WriteFile("badbase.json", []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(t, "gate", "--in", cov, "--baseline", "badbase.json"); code != ExitInput {
		t.Errorf("bad baseline: %d", code)
	}
}

func TestGateUsageErrors(t *testing.T) {
	cov := gateFixture(t)
	for _, args := range [][]string{
		{"--fail-on", "bogus"}, {"--fail-on", ""}, {"--fail-on", "drop,"},
		{"--max-drop", "-1"}, {"--max-drop", "NaN"}, {"--max-drop", "abc"},
		{"--max-drop", "Inf"}, {"--max-drop", "+Inf"}, {"--max-drop", "inf"},
		{"--waivers", "missing.yaml"},
	} {
		if code, _, errs := runCLI(t, append([]string{"gate", "--in", cov}, args...)...); code != ExitUsage {
			t.Errorf("%v: %d %s", args, code, errs)
		}
	}
}

func TestGateExpiredWaiver(t *testing.T) {
	es, _ := entries(t)
	run := runCoverageIn(t, vampi, idsFx, es)
	ep, rel := firstGap(t, run.json)
	cov := filepath.Join("out", "coverage.json")
	setNow(t, "2026-06-01")
	writeBL(t, "w.yaml", waiverYAML(ep, rel, "Accepted for the demo environment", "2026-12-31"))
	if code, _, errs := runCLI(t, "baseline", "write", "--in", cov, "--waivers", "w.yaml"); code != ExitOK {
		t.Fatalf("write: %d %s", code, errs)
	}
	if code, out, _ := runCLI(t, "gate", "--in", cov, "--waivers", "w.yaml"); code != ExitOK {
		t.Fatalf("before expiry: %d\n%s", code, out)
	}
	// A waiver is still valid on its expiry date.
	setNow(t, "2026-12-31")
	if code, out, _ := runCLI(t, "gate", "--in", cov, "--waivers", "w.yaml", "--fail-on", "expired-waivers"); code != ExitOK {
		t.Fatalf("on expiry day: %d\n%s", code, out)
	}
	setNow(t, "2027-01-02")
	code, out, _ := runCLI(t, "gate", "--in", cov, "--waivers", "w.yaml", "--fail-on", "expired-waivers")
	if code != ExitGate || !strings.Contains(out, "expired-waivers (1)") || !strings.Contains(out, "2026-12-31") {
		t.Fatalf("%d\n%s", code, out)
	}
	// waived -> missing is not a regression for the gate.
	if code, out, _ := runCLI(t, "gate", "--in", cov, "--waivers", "w.yaml", "--fail-on", "regressions,new-gaps"); code != ExitOK {
		t.Fatalf("%d\n%s", code, out)
	}
}

func TestGateRemovedEndpointNeverFails(t *testing.T) {
	cov := gateFixture(t)
	var gone string
	mutateReport(t, cov, func(r *coveragejson.Report) {
		gone = r.Cells[0].Endpoint
		kept := r.Cells[:0]
		for _, c := range r.Cells {
			if c.Endpoint != gone {
				kept = append(kept, c)
			}
		}
		r.Cells = kept
	})
	code, out, _ := runCLI(t, "gate", "--in", cov, "--fail-on", "new-gaps,regressions,expired-waivers")
	if code != ExitOK || !strings.Contains(out, "removed endpoints (1)\n  "+gone) {
		t.Fatalf("%d\n%s", code, out)
	}
}
