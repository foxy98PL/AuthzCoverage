package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// firstGap returns the endpoint and relationship of a required, uncovered cell.
func firstGap(t *testing.T, covJSON string) (string, string) {
	t.Helper()
	var r struct {
		Cells []struct {
			Endpoint, Relationship string
			Required, Covered      bool
		}
	}
	if err := json.Unmarshal([]byte(covJSON), &r); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Cells {
		if c.Required && !c.Covered {
			return c.Endpoint, c.Relationship
		}
	}
	t.Fatal("fixture has no gap")
	return "", ""
}

func setNow(t *testing.T, s string) {
	t.Helper()
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		t.Fatal(err)
	}
	old := now
	now = func() time.Time { return d.Add(13 * time.Hour) }
	t.Cleanup(func() { now = old })
}

func writeBL(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func waiverYAML(ep, rel, reason, exp string) string {
	s := "schema: authzcov.waivers/v1\nwaivers:\n  - endpoint: \"" + ep + "\"\n    relationship: " + rel + "\n"
	if reason != "" {
		s += "    reason: " + reason + "\n"
	}
	return s + "    expires: " + exp + "\n"
}

func TestBaselineWriteDeterministic(t *testing.T) {
	es, _ := entries(t)
	runCoverageIn(t, vampi, idsFx, es)
	cov := filepath.Join("out", "coverage.json")
	var first []byte
	for i := 0; i < 2; i++ {
		code, _, errs := runCLI(t, "baseline", "write", "--in", cov, "--out", ".authzcov/baseline.json")
		if code != ExitOK || !strings.Contains(errs, "wrote .authzcov/baseline.json") {
			t.Fatalf("exit=%d stderr=%s", code, errs)
		}
		b, err := os.ReadFile(".authzcov/baseline.json")
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = b
		} else if string(b) != string(first) {
			t.Error("rewrite is not byte-identical")
		}
	}
	s := string(first)
	if !strings.Contains(s, `"schema": "authzcov.baseline/v1"`) || strings.Contains(s, "generated") || strings.Contains(s, "2026") {
		t.Errorf("unexpected content:\n%s", s)
	}
	if info, err := os.Stat(".authzcov/baseline.json"); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("stat = %v %v", info, err)
	}
}

func TestBaselineDiffWaived(t *testing.T) {
	es, _ := entries(t)
	run := runCoverageIn(t, vampi, idsFx, es)
	setNow(t, "2026-06-01")
	ep, rel := firstGap(t, run.json)
	cov := filepath.Join("out", "coverage.json")
	if code, _, errs := runCLI(t, "baseline", "write", "--in", cov); code != ExitOK {
		t.Fatalf("write: %d %s", code, errs)
	}
	writeBL(t, "w.yaml", waiverYAML(ep, rel, "Accepted for the demo environment", "2026-12-31"))
	code, out, errs := runCLI(t, "baseline", "diff", "--in", cov, "--waivers", "w.yaml")
	if code != ExitOK {
		t.Fatalf("diff: %d %s", code, errs)
	}
	if !strings.Contains(out, "waived (1)") || !strings.Contains(out, ep+"  "+rel+"  missing -> waived") ||
		strings.Contains(out, "expired") || !strings.Contains(out, "coverage ") {
		t.Errorf("diff output:\n%s", out)
	}
	// The coverage run with --waivers records the waiver and recomputes the summary.
	code, _, errs = runCLI(t, "coverage", "--spec", "spec.yml", "--har", "t.har", "--identities", "ids.yaml",
		"--out", "out2", "--waivers", "w.yaml")
	if code != ExitOK {
		t.Fatalf("coverage: %d %s", code, errs)
	}
	b, _ := os.ReadFile(filepath.Join("out2", "coverage.json"))
	if !strings.Contains(string(b), `"waiver": {`) || !strings.Contains(string(b), `"waived": 1`) {
		t.Error("coverage.json lacks waiver / summary.waived")
	}
}

func TestBaselineDiffExpired(t *testing.T) {
	es, _ := entries(t)
	run := runCoverageIn(t, vampi, idsFx, es)
	ep, rel := firstGap(t, run.json)
	cov := filepath.Join("out", "coverage.json")
	setNow(t, "2026-06-01")
	writeBL(t, "w.yaml", waiverYAML(ep, rel, "Accepted for the demo environment", "2026-12-31"))
	if code, _, errs := runCLI(t, "baseline", "write", "--in", cov, "--waivers", "w.yaml"); code != ExitOK {
		t.Fatalf("write: %d %s", code, errs)
	}
	b, _ := os.ReadFile(".authzcov/baseline.json")
	if !strings.Contains(string(b), `"waived"`) {
		t.Fatalf("baseline lacks waived cell:\n%s", b)
	}
	setNow(t, "2027-01-02")
	code, out, errs := runCLI(t, "baseline", "diff", "--in", cov, "--waivers", "w.yaml")
	if code != ExitOK {
		t.Fatalf("diff: %d %s", code, errs)
	}
	if !strings.Contains(out, "expired waivers (1)") || !strings.Contains(out, "2026-12-31") ||
		!strings.Contains(out, "regressions (1)") || !strings.Contains(out, "waived -> missing") {
		t.Errorf("diff output:\n%s", out)
	}
	if strings.Index(out, "regressions") > strings.Index(out, "expired waivers") {
		t.Errorf("section order:\n%s", out)
	}
}

func TestWaiversWithoutReasonExit2(t *testing.T) {
	es, _ := entries(t)
	run := runCoverageIn(t, vampi, idsFx, es)
	ep, rel := firstGap(t, run.json)
	setNow(t, "2026-06-01")
	writeBL(t, "w.yaml", waiverYAML(ep, rel, "", "2026-12-31"))
	cov := filepath.Join("out", "coverage.json")
	for _, args := range [][]string{
		{"baseline", "write", "--in", cov, "--waivers", "w.yaml"},
		{"baseline", "diff", "--in", cov, "--waivers", "w.yaml"},
		{"coverage", "--spec", "spec.yml", "--har", "t.har", "--identities", "ids.yaml", "--out", "o3", "--waivers", "w.yaml"},
	} {
		code, _, errs := runCLI(t, args...)
		if code != ExitUsage || !strings.Contains(errs, "w.yaml:3: missing reason") {
			t.Errorf("%v: exit=%d stderr=%s", args[:2], code, errs)
		}
	}
}

func TestWaiversPathHandling(t *testing.T) {
	es, _ := entries(t)
	runCoverageIn(t, vampi, idsFx, es)
	cov := filepath.Join("out", "coverage.json")
	if code, _, errs := runCLI(t, "baseline", "write", "--in", cov, "--waivers", "missing.yaml"); code != ExitUsage {
		t.Errorf("explicit missing waivers: exit=%d %s", code, errs)
	}
	// The default path is used only when it exists; here it is absent.
	if code, _, errs := runCLI(t, "baseline", "write", "--in", cov); code != ExitOK {
		t.Errorf("default absent: exit=%d %s", code, errs)
	}
	// The default path is picked up when present (and validated).
	if err := os.MkdirAll(".authzcov", 0o750); err != nil {
		t.Fatal(err)
	}
	writeBL(t, defaultWaivers, "not: [valid")
	if code, _, _ := runCLI(t, "baseline", "write", "--in", cov); code != ExitUsage {
		t.Errorf("invalid default waivers: exit=%d", code)
	}
}

func TestBaselineInputErrors(t *testing.T) {
	es, _ := entries(t)
	runCoverageIn(t, vampi, idsFx, es)
	cov := filepath.Join("out", "coverage.json")
	writeBL(t, "bad.json", `{"schema":"authzcov.baseline/v9","cells":{}}`)
	writeBL(t, "notcov.json", `{"schema":"x"}`)
	cases := []struct {
		args []string
		want int
	}{
		{[]string{"baseline", "diff", "--baseline", "bad.json", "--in", cov}, ExitInput},
		{[]string{"baseline", "diff", "--baseline", "nope.json", "--in", cov}, ExitInput},
		{[]string{"baseline", "write", "--in", "notcov.json"}, ExitInput},
		{[]string{"baseline", "write", "--in", "nope.json"}, ExitInput},
		{[]string{"baseline", "write", "--in", ""}, ExitUsage},
		{[]string{"baseline", "diff", "--baseline", "", "--in", cov}, ExitUsage},
		{[]string{"baseline", "write", "--bogus"}, ExitUsage},
	}
	for _, c := range cases {
		if code, _, errs := runCLI(t, c.args...); code != c.want {
			t.Errorf("%v: exit=%d want %d (%s)", c.args, code, c.want, errs)
		}
	}
}
