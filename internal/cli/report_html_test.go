package cli

import (
	"strings"
	"testing"
)

func TestReportHTML(t *testing.T) {
	vampiEntries, _ := entries(t)
	runCoverageIn(t, vampi, idsFx, vampiEntries)
	code, out, errs := runCLI(t, "report", "--in", "out/coverage.json", "--format", "html")
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, errs)
	}
	if !strings.HasPrefix(out, "<!doctype html>") || !strings.Contains(out, "Content-Security-Policy") {
		t.Errorf("not the HTML report: %.80q", out)
	}
	code, _, errs = runCLI(t, "report", "--in", "out/coverage.json", "--format", "xml")
	if code != ExitUsage || !strings.Contains(errs, "table, json, markdown, sarif or html") {
		t.Errorf("bad format: exit %d, stderr %q", code, errs)
	}
}
