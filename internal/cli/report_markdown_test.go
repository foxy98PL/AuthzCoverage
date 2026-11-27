package cli

import (
	"strings"
	"testing"
)

func TestReportMarkdown(t *testing.T) {
	vampiEntries, _ := entries(t)
	runCoverageIn(t, vampi, idsFx, vampiEntries)
	code, out, errs := runCLI(t, "report", "--in", "out/coverage.json", "--format", "markdown")
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, errs)
	}
	first, _, _ := strings.Cut(out, "\n")
	if !strings.HasPrefix(first, "**authzcov:** ") || !strings.Contains(first, " required authorization checks covered (") {
		t.Errorf("first line = %q", first)
	}
	if code, _, errs := runCLI(t, "report", "--in", "out/coverage.json", "--format", "xml"); code != ExitUsage || !strings.Contains(errs, "markdown") {
		t.Errorf("unknown format: exit %d, stderr %s", code, errs)
	}
}
