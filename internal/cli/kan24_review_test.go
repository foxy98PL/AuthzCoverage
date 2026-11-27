package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// Review KAN-24 F2: waiver strings printed by `baseline diff` carry no control bytes.
func TestBaselineDiffStripsControlInWaiver(t *testing.T) {
	es, _ := entries(t)
	runCoverageIn(t, vampi, idsFx, es)
	cov := filepath.Join("out", "coverage.json")
	setNow(t, "2026-06-01")
	if code, _, errs := runCLI(t, "baseline", "write", "--in", cov); code != ExitOK {
		t.Fatalf("write: %d %s", code, errs)
	}
	// YAML double-quoted "\e" is ESC; the waiver is expired and matches nothing.
	writeBL(t, "w.yaml", waiverYAML(`GET /x\e[31m*`, "owner", "Accepted for the demo environment", "2026-01-01"))
	code, out, errs := runCLI(t, "baseline", "diff", "--in", cov, "--waivers", "w.yaml")
	if code != ExitOK {
		t.Fatalf("diff: %d %s", code, errs)
	}
	if !strings.Contains(out, "expired waivers (1)") {
		t.Fatalf("expected an expired waiver:\n%s", out)
	}
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(errs, 0x1b) {
		t.Errorf("control byte leaked:\n%q", out)
	}
}
