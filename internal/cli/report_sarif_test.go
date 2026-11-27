package cli

import (
	"encoding/json"
	"testing"
)

func TestReportSARIF(t *testing.T) {
	vampiEntries, _ := entries(t)
	runCoverageIn(t, vampi, idsFx, vampiEntries)
	code, out, errs := runCLI(t, "report", "--in", "out/coverage.json", "--format", "sarif")
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, errs)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Results) == 0 {
		t.Errorf("unexpected SARIF: version=%q runs=%d", doc.Version, len(doc.Runs))
	}
	if code, _, _ := runCLI(t, "report", "--in", "out/coverage.json", "--format", "xml"); code != ExitUsage {
		t.Errorf("bad format exit = %d, want %d", code, ExitUsage)
	}
}
