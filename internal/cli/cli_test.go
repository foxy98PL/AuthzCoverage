package cli

import (
	"bytes"
	"strings"
	"testing"

	"authzcov/internal/testutil/hartest"
)

const (
	specs = "../../testdata/specs/"
	vampi = specs + "vampi.yml"
	idsFx = "../../testdata/identities/vampi.yaml"
)

func TestExecuteExitCodes(t *testing.T) {
	dir := t.TempDir()
	e := hartest.Entry{Method: "GET", URL: "http://localhost:5000/me", Status: 200, Headers: hartest.Bearer(hartest.JWT(t, "alice", nil))}
	har1 := hartest.WriteHAR(t, dir, "a.har", e)
	har2 := hartest.WriteHAR(t, dir, "b.har", e)
	tests := []struct {
		name    string
		args    []string
		want    int
		wantErr string
	}{
		{"no args shows help", nil, ExitOK, ""},
		{"version", []string{"version"}, ExitOK, ""},
		{"unknown command", []string{"nope"}, ExitUsage, "unknown command"},
		{"unknown flag", []string{"coverage", "--bogus"}, ExitUsage, "unknown flag"},
		{"missing spec", []string{"coverage", "--har", "a.har", "--identities", "i.yaml"}, ExitUsage, "missing --spec"},
		{"missing har", []string{"coverage", "--spec", "s.yml", "--identities", "i.yaml"}, ExitUsage, "missing --har"},
		{"missing identities", []string{"coverage", "--spec", "s.yml", "--har", "a.har"}, ExitUsage, "missing --identities"},
		{"positional arg", []string{"coverage", "extra"}, ExitUsage, "unknown command"},
		{"all flags", []string{"coverage", "--spec", vampi, "--har", har1, "--har", har2, "--identities", idsFx, "--strict"}, ExitOK, "from 2 HAR file(s)"},
		{"unreadable spec", []string{"coverage", "--spec", "nope.yml", "--har", "a.har", "--identities", idsFx}, ExitInput, "spec nope.yml"},
		{"duplicate template", []string{"coverage", "--spec", specs + "dup_param_names.yml", "--har", "a.har", "--identities", idsFx}, ExitInput, "duplicate endpoint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			got := Execute(tt.args, &out, &errb)
			if got != tt.want {
				t.Fatalf("exit = %d, want %d; stderr=%q", got, tt.want, errb.String())
			}
			if tt.wantErr != "" && !strings.Contains(errb.String(), tt.wantErr) {
				t.Fatalf("stderr = %q, want substring %q", errb.String(), tt.wantErr)
			}
		})
	}
}

func TestCoverageHelpListsFlags(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Execute([]string{"coverage", "--help"}, &out, &errb); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	for _, flag := range []string{"--spec", "--har", "--identities", "--strict"} {
		if !strings.Contains(out.String(), flag) {
			t.Errorf("help missing %s:\n%s", flag, out.String())
		}
	}
}

func TestRepeatableHar(t *testing.T) {
	cmd := newCoverageCmd()
	if err := cmd.ParseFlags([]string{"--har", "a.har", "--har", "b.har"}); err != nil {
		t.Fatal(err)
	}
	got, _ := cmd.Flags().GetStringArray("har")
	if len(got) != 2 || got[0] != "a.har" || got[1] != "b.har" {
		t.Fatalf("har = %v", got)
	}
}
