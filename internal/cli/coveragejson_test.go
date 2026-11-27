package cli

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authzcov/internal/testutil/hartest"
)

// fixedEpoch is 2026-01-01T00:00:00Z.
const fixedEpoch = "1767225600"

// covRun is the result of one coverage run in an isolated working directory.
type covRun struct {
	stdout, stderr, json string
	dir                  string
}

// runCoverageIn runs `coverage` in a fresh working directory whose spec,
// identities and HAR files get fixed relative names, so paths and hashes in
// coverage.json are stable. Callers must not be parallel (t.Chdir, t.Setenv).
func runCoverageIn(t *testing.T, specSrc, idsSrc string, es []hartest.Entry, extra ...string) covRun {
	t.Helper()
	specB, err := os.ReadFile(fromPkgDir(specSrc)) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	idsB, err := os.ReadFile(fromPkgDir(idsSrc)) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, b := range map[string][]byte{"spec.yml": specB, "ids.yaml": idsB} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	hartest.WriteHAR(t, dir, "t.har", es...)
	t.Chdir(dir)
	t.Setenv("SOURCE_DATE_EPOCH", fixedEpoch)
	args := append([]string{"coverage", "--spec", "spec.yml", "--har", "t.har", "--identities", "ids.yaml", "--out", "out"}, extra...)
	code, out, errs := runCLI(t, args...)
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, errs)
	}
	b, err := os.ReadFile(filepath.Join(dir, "out", "coverage.json")) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	return covRun{stdout: out, stderr: errs, json: string(b), dir: dir}
}

// stripOrderDependent removes what legitimately depends on HAR bytes or entry
// order: file hashes and evidence references (file#index).
func stripOrderDependent(t *testing.T, doc string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatal(err)
	}
	var walk func(any)
	walk = func(n any) {
		switch x := n.(type) {
		case map[string]any:
			delete(x, "sha256")
			delete(x, "evidence")
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(v)
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCoverageJSONWritten(t *testing.T) {
	es, _ := entries(t)
	r := runCoverageIn(t, vampi, idsFx, es)
	for _, want := range []string{
		`"schema": "authzcov.coverage/v1"`, `"generated_at": "2026-01-01T00:00:00Z"`,
		`"path": "spec.yml"`, `"path": "t.har"`, `"evidence": "refs"`, `"mode": "auto"`, `"kind": "gap"`,
	} {
		if !strings.Contains(r.json, want) {
			t.Errorf("coverage.json lacks %s", want)
		}
	}
	if !strings.Contains(r.stderr, "wrote out/coverage.json\n") {
		t.Errorf("stderr lacks wrote line:\n%s", r.stderr)
	}
	st, err := os.Stat(filepath.Join(r.dir, "out", "coverage.json"))
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Errorf("stat = %v, %v", st, err)
	}
	left, _ := filepath.Glob(filepath.Join(r.dir, "out", ".coverage-*"))
	if len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}

func TestOutEmptyDisablesWriting(t *testing.T) {
	es, _ := entries(t)
	har := hartest.WriteHAR(t, t.TempDir(), "t.har", es...)
	t.Chdir(t.TempDir())
	code, _, errs := runCLI(t, "coverage", "--spec", fromPkgDir(vampi), "--har", har, "--identities", fromPkgDir(idsFx), "--out", "")
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, errs)
	}
	if strings.Contains(errs, "wrote ") {
		t.Errorf("unexpected wrote line:\n%s", errs)
	}
	if ents, _ := os.ReadDir("."); len(ents) != 0 {
		t.Errorf("--out \"\" wrote files: %v", ents)
	}
}

// fromPkgDir resolves a package-relative path even after t.Chdir.
func fromPkgDir(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(pkgDir, p)
}

func TestCoverageJSONDeterministic(t *testing.T) {
	es, _ := entries(t)
	a := runCoverageIn(t, vampi, idsFx, es)
	b := runCoverageIn(t, vampi, idsFx, es)
	if a.json != b.json {
		t.Errorf("two runs on identical input differ:\n%s\nvs\n%s", a.json, b.json)
	}
	want := stripOrderDependent(t, a.json)
	for name, v := range map[string][]hartest.Entry{"reversed": reverse(es), "shuffled": shuffled(es)} {
		got := runCoverageIn(t, vampi, idsFx, v)
		if g := stripOrderDependent(t, got.json); g != want {
			t.Errorf("%s HAR order changes coverage.json:\n%s\nwant\n%s", name, g, want)
		}
	}
}

func TestCoverageJSONNoRawSecrets(t *testing.T) {
	es, tk := entries(t)
	r := runCoverageIn(t, vampi, idsFx, es)
	for _, tok := range []string{tk.alice, tk.bob} {
		sig := tok[strings.LastIndex(tok, ".")+1:]
		for _, s := range []string{tok, sig, secret} {
			if strings.Contains(r.json, s) {
				t.Errorf("coverage.json leaks %q", s)
			}
		}
	}
	// Learned object IDs (book titles) appear only as hashes.
	for _, id := range []string{`"a1"`, `"b1"`} {
		if strings.Contains(r.json, id) {
			t.Errorf("coverage.json contains raw object id %s", id)
		}
	}
}

func TestReportMatchesCoverageTable(t *testing.T) {
	tenSpec := writeFile(t, "tenants.yml", tenantsSpec)
	tenIDs := writeFile(t, "ids.yaml", tenantsIDs)
	listIDs := writeFile(t, "ids.yaml", listsIDs)
	vampiEs, _ := entries(t)
	tests := []struct {
		name      string
		spec, ids string
		es        []hartest.Entry
		extra     []string
	}{
		{"vampi", vampi, idsFx, vampiEs, nil},
		{"tenants", tenSpec, tenIDs, tenantsEntries(t), nil},
		{"lists", vampi, listIDs, listsEntries(t), nil},
		{"lists-strict", vampi, listIDs, listsEntries(t), []string{"--strict"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runCoverageIn(t, tc.spec, tc.ids, tc.es, tc.extra...)
			// report reads only coverage.json: remove every other input first.
			for _, f := range []string{"spec.yml", "ids.yaml", "t.har"} {
				if err := os.Remove(f); err != nil {
					t.Fatal(err)
				}
			}
			code, out, errs := runCLI(t, "report", "--in", "out/coverage.json", "--format", "table")
			if code != ExitOK || out != r.stdout {
				t.Fatalf("report table differs (exit %d, stderr %s):\n%s\nwant:\n%s", code, errs, out, r.stdout)
			}
			if code, def, _ := runCLI(t, "report", "--in", "out/coverage.json"); code != ExitOK || def != out {
				t.Errorf("default format is not table")
			}
			code, js, errs := runCLI(t, "report", "--in", "out/coverage.json", "--format", "json")
			if code != ExitOK || js != r.json {
				t.Fatalf("report json differs (exit %d, stderr %s)", code, errs)
			}
		})
	}
}

func TestReportExitCodes(t *testing.T) {
	dir := t.TempDir()
	wrong := filepath.Join(dir, "wrong.json")
	garbage := filepath.Join(dir, "garbage.json")
	for p, c := range map[string]string{wrong: `{"schema":"authzcov.coverage/v9"}`, garbage: "not json"} {
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name    string
		args    []string
		want    int
		wantErr string
	}{
		{"missing --in", []string{"report"}, ExitUsage, "missing --in"},
		{"bad format", []string{"report", "--in", wrong, "--format", "xml"}, ExitUsage, "invalid --format"},
		{"wrong schema", []string{"report", "--in", wrong}, ExitInput, "unsupported coverage.json schema"},
		{"garbage", []string{"report", "--in", garbage}, ExitInput, "invalid coverage.json"},
		{"unreadable", []string{"report", "--in", filepath.Join(dir, "nope.json")}, ExitInput, "nope.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if got := Execute(tt.args, &out, &errb); got != tt.want || !strings.Contains(errb.String(), tt.wantErr) {
				t.Fatalf("exit = %d, stderr=%q; want %d containing %q", got, errb.String(), tt.want, tt.wantErr)
			}
		})
	}
}

func TestExplicitBasePathMode(t *testing.T) {
	es := []hartest.Entry{{Method: "GET", URL: "http://localhost:5000/api/me", Status: 200, Headers: hartest.Bearer(hartest.JWT(t, "alice", nil))}}
	r := runCoverageIn(t, vampi, idsFx, es, "--base-path", "/api")
	if !strings.Contains(r.json, `"mode": "explicit"`) || !strings.Contains(r.json, `"value": "/api"`) {
		t.Errorf("base_path not explicit /api:\n%s", r.json)
	}
}

func shuffled(es []hartest.Entry) []hartest.Entry {
	out := append([]hartest.Entry(nil), es...)
	rng := rand.New(rand.NewSource(42)) //nolint:gosec // fixed seed for a reproducible test shuffle
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}
