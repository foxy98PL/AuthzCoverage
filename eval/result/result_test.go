package result

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func sample() *Result {
	return &Result{
		SchemaVersion: 1, Suite: "t", GeneratedAt: "2026-01-01T00:00:00Z",
		App: App{Name: "a", Version: "1"}, Authzcov: Authzcov{Version: "v1"}, Machine: Machine(),
		Cases: []Case{
			{ID: "b", Kind: "k", Result: TP, Reason: "r", Expected: []Cell{{"GET /x", "other_tenant"}}},
			{ID: "a", Kind: "k", Result: FN, Reason: "r"},
		},
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize(sample().Cases)
	if s.TP != 1 || s.FN != 1 || s.Precision == nil || *s.Precision != 1 || *s.Recall != 0.5 {
		t.Errorf("%+v", s)
	}
	if e := Summarize(nil); e.Precision != nil || e.Recall != nil {
		t.Errorf("undefined must be nil: %+v", e)
	}
	if p := Summarize([]Case{{Result: TP}, {Result: TP}, {Result: FP}}).Precision; *p != 0.667 {
		t.Errorf("rounding: %v", *p)
	}
}

func TestValidate(t *testing.T) {
	r := sample()
	r.Summary = Summarize(r.Cases)
	if err := Validate(r); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Result){
		"version":  func(r *Result) { r.SchemaVersion = 2 },
		"result":   func(r *Result) { r.Cases[0].Result = "maybe" },
		"dup":      func(r *Result) { r.Cases[1].ID = "b" },
		"suite":    func(r *Result) { r.Suite = "" },
		"summary":  func(r *Result) { r.Summary.TP = 9 },
		"time":     func(r *Result) { r.GeneratedAt = "yesterday" },
		"reason":   func(r *Result) { r.Cases[0].Reason = "" },
		"no-cases": func(r *Result) { r.Cases = nil },
	} {
		c := *r
		c.Cases = append([]Case(nil), r.Cases...)
		mut(&c)
		if Validate(&c) == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestWrite(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "0")
	if Now() != "1970-01-01T00:00:00Z" {
		t.Fatalf("Now = %s", Now())
	}
	r := sample()
	r.GeneratedAt = Now()
	r.Summary = Summarize(r.Cases)
	p := filepath.Join(t.TempDir(), "sub", "r.json")
	if err := Write(p, r); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !bytes.HasSuffix(b, []byte("}\n")) || !strings.Contains(string(b), "\n  \"app\"") {
		t.Errorf("format:\n%s", b)
	}
	var back Result
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Cases[0].ID != "a" || back.Cases[0].Expected == nil || !strings.Contains(string(b), `"flagged": []`) {
		t.Errorf("cases not sorted/normalised:\n%s", b)
	}
	if entries, _ := os.ReadDir(filepath.Dir(p)); len(entries) != 1 {
		t.Errorf("temp file left behind: %v", entries)
	}
	bad := sample()
	if Write(filepath.Join(t.TempDir(), "x.json"), bad) == nil {
		t.Error("summary mismatch must not be written")
	}
}

func TestParseVersion(t *testing.T) {
	a := ParseVersion("authzcov v0.1.0-rc.1 (commit db3ddcc)\n")
	if a.Version != "v0.1.0-rc.1" || a.Commit != "db3ddcc" {
		t.Errorf("%+v", a)
	}
}

// required returns the json keys of t's fields that are not omitempty.
func required(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if name, opts, _ := strings.Cut(tag, ","); name != "" && !strings.Contains(opts, "omitempty") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func TestSchemaMatchesStructs(t *testing.T) {
	raw, err := os.ReadFile("../schema/result.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	keys := func(n map[string]any) []string {
		var out []string
		for _, k := range n["required"].([]any) {
			out = append(out, k.(string))
		}
		sort.Strings(out)
		return out
	}
	props := func(n map[string]any, k string) map[string]any {
		return n["properties"].(map[string]any)[k].(map[string]any)
	}
	check := func(name string, node map[string]any, typ reflect.Type) {
		if got, want := keys(node), required(typ); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: schema required %v, struct tags %v", name, got, want)
		}
		for k := range node["properties"].(map[string]any) {
			found := false
			for i := 0; i < typ.NumField(); i++ {
				if n, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ","); n == k {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: schema property %q has no struct field", name, k)
			}
		}
	}
	check("result", schema, reflect.TypeOf(Result{}))
	check("app", props(schema, "app"), reflect.TypeOf(App{}))
	check("authzcov", props(schema, "authzcov"), reflect.TypeOf(Authzcov{}))
	check("machine", props(schema, "machine"), reflect.TypeOf(MachineInfo{}))
	check("summary", props(schema, "summary"), reflect.TypeOf(Summary{}))
	check("case", props(schema, "cases")["items"].(map[string]any), reflect.TypeOf(Case{}))
	check("cell", schema["$defs"].(map[string]any)["cell"].(map[string]any), reflect.TypeOf(Cell{}))
}

// Measurement suites (scaling) have no cases: an empty list is valid, null precision/recall too.
func TestWriteEmptyCases(t *testing.T) {
	r := sample()
	r.Cases = nil
	r.Summary = Summarize(r.Cases)
	p := filepath.Join(t.TempDir(), "m.json")
	if err := Write(p, r); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	for _, want := range []string{`"cases": []`, `"precision": null`, `"recall": null`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
}
