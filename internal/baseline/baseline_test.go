package baseline

import (
	"bytes"
	"io"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"authzcov/internal/report/coveragejson"
)

func cell(ep, rel string, required, covered bool, w *coveragejson.CellWaiver) coveragejson.Cell {
	return coveragejson.Cell{Endpoint: ep, Relationship: rel, Required: required, Covered: covered, Waiver: w}
}

func report() *coveragejson.Report {
	return &coveragejson.Report{
		GeneratedAt: "2026-01-01T00:00:00Z",
		Tool:        coveragejson.Tool{Name: "authzcov", Version: "9.9.9"},
		Inputs:      coveragejson.Inputs{Spec: coveragejson.FileRef{SHA256: "abc"}},
		Cells: []coveragejson.Cell{
			cell("DELETE /users/{userId}", "anonymous", true, true, nil),
			cell("DELETE /users/{userId}", "lower_role", true, false, nil),
			cell("DELETE /users/{userId}", "same_role_other_user", true, false, &coveragejson.CellWaiver{Reason: "r", Expires: "2027-01-01"}),
			cell("DELETE /users/{userId}", "owner", false, true, nil), // observed, not required
		},
	}
}

func TestFromReport(t *testing.T) {
	b := FromReport(report())
	want := map[string]map[string]string{"DELETE /users/{userId}": {"anonymous": "covered", "lower_role": "missing", "same_role_other_user": "waived"}}
	if !reflect.DeepEqual(b.Cells, want) {
		t.Errorf("cells = %v", b.Cells)
	}
	if b.Schema != SchemaV1 || b.SpecSHA256 != "abc" || b.Summary.Required != 3 || b.Summary.Covered != 1 {
		t.Errorf("b = %+v", b)
	}
	if b.Percent() != 50 { // 1 / (3-1)
		t.Errorf("percent = %v", b.Percent())
	}
}

func TestWriteDeterministicNoTimestamps(t *testing.T) {
	var a, c bytes.Buffer
	if err := Write(&a, FromReport(report())); err != nil {
		t.Fatal(err)
	}
	if err := Write(&c, FromReport(report())); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), c.Bytes()) {
		t.Error("rewrite differs")
	}
	s := a.String()
	if !strings.HasSuffix(s, "}\n") || !strings.Contains(s, "\n  \"cells\": {\n    \"DELETE /users/{userId}\": {\n") {
		t.Errorf("format:\n%s", s)
	}
	if regexp.MustCompile(`\d{4}-\d{2}-\d{2}|T\d{2}:|9\.9\.9|version|generated`).MatchString(s) {
		t.Errorf("timestamp/version-like content:\n%s", s)
	}
	b, err := Read(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	var d bytes.Buffer
	_ = Write(&d, b)
	if d.String() != s {
		t.Error("read+write not identity")
	}
}

func TestReadRejects(t *testing.T) {
	for name, in := range map[string]string{
		"schema":   `{"schema":"authzcov.baseline/v2","cells":{}}`,
		"state":    `{"schema":"authzcov.baseline/v1","cells":{"GET /a":{"owner":"maybe"}}}`,
		"trailing": `{"schema":"authzcov.baseline/v1","cells":{}} x`,
		"junk":     `nope`,
	} {
		if _, err := Read(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if b, err := Read(strings.NewReader(`{"schema":"authzcov.baseline/v1"}`)); err != nil || b.Cells == nil {
		t.Errorf("minimal: %v %v", b, err)
	}
}

func bl(cells map[string]map[string]string) *Baseline {
	return &Baseline{Schema: SchemaV1, Cells: cells}
}

func TestCompare(t *testing.T) {
	old := bl(map[string]map[string]string{
		"GET /a":    {"owner": "covered", "anonymous": "missing", "lower_role": "waived", "other_tenant": "covered"},
		"GET /gone": {"owner": "missing"},
	})
	cur := bl(map[string]map[string]string{
		"GET /a":   {"owner": "missing", "anonymous": "covered", "lower_role": "covered", "other_tenant": "waived", "same_role_other_user": "missing"},
		"GET /new": {"owner": "covered", "anonymous": "missing", "lower_role": "waived"},
	})
	rep := &coveragejson.Report{Warnings: []coveragejson.Warning{{Code: "waiver_expired", Message: "waiver X expired"}, {Code: "other", Message: "no"}}}
	d := Compare(old, cur, rep)
	chk := func(name string, got, want any) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	chk("NewEndpoints", d.NewEndpoints, []string{"GET /new"})
	chk("NewGaps", d.NewGaps, []Change{{"GET /a", "same_role_other_user", "", "missing"}, {"GET /new", "anonymous", "", "missing"}})
	chk("Removed", d.Removed, []string{"GET /gone"})
	chk("Regressions", d.Regressions, []Change{{"GET /a", "owner", "covered", "missing"}})
	chk("Improvements", d.Improvements, []Change{{"GET /a", "anonymous", "missing", "covered"}, {"GET /a", "lower_role", "waived", "covered"}})
	chk("Waived", d.Waived, []Change{{"GET /a", "other_tenant", "covered", "waived"}, {"GET /new", "lower_role", "", "waived"}})
	chk("Expired", d.Expired, []string{"waiver X expired"})
	if d.PercentWas != old.Percent() || d.PercentNow != cur.Percent() {
		t.Error("percent mismatch")
	}
}

func TestCompareUnchangedAndNilReport(t *testing.T) {
	b := bl(map[string]map[string]string{"GET /a": {"owner": "covered"}})
	d := Compare(b, b, nil)
	if len(d.NewEndpoints)+len(d.NewGaps)+len(d.Removed)+len(d.Regressions)+len(d.Improvements)+len(d.Waived)+len(d.Expired) != 0 {
		t.Errorf("diff = %+v", d)
	}
	if d.PercentWas != 100 || d.PercentNow != 100 {
		t.Errorf("percents = %v %v", d.PercentWas, d.PercentNow)
	}
}

// zeros yields n spaces (valid JSON whitespace) without allocating them up front.
type spaces struct{ n int }

func (z *spaces) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, io.EOF
	}
	k := min(len(p), z.n)
	for i := range k {
		p[i] = ' '
	}
	z.n -= k
	return k, nil
}

func TestReadSizeCap(t *testing.T) {
	_, err := Read(&spaces{n: MaxSize + 1})
	if err == nil || !strings.Contains(err.Error(), "exceeds the 64 MiB limit") {
		t.Fatalf("err = %v", err)
	}
}
