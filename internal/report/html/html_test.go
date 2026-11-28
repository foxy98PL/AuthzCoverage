package htmlreport

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"authzcov/internal/report/coveragejson"
)

func sample() *coveragejson.Report {
	return &coveragejson.Report{
		Schema: coveragejson.SchemaV1, Tool: coveragejson.Tool{Name: "authzcov", Version: "v1"},
		GeneratedAt: "1970-01-01T00:00:00Z",
		Endpoints: []coveragejson.Endpoint{
			{ID: "GET /a/{id}", Method: "GET", Template: "/a/{id}"},
			{ID: "POST /b", Method: "POST", Template: "/b"},
		},
		Cells: []coveragejson.Cell{
			{Endpoint: "GET /a/{id}", Relationship: "owner", Required: true, Covered: true, MinConfidence: "inferred", Statuses: map[string]int{"200": 2}, Identities: []string{"alice"}},
			{Endpoint: "GET /a/{id}", Relationship: "other_tenant", Required: true},
			{Endpoint: "POST /b", Relationship: "owner", Required: true, Covered: true, MinConfidence: "proven"},
			{Endpoint: "POST /b", Relationship: "anonymous", Required: false, Statuses: map[string]int{"401": 1}},
			{Endpoint: "POST /b", Relationship: "lower_role", Required: true, Waiver: &coveragejson.CellWaiver{Reason: "r"}},
		},
		Findings: []coveragejson.Finding{{Kind: "gap", Severity: "error", Endpoint: "GET /a/{id}", Relationship: "other_tenant", Message: "never"}},
		Summary:  coveragejson.Summary{Required: 4, Covered: 2, Gaps: 2, Percent: 50},
	}
}

func render(t *testing.T, r *coveragejson.Report) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, r); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func b64(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func between(t *testing.T, s, open, closeTag string) string {
	t.Helper()
	if strings.Count(s, open) != 1 || strings.Count(s, closeTag) != 1 {
		t.Fatalf("want exactly one %s ... %s", open, closeTag)
	}
	i := strings.Index(s, open) + len(open)
	return s[i : i+strings.Index(s[i:], closeTag)]
}

func TestCSP(t *testing.T) {
	out := render(t, sample())
	script := between(t, out, "<script>", "</script>")
	style := between(t, out, "<style>", "</style>")
	want := `<meta charset="utf-8">` + "\n" + `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src ` + b64(script) +
		`; style-src ` + b64(style) + `; img-src 'none'; connect-src 'none'; font-src 'none'; base-uri 'none'; form-action 'none'">`
	// html/template escapes ' as &#39; in attributes.
	got := strings.ReplaceAll(out, "&#39;", "'")
	if !strings.Contains(got, "<head>\n"+want) {
		t.Errorf("CSP meta missing or not first after charset; got head:\n%s", got[:min(len(got), 700)])
	}
	if !strings.HasPrefix(out, "<!doctype html>") {
		t.Error("no doctype")
	}
}

func TestNoExternalRequests(t *testing.T) {
	out := render(t, sample())
	for _, bad := range []string{"http://", "https://", " src=", "<link", "url(", "@import", "javascript:", "style=", "<iframe", "<img", "<object"} {
		if strings.Contains(out, bad) {
			t.Errorf("output contains %q", bad)
		}
	}
	if m := regexp.MustCompile(`(?i)\son[a-z]+=`).FindString(out); m != "" {
		t.Errorf("inline handler %q", m)
	}
	if regexp.MustCompile(`(?:src|href)="?//`).MatchString(out) || strings.Contains(out, "href=") {
		t.Error("href/src found")
	}
}

func TestEscaping(t *testing.T) {
	evil := []string{`<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`, `</style>`}
	r := sample()
	for _, e := range evil {
		r.Endpoints = append(r.Endpoints, coveragejson.Endpoint{ID: e, Method: "GET", Template: e})
		r.Cells = append(r.Cells, coveragejson.Cell{Endpoint: e, Relationship: "owner", Required: true, Covered: true, Identities: []string{e}})
		r.Findings = append(r.Findings, coveragejson.Finding{Kind: "gap", Severity: "error", Endpoint: e, Relationship: e, Message: e})
	}
	r.Tool.Version = evil[0]
	out := render(t, r)
	for _, e := range evil[:2] {
		if strings.Contains(out, e) {
			t.Errorf("unescaped %q", e)
		}
	}
	if n := strings.Count(out, "</style>"); n != 1 {
		t.Errorf("</style> count = %d (hostile closer unescaped)", n)
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped form missing")
	}
	if n := strings.Count(out, "<script"); n != 1 {
		t.Errorf("<script count = %d", n)
	}
	if n := strings.Count(out, "<style"); n != 1 {
		t.Errorf("<style count = %d", n)
	}
	if strings.Contains(out, "<img") {
		t.Error("<img in output")
	}
}

func TestFilterStructure(t *testing.T) {
	out := render(t, sample())
	table := out[strings.Index(out, `<table id="matrix">`):strings.Index(out, "</tbody>")]
	thead := table[:strings.Index(table, "</thead>")]
	wantCols := []string{"owner", "lower_role", "other_tenant"}
	var got []string
	for _, m := range regexp.MustCompile(`<th data-rel="([^"]+)"`).FindAllStringSubmatch(thead, -1) {
		got = append(got, m[1])
	}
	if strings.Join(got, ",") != strings.Join(wantCols, ",") {
		t.Errorf("th cols = %v, want %v", got, wantCols)
	}
	var opts []string
	for _, m := range regexp.MustCompile(`<option value="([^"]*)">`).FindAllStringSubmatch(out, -1) {
		if m[1] != "" {
			opts = append(opts, m[1])
		}
	}
	if strings.Join(opts, ",") != strings.Join(wantCols, ",") {
		t.Errorf("options = %v", opts)
	}
	body := table[strings.Index(table, "<tbody>"):]
	rows := strings.Count(body, "<tr ")
	if rows != 2 || strings.Count(body, `data-endpoint="`) != rows {
		t.Errorf("rows = %d", rows)
	}
	tds := strings.Count(body, "<td data-rel=")
	if tds != rows*len(wantCols) {
		t.Errorf("td with data-rel = %d, want %d", tds, rows*len(wantCols))
	}
	if strings.Count(body, "<td") != rows*(len(wantCols)+1) {
		t.Error("td without data-rel besides endpoint label")
	}
	for _, st := range []string{`data-state="covered"`, `data-state="gap"`, `data-state="waived"`, `data-state="na"`} {
		if !strings.Contains(body, st) {
			t.Errorf("missing %s", st)
		}
	}
	if !strings.Contains(body, ">ok~<") || !strings.Contains(body, ">GAP<") {
		t.Error("cell texts missing")
	}
	for _, bad := range []string{"innerHTML", "outerHTML", "eval(", "Function(", "document.write", "insertAdjacentHTML", "setTimeout(\"", "XMLHttpRequest", "fetch("} {
		if strings.Contains(reportJS, bad) {
			t.Errorf("report.js contains %s", bad)
		}
	}
	if len(reportJS) > 8192 || len(reportCSS) > 8192 {
		t.Error("js/css too large")
	}
}

func TestDeterministic(t *testing.T) {
	r := sample()
	a := render(t, r)
	if b := render(t, r); a != b {
		t.Error("not deterministic")
	}
}

func TestBigReportSize(t *testing.T) {
	r := &coveragejson.Report{Schema: coveragejson.SchemaV1, Tool: coveragejson.Tool{Version: "v0.1.0"}}
	rels := []string{"owner", "same_role_other_user", "lower_role", "higher_role", "other_tenant", "anonymous", "unknown"}
	for i := 0; i < 300; i++ {
		id := fmt.Sprintf("GET /api/v1/orgs/{orgId}/items/res%03d", i)
		r.Endpoints = append(r.Endpoints, coveragejson.Endpoint{ID: id, Method: "GET", Template: id[4:]})
		for j, rel := range rels {
			c := coveragejson.Cell{Endpoint: id, Relationship: rel, Required: true, Covered: j%2 == 0,
				Statuses: map[string]int{"200": 3}, Identities: []string{"alice-admin", "bob-member"}, Evidence: []string{"e1", "e2"}}
			r.Cells = append(r.Cells, c)
		}
	}
	for i := 0; i < 3000; i++ {
		ep := r.Endpoints[i%300].ID
		r.Findings = append(r.Findings, coveragejson.Finding{Fingerprint: "0123456789abcdef", Kind: "gap", Severity: "error",
			Endpoint: ep, Relationship: rels[i%7], Message: ep + " was never called as " + rels[i%7]})
	}
	out := render(t, r)
	t.Logf("size = %d bytes (matrix %d, findings %d)", len(out), strings.Index(out, "<h2>")-strings.Index(out, "<table"), strings.Index(out, "<footer")-strings.Index(out, "<h2>"))
	if len(out) >= 500*1024 {
		t.Errorf("output %d bytes, want < 512000", len(out))
	}
}

func TestSuspiciousAllowShown(t *testing.T) {
	r := sample()
	r.Findings = append(r.Findings, coveragejson.Finding{Kind: "suspicious_allow", Severity: "warning", Endpoint: "GET /a/{id}", Relationship: "same_role_other_user", Message: "bob received 200 for an object owned by alice"})
	r.Summary.SuspiciousAllows = 1
	if out := render(t, r); !strings.Contains(out, "suspicious_allow") || !strings.Contains(out, "bob received 200") {
		t.Error("html lacks suspicious_allow finding")
	}
}

// TestJSContract ties report.js to the markup it filters: every id, attribute
// and selector the script reads must exist in the rendered page, so a typo on
// either side fails here (no JS engine is available in the test environment).
func TestJSContract(t *testing.T) {
	out := render(t, sample())
	for _, m := range regexp.MustCompile(`getElementById\("([^"]+)"\)`).FindAllStringSubmatch(reportJS, -1) {
		if !strings.Contains(out, `id="`+m[1]+`"`) {
			t.Errorf("report.js reads #%s, absent from the page", m[1])
		}
	}
	for _, m := range regexp.MustCompile(`getAttribute\("([^"]+)"\)`).FindAllStringSubmatch(reportJS, -1) {
		if !strings.Contains(out, m[1]+`="`) {
			t.Errorf("report.js reads attribute %s, absent from the page", m[1])
		}
	}
	for _, m := range regexp.MustCompile(`td\[(data-[a-z]+)="([^"]+)"\]`).FindAllStringSubmatch(reportJS, -1) {
		if !strings.Contains(out, m[1]+`="`+m[2]+`"`) {
			t.Errorf("report.js selects %s=%s, absent from the page", m[1], m[2])
		}
	}
	if !strings.Contains(reportJS, `"hidden"`) || !strings.Contains(reportCSS, ".hidden") {
		t.Error("report.js toggles class hidden but report.css has no .hidden rule")
	}
}
