package waivers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authzcov/internal/report/coveragejson"
)

var today = time.Date(2026, 6, 1, 15, 4, 5, 0, time.UTC)

const okItem = `  - endpoint: "GET /products/{productId}"
    relationship: other_tenant
    reason: Catalogue is global, not tenant-scoped
    expires: 2027-03-31
`

func doc(items string) string { return "schema: authzcov.waivers/v1\nwaivers:\n" + items }

func TestParseValid(t *testing.T) {
	ws, err := Parse([]byte(doc(okItem)), "w.yaml", today)
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 1 || ws[0].Endpoint != "GET /products/{productId}" || ws[0].Relationship != "other_tenant" ||
		ws[0].ExpiresText != "2027-03-31" || ws[0].Line != 3 || ws[0].Expires.Hour() != 0 {
		t.Errorf("got %+v", ws)
	}
}

func TestParseBareList(t *testing.T) {
	bare := strings.ReplaceAll(okItem, "  - ", "- ")
	bare = strings.ReplaceAll(bare, "\n    ", "\n  ")
	ws, err := Parse([]byte(bare), "w.yaml", today)
	if err != nil || len(ws) != 1 {
		t.Fatalf("ws=%v err=%v", ws, err)
	}
}

func TestParsePastDateLoads(t *testing.T) {
	y := strings.Replace(okItem, "2027-03-31", "2020-01-01", 1)
	ws, err := Parse([]byte(doc(y)), "w.yaml", today)
	if err != nil || !ws[0].Expired(today) {
		t.Fatalf("ws=%v err=%v", ws, err)
	}
}

func TestParseErrors(t *testing.T) {
	item := func(rel, reason, exp string) string {
		return "  - endpoint: GET /a\n    relationship: " + rel + "\n    reason: " + reason + "\n    expires: " + exp + "\n"
	}
	good := "Catalogue is global"
	cases := []struct{ name, in, want string }{
		{"missing reason", doc("  - endpoint: GET /a\n    relationship: owner\n    expires: 2027-01-01\n"), "w.yaml:3: missing reason"},
		{"short reason", doc(item("owner", "123456789", "2027-01-01")), "w.yaml:5: reason must be 10-500"},
		{"long reason", doc(item("owner", strings.Repeat("x", 501), "2027-01-01")), "reason must be 10-500 characters (got 501)"},
		{"bad date", doc(item("owner", good, "2027-13-01")), "invalid expires"},
		{"not a date", doc(item("owner", good, "soon")), "invalid expires"},
		{"too far", doc(item("owner", good, "2027-06-02")), "more than 365 days"},
		{"unknown key", doc(item("owner", good, "2027-01-01") + "    extra: 1\n"), `unknown key "extra"`},
		{"bad relationship", doc(item("higher_role", good, "2027-01-01")), `invalid relationship "higher_role"`},
		{"duplicate", doc(item("owner", good, "2027-01-01") + item("owner", good, "2027-01-01")), "duplicate waiver"},
		{"anchor", "schema: authzcov.waivers/v1\nwaivers:\n  - &a\n    endpoint: GET /a\n", "anchors and aliases"},
		{"alias", "x: &a 1\ny: *a\n", "anchors and aliases"},
		{"bad schema", "schema: other/v2\nwaivers: []\n", "unsupported schema"},
		{"no schema", "waivers: []\n", "missing schema"},
		{"empty", "", "file is empty"},
		{"unknown top key", "schema: authzcov.waivers/v1\nwaivers: []\nfoo: 1\n", `unknown key "foo"`},
		{"two docs", "- {}\n---\n- {}\n", "multiple yaml documents"},
		{"not yaml", "a: [", "invalid yaml"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.in), "w.yaml", today)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want containing %q", err, c.want)
			}
		})
	}
}

func TestReasonBoundariesAndTrim(t *testing.T) {
	for _, r := range []string{strings.Repeat("é", 10), strings.Repeat("x", 500), "  " + strings.Repeat("x", 10) + "  "} {
		in := "  - endpoint: GET /a\n    relationship: owner\n    reason: \"" + r + "\"\n    expires: 2027-01-01\n"
		if _, err := Parse([]byte(doc(in)), "w.yaml", today); err != nil {
			t.Errorf("reason %q: %v", r, err)
		}
	}
}

func TestExpiryLimitBoundary(t *testing.T) {
	last := today.AddDate(0, 0, 365).Format("2006-01-02")
	in := strings.Replace(okItem, "2027-03-31", last, 1)
	if _, err := Parse([]byte(doc(in)), "w.yaml", today); err != nil {
		t.Errorf("day 365 should load: %v", err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "w.yaml")
	if err := os.WriteFile(p, []byte(doc(okItem)), 0o600); err != nil {
		t.Fatal(err)
	}
	if ws, err := Load(p, today); err != nil || len(ws) != 1 {
		t.Fatalf("ws=%v err=%v", ws, err)
	}
	if _, err := Load(filepath.Join(dir, "nope.yaml"), today); err == nil {
		t.Error("missing file must fail")
	}
	big := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(big, []byte(strings.Repeat("#", MaxSize+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(big, today); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("err = %v", err)
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"GET /a", "GET /a", true},
		{"GET /a", "GET /ab", false},
		{"GET /admin/*", "GET /admin/users/{id}", true},
		{"GET /admin/*", "GET /admin/", true},
		{"GET /admin/*", "GET /admin", false},
		{"* /health", "GET /health", true},
		{"* /health", "POST /health", true},
		{"* /health", "GET /healthz", false},
		{"*", "", true},
		{"*", "anything", true},
		{"", "", true},
		{"", "a", false},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"a**b", "ab", true},
		{"*a", "baba", true},
		{"*ab", "aab", true},
		{"GET /users/{userId}", "GET /users/{userId}", true},
	}
	for _, c := range cases {
		if got := Match(c.pat, c.s); got != c.want {
			t.Errorf("Match(%q,%q) = %v, want %v", c.pat, c.s, got, c.want)
		}
	}
}

func report() *coveragejson.Report {
	cell := func(ep, rel string, covered bool) coveragejson.Cell {
		return coveragejson.Cell{Endpoint: ep, Relationship: rel, Required: true, Covered: covered}
	}
	gap := func(ep, rel string) coveragejson.Finding {
		return coveragejson.Finding{Kind: coveragejson.KindGap, Endpoint: ep, Relationship: rel}
	}
	return &coveragejson.Report{
		Endpoints: []coveragejson.Endpoint{{ID: "GET /a"}, {ID: "GET /admin/x"}},
		Cells: []coveragejson.Cell{
			cell("GET /a", "anonymous", true), cell("GET /a", "owner", false), cell("GET /a", "lower_role", false),
			cell("GET /admin/x", "anonymous", false),
		},
		Findings: []coveragejson.Finding{gap("GET /a", "lower_role"), gap("GET /a", "owner"), gap("GET /admin/x", "anonymous"),
			{Kind: coveragejson.KindUnmatchedRequest, Endpoint: "GET /zzz"}},
		Warnings: []coveragejson.Warning{{Code: "config", Message: "m"}},
		Summary:  coveragejson.Summary{Required: 4, Covered: 1, Gaps: 3, Percent: 25},
	}
}

func w(ep, rel, exp string) Waiver {
	t, _ := time.Parse("2006-01-02", exp)
	return Waiver{Endpoint: ep, Relationship: rel, Reason: "because of reasons", Expires: t, ExpiresText: exp}
}

func cellOf(r *coveragejson.Report, ep, rel string) coveragejson.Cell {
	for _, c := range r.Cells {
		if c.Endpoint == ep && c.Relationship == rel {
			return c
		}
	}
	return coveragejson.Cell{}
}

func TestApplyWaivedAndSummary(t *testing.T) {
	r := report()
	Apply(r, []Waiver{w("GET /a", "owner", "2027-01-01"), w("GET /admin/*", "anonymous", "2027-01-01")}, today)
	c := cellOf(r, "GET /a", "owner")
	if c.Waiver == nil || c.Waiver.Reason != "because of reasons" || c.Waiver.Expires != "2027-01-01" {
		t.Fatalf("waiver = %+v", c.Waiver)
	}
	if cellOf(r, "GET /admin/x", "anonymous").Waiver == nil {
		t.Error("glob waiver not applied")
	}
	if cellOf(r, "GET /a", "lower_role").Waiver != nil {
		t.Error("unwaived cell marked")
	}
	s := r.Summary
	if s.Waived != 2 || s.Gaps != 1 || s.Percent != 50 || s.Required != 4 || s.Covered != 1 {
		t.Errorf("summary = %+v", s)
	}
	if len(r.Findings) != 2 || r.Findings[0].Relationship != "lower_role" || r.Findings[1].Kind != coveragejson.KindUnmatchedRequest {
		t.Errorf("findings = %+v", r.Findings)
	}
	if len(r.Warnings) != 1 {
		t.Errorf("warnings = %+v", r.Warnings)
	}
}

func TestApplyCoveredNeverWaived(t *testing.T) {
	r := report()
	Apply(r, []Waiver{w("GET /a", "anonymous", "2027-01-01")}, today)
	if cellOf(r, "GET /a", "anonymous").Waiver != nil || r.Summary.Waived != 0 || r.Summary.Gaps != 3 {
		t.Errorf("covered cell waived: %+v", r.Summary)
	}
}

func TestApplyExpired(t *testing.T) {
	r := report()
	Apply(r, []Waiver{w("GET /a", "owner", "2026-05-31")}, today)
	if cellOf(r, "GET /a", "owner").Waiver != nil || r.Summary.Waived != 0 || r.Summary.Gaps != 3 {
		t.Errorf("expired waiver applied: %+v", r.Summary)
	}
	if len(r.Findings) != 4 {
		t.Errorf("gap finding must stay: %+v", r.Findings)
	}
	var msg string
	for _, wn := range r.Warnings {
		if wn.Code == WarnExpired {
			msg = wn.Message
		}
	}
	for _, part := range []string{"GET /a", "owner", "2026-05-31"} {
		if !strings.Contains(msg, part) {
			t.Errorf("expired message %q lacks %q", msg, part)
		}
	}
	// Expiring today is still valid.
	r = report()
	Apply(r, []Waiver{w("GET /a", "owner", "2026-06-01")}, today)
	if cellOf(r, "GET /a", "owner").Waiver == nil {
		t.Error("waiver expiring today must still apply")
	}
}

func TestApplyUnusedAndSorted(t *testing.T) {
	r := report()
	Apply(r, []Waiver{w("GET /nope", "owner", "2027-01-01"), w("GET /a", "owner", "2027-01-01")}, today)
	codes := []string{}
	for _, wn := range r.Warnings {
		codes = append(codes, wn.Code)
	}
	if strings.Join(codes, ",") != "config,waiver_unused" {
		t.Errorf("codes = %v", codes)
	}
	if !strings.Contains(r.Warnings[1].Message, "GET /nope") {
		t.Errorf("message = %q", r.Warnings[1].Message)
	}
}

// Review KAN-24 F3: calendar and rune-count boundaries.
func TestLeapDayAndRuneBoundaries(t *testing.T) {
	item := func(reason, exp string) string {
		return "  - endpoint: GET /a\n    relationship: owner\n    reason: \"" + reason + "\"\n    expires: " + exp + "\n"
	}
	ok := "Reason long enough"
	feb := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	if _, err := Parse([]byte(doc(item(ok, "2027-02-29"))), "w.yaml", feb); err == nil {
		t.Error("2027-02-29 should be rejected")
	}
	if _, err := Parse([]byte(doc(item(ok, "2028-02-29"))), "w.yaml", feb); err != nil {
		t.Errorf("2028-02-29 should load: %v", err)
	}
	if _, err := Parse([]byte(doc(item(strings.Repeat("é", 500), "2027-01-01"))), "w.yaml", today); err != nil {
		t.Errorf("500 runes should load: %v", err)
	}
	if _, err := Parse([]byte(doc(item(strings.Repeat("é", 501), "2027-01-01"))), "w.yaml", today); err == nil {
		t.Error("501 runes should be rejected")
	}
	if _, err := Parse([]byte(doc(item("   "+strings.Repeat("x", 9)+"   ", "2027-01-01"))), "w.yaml", today); err == nil {
		t.Error("9 runes after trimming should be rejected")
	}
}

// Review KAN-88 R4: a waiver on a cell never hides a suspicious_allow finding.
func TestApplyKeepsSuspiciousAllow(t *testing.T) {
	r := report()
	r.Findings = append(r.Findings, coveragejson.Finding{Kind: coveragejson.KindSuspiciousAllow, Severity: "warning",
		Endpoint: "GET /a", Relationship: "owner", Message: "bob received 200 for an object owned by alice"})
	r.Summary.SuspiciousAllows = 1
	Apply(r, []Waiver{w("GET /a", "owner", "2027-01-01")}, today)
	n := 0
	for _, f := range r.Findings {
		if f.Kind == coveragejson.KindSuspiciousAllow {
			n++
		}
	}
	if n != 1 || r.Summary.SuspiciousAllows != 1 {
		t.Errorf("suspicious_allow removed by waiver: %d findings, summary %d", n, r.Summary.SuspiciousAllows)
	}
}
