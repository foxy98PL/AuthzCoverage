package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"authzcov/internal/testutil/hartest"
)

func TestSuspiciousAllowEndToEnd(t *testing.T) {
	a := hartest.Bearer(hartest.JWT(t, "alice", nil))
	b := hartest.Bearer(hartest.JWT(t, "bob", nil))
	es := []hartest.Entry{
		{Method: "POST", URL: base + "/books/v1", Status: 200, Headers: a, ReqJSON: `{"book_title":"a1","secret":"x"}`},
		{Method: "GET", URL: base + "/books/v1/a1", Status: 200, Headers: a, RespJSON: `{"book_title":"a1"}`},
		{Method: "GET", URL: base + "/books/v1/a1", Status: 200, Headers: b, RespJSON: `{"book_title":"a1","secret":"x"}`},
		{Method: "GET", URL: base + "/users/v1/alice", Status: 200, Headers: b, RespJSON: `{}`}, // empty body: no finding
	}
	r := runCoverageIn(t, vampi, idsFx, es)
	var rep struct {
		Findings []struct {
			Fingerprint, Kind, Severity, Endpoint, Relationship, Message string
			Evidence                                                     []string
		}
		Summary struct {
			SuspiciousAllows int `json:"suspicious_allows"`
		}
	}
	if err := json.Unmarshal([]byte(r.json), &rep); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range rep.Findings {
		if f.Kind != "suspicious_allow" {
			continue
		}
		n++
		if f.Endpoint != "GET /books/v1/{book_title}" || f.Relationship != "same_role_other_user" ||
			f.Message != "bob received 200 for an object owned by alice" || f.Severity != "warning" ||
			len(f.Evidence) != 1 || !strings.HasPrefix(f.Evidence[0], "t.har#") || f.Fingerprint == "" {
			t.Errorf("finding = %+v", f)
		}
	}
	if n != 1 || rep.Summary.SuspiciousAllows != 1 {
		t.Fatalf("findings %d, summary %d\n%s", n, rep.Summary.SuspiciousAllows, r.json)
	}
	const footer = "! 1 suspicious allow(s): run \"authzcov report --format markdown\" for details\n"
	if !strings.Contains(r.stdout, footer) {
		t.Errorf("coverage table lacks footer:\n%s", r.stdout)
	}
	code, out, errs := runCLI(t, "report", "--in", "out/coverage.json")
	if code != ExitOK || !strings.Contains(out, footer) {
		t.Errorf("report table: exit %d, stderr %s\n%s", code, errs, out)
	}
	code, md, errs := runCLI(t, "report", "--in", "out/coverage.json", "--format", "markdown")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, want := range []string{"### Suspicious allows", "bob received 200 for an object owned by alice", ", 1 suspicious allow."} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
	if strings.Index(md, "### Suspicious allows") > strings.Index(md, "### Top gaps") {
		t.Errorf("suspicious section must precede top gaps")
	}
	for _, f := range []string{"sarif", "html"} {
		code, o, errs := runCLI(t, "report", "--in", "out/coverage.json", "--format", f)
		if code != ExitOK || !strings.Contains(o, "suspicious_allow") {
			t.Errorf("%s: exit %d %s", f, code, errs)
		}
	}
}

func TestNoSuspiciousFooterWhenClean(t *testing.T) {
	es, _ := entries(t)
	r := runCoverageIn(t, vampi, idsFx, es)
	if strings.Contains(r.stdout, "suspicious") || strings.Contains(r.json, `"suspicious_allows": 0`) == false {
		t.Errorf("unexpected suspicious output:\n%s", r.stdout)
	}
}
