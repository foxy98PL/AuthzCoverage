package markdown

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"authzcov/internal/report/coveragejson"
)

func render(t *testing.T, r *coveragejson.Report) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, r); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func gapReport(n int, endpoint func(i int) string) *coveragejson.Report {
	r := &coveragejson.Report{Schema: coveragejson.SchemaV1, Tool: coveragejson.Tool{Name: "authzcov", Version: "dev"}}
	rels := []string{"owner", "same_role_other_user", "lower_role", "anonymous", "other_tenant"}
	for i := 0; i < n; i++ {
		r.Findings = append(r.Findings, coveragejson.Finding{
			Kind: "gap", Endpoint: endpoint(i), Relationship: rels[i%len(rels)], Message: "m",
		})
	}
	r.Summary = coveragejson.Summary{Required: n + 5, Covered: 5, Percent: 100 * 5 / float64(n+5), Gaps: n}
	return r
}

func TestEscape(t *testing.T) {
	tests := []struct{ in, want string }{
		{`a\b`, `a\\b`},
		{`a|b`, `a\|b`},
		{"a`b", "a\\`b"},
		{"a*b", `a\*b`}, {"a_b", `a\_b`}, {"a~b", `a\~b`},
		{"a[b]", `a\[b\]`}, {"a(b)", `a\(b\)`}, {"#a", `\#a`}, {"a!", `a\!`},
		{"a&b", "a&amp;b"}, {"<b>", "&lt;b&gt;"}, {"</details>", "&lt;/details&gt;"},
		{"@team", "&#64;team"},
		{"http://x", `http&#58;//x`},
		{"a\r\nb\tc", "a  b c"},
		{"a\x00b", "ab"},
		{"a\x1bb", "a b"},
		{"www.evil.com", `www\.evil\.com`},
		{"a\u202eb\u200bc", "abc"},
		{"  pad  ", "pad"},
		{`\|`, `\\\|`},
		{"GET /books/v1/{id}", "GET /books/v1/{id}"},
	}
	for _, tc := range tests {
		if got := Escape(tc.in); got != tc.want {
			t.Errorf("Escape(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTopGapsAndDetails(t *testing.T) {
	out := render(t, gapReport(50, func(i int) string { return fmt.Sprintf("GET /e%02d", i) }))
	top, rest, ok := strings.Cut(out, "<details>")
	if !ok {
		t.Fatal("no details block")
	}
	if n := strings.Count(top, "| GET /e"); n != TopGaps {
		t.Errorf("top rows = %d, want %d", n, TopGaps)
	}
	if !strings.Contains(rest, "<summary>30 more gaps</summary>") {
		t.Errorf("summary missing:\n%s", rest)
	}
	if n := strings.Count(rest, "| GET /e"); n != 30 {
		t.Errorf("details rows = %d, want 30", n)
	}
	if !strings.Contains(out, "</details>") {
		t.Error("details not closed")
	}
	// <= TopGaps: no details.
	if strings.Contains(render(t, gapReport(20, func(i int) string { return fmt.Sprintf("GET /e%02d", i) })), "<details>") {
		t.Error("details block with 20 gaps")
	}
}

func TestFirstLine(t *testing.T) {
	ep := func(i int) string { return fmt.Sprintf("GET /e%d", i) }
	tests := []struct {
		name, want string
		r          *coveragejson.Report
	}{
		{"zero", "**authzcov:** 0 of 0 required authorization checks covered (0.0%), 0 gaps.", gapReport(0, ep)},
		{"one", "1 gap.", gapReport(1, ep)},
		{"many", " gaps.", gapReport(7, ep)},
	}
	tests[0].r.Summary = coveragejson.Summary{}
	for _, tc := range tests {
		out := render(t, tc.r)
		first, _, _ := strings.Cut(out, "\n")
		if !strings.HasPrefix(first, "**authzcov:** ") || !strings.Contains(first, " of ") || !strings.HasSuffix(first, tc.want) {
			t.Errorf("%s: first line %q", tc.name, first)
		}
		if strings.Count(first, ". ") != 0 || !strings.HasSuffix(first, ".") {
			t.Errorf("%s: not one sentence: %q", tc.name, first)
		}
	}
	if out := render(t, gapReport(0, ep)); !strings.Contains(out, "No gaps.") || strings.Contains(out, "Top gaps") {
		t.Errorf("no-gap output wrong:\n%s", out)
	}
	if out := render(t, gapReport(1, ep)); !strings.Contains(out, "5 of 6 required") {
		t.Errorf("counts missing: %s", out)
	}
}

func TestDeterministic(t *testing.T) {
	r := gapReport(45, func(i int) string { return fmt.Sprintf("GET /e%02d", i%9) })
	r.Findings = append(r.Findings, coveragejson.Finding{Kind: "unmatched_request", Endpoint: "GET /x", Message: "y"})
	want := render(t, r)
	rng := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic shuffle in a test
	for i := 0; i < 5; i++ {
		rng.Shuffle(len(r.Findings), func(a, b int) { r.Findings[a], r.Findings[b] = r.Findings[b], r.Findings[a] })
		if got := render(t, r); got != want {
			t.Fatal("output depends on finding order")
		}
	}
	if !strings.Contains(want, "Other findings (1)") {
		t.Error("other findings missing")
	}
}

func TestRiskOrder(t *testing.T) {
	r := gapReport(0, nil)
	for _, rel := range []string{"owner", "other_tenant", "anonymous"} {
		r.Findings = append(r.Findings, coveragejson.Finding{Kind: "gap", Endpoint: "GET /a", Relationship: rel})
	}
	out := render(t, r)
	i1, i2, i3 := strings.Index(out, "another tenant"), strings.Index(out, "anonymous caller"), strings.Index(out, "the owner")
	if i1 >= i2 || i2 >= i3 {
		t.Errorf("order wrong:\n%s", out)
	}
}

func TestTruncation(t *testing.T) {
	r := gapReport(5000, func(i int) string { return fmt.Sprintf("GET /%s/%d", strings.Repeat("segment/", 20), i) })
	r.Findings = append(r.Findings, coveragejson.Finding{Kind: "ambiguous_match", Endpoint: "GET /z", Message: "m"})
	out := render(t, r)
	if len(out) > MaxBytes {
		t.Fatalf("len = %d > %d", len(out), MaxBytes)
	}
	if strings.Count(out, "<details>") != strings.Count(out, "</details>") {
		t.Error("unbalanced details")
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "_Output truncated: ") || !strings.HasSuffix(last, "rows omitted; see coverage.json._") {
		t.Errorf("last line %q", last)
	}
	if !strings.Contains(out, "</details>") {
		t.Error("details not closed")
	}
}

// Review F1: escapes grow '@' to 5 bytes and the top-20 rows are never
// dropped, so hostile wide cells must still fit under MaxBytes.
func TestTruncationWideEscapedCells(t *testing.T) {
	wide := strings.Repeat("@", 300)
	r := gapReport(5000, func(i int) string { return fmt.Sprintf("GET /%s|%d", wide, i) })
	for i := range r.Findings {
		if i%2 == 0 {
			r.Findings[i].Relationship = wide
		}
	}
	r.Findings = append(r.Findings, coveragejson.Finding{Kind: "ambiguous_match", Endpoint: "GET /" + wide, Message: wide})
	out := render(t, r)
	if len(out) > MaxBytes {
		t.Fatalf("len = %d > %d", len(out), MaxBytes)
	}
	if strings.Count(out, "<details>") != strings.Count(out, "</details>") {
		t.Error("unbalanced details")
	}
	if strings.Contains(out, "@") {
		t.Error("raw @ in output")
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "| GET") && unescapedPipes(line) != 3 {
			t.Fatalf("row breaks the 2-column table: %q", line)
		}
	}
}

func TestCellByteCapKeepsEscapesWhole(t *testing.T) {
	for _, s := range []string{strings.Repeat("@", 300), strings.Repeat(`\|`, 200), strings.Repeat("&", 300)} {
		c := cell(s)
		if len(c) > maxCellBytes {
			t.Errorf("cell len %d > %d", len(c), maxCellBytes)
		}
		if !strings.HasSuffix(c, `\.\.\.`) {
			t.Errorf("truncated cell should end with escaped ellipsis: %q", c[len(c)-12:])
		}
		if unescapedPipes(c) != 0 {
			t.Errorf("cell has an unescaped pipe")
		}
	}
}

func TestUnknownRelationshipLabel(t *testing.T) {
	if got := relLabel("<script>"); got != "unknown" {
		t.Errorf("relLabel = %q", got)
	}
}

func unescapedPipes(row string) int {
	n := 0
	for i := 0; i < len(row); i++ {
		switch row[i] {
		case '\\':
			i++
		case '|':
			n++
		}
	}
	return n
}

func TestHostileEndpoint(t *testing.T) {
	ep := "GET /a|b/`x`/<script>/[l](http://e)/@team"
	r := gapReport(30, func(int) string { return ep })
	r.Findings = append(r.Findings, coveragejson.Finding{Kind: "suspicious_allow", Endpoint: ep, Message: "</details> @team | [x](javascript:1)"})
	out := render(t, r)
	for _, bad := range []string{"<script", "@team", "](", "http://", "javascript:", "`x`"} {
		if strings.Contains(out, bad) {
			t.Errorf("output contains %q:\n%s", bad, out)
		}
	}
	if strings.Count(out, "</details>") != 1 {
		t.Errorf("injected </details>:\n%s", out)
	}
	rows, want := 0, 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "| ") {
			want = 0 // table ended
			continue
		}
		if want == 0 { // header row fixes the column count
			want = unescapedPipes(line)
		}
		rows++
		if got := unescapedPipes(line); got != want {
			t.Errorf("row %q has %d unescaped pipes, want %d", line, got, want)
		}
	}
	if rows == 0 {
		t.Fatal("no rows")
	}
}

func TestSuspiciousAllowsSection(t *testing.T) {
	r := gapReport(2, func(i int) string { return fmt.Sprintf("GET /g%d", i) })
	r.Findings = append(r.Findings,
		coveragejson.Finding{Kind: "suspicious_allow", Endpoint: "GET /books/{id}", Relationship: "same_role_other_user", Message: "bob received 200 for an object owned by alice"},
		coveragejson.Finding{Kind: "unmatched_request", Endpoint: "GET /x", Message: "other"})
	out := render(t, r)
	first, _, _ := strings.Cut(out, "\n")
	if !strings.HasSuffix(first, "2 gaps, 1 suspicious allow.") {
		t.Errorf("first line = %q", first)
	}
	i, j := strings.Index(out, "### Suspicious allows"), strings.Index(out, "### Top gaps")
	if i < 0 || j < 0 || i > j {
		t.Fatalf("section order wrong:\n%s", out)
	}
	if !strings.Contains(out, "| Endpoint | Relationship | What happened |") ||
		!strings.Contains(out, "| GET /books/\\{id}") && !strings.Contains(out, "another user with the same role | bob received 200") {
		t.Errorf("table missing:\n%s", out)
	}
	if strings.Contains(out[strings.Index(out, "<details>"):], "suspicious_allow") {
		t.Errorf("suspicious allow repeated under other findings:\n%s", out)
	}
	if !strings.Contains(out, "Other findings (1)") {
		t.Errorf("other findings count:\n%s", out)
	}
	clean := render(t, gapReport(2, func(i int) string { return fmt.Sprintf("GET /g%d", i) }))
	if strings.Contains(clean, "suspicious") {
		t.Error("no section without findings")
	}
}

func TestManySuspiciousAllowsStayBounded(t *testing.T) {
	r := gapReport(0, nil)
	for i := 0; i < 500; i++ {
		r.Findings = append(r.Findings, coveragejson.Finding{Kind: "suspicious_allow", Endpoint: fmt.Sprintf("GET /e%d", i),
			Relationship: "other_tenant", Message: strings.Repeat("m", 400)})
	}
	out := render(t, r)
	if len(out) > MaxBytes || !strings.Contains(out, "500 suspicious allows.") {
		t.Errorf("len %d", len(out))
	}
}
