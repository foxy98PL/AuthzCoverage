// Package markdown renders a coverage.json report as GitHub-flavoured Markdown
// sized for a pull-request comment. Every string that came from a spec, a HAR
// or the report goes through Escape, so a hostile path cannot break a table,
// inject HTML or links, or ping users. The output carries no timestamp, so
// re-posting an unchanged result yields an identical comment.
package markdown

import (
	"bytes"
	"cmp"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"authzcov/internal/report/coveragejson"
)

const (
	// MaxBytes caps the output; GitHub rejects comments over 65536 characters.
	MaxBytes = 60000
	// TopGaps is how many gaps are listed before the rest go into <details>.
	TopGaps = 20

	maxCellRunes = 300
	// maxCellBytes caps a cell after escaping (escapes can grow a rune to 5
	// bytes), so the top-gaps table alone always fits: 20 rows x 2 cells x 1000.
	maxCellBytes = 1000
)

// relRisk orders relationships from riskiest to least risky.
var relRisk = []string{"other_tenant", "same_role_other_user", "lower_role", "anonymous", "owner", "higher_role", "unknown"}

var relText = map[string]string{
	"owner":                "the owner",
	"same_role_other_user": "another user with the same role",
	"lower_role":           "a lower role",
	"higher_role":          "a higher role",
	"other_tenant":         "a user from another tenant",
	"anonymous":            "an anonymous caller",
	"unknown":              "unknown",
}

// Escape makes s safe inside a GFM table cell or inline text: no raw HTML, no
// links or autolinks, no mentions, no emphasis, no line breaks.
func Escape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == 0 || r == utf8.RuneError:
			if r == utf8.RuneError {
				b.WriteRune(r)
			}
		case r == '&':
			b.WriteString("&amp;")
		case r == '<':
			b.WriteString("&lt;")
		case r == '>':
			b.WriteString("&gt;")
		case r == '@':
			b.WriteString("&#64;")
		case r == ':':
			b.WriteString("&#58;")
		// '.' is escaped so GitHub's extended autolinks (www.example.com) do not fire.
		case strings.ContainsRune("\\|`*_~[]()#!.", r):
			b.WriteByte('\\')
			b.WriteRune(r)
		case unicode.IsControl(r):
			b.WriteByte(' ')
		case unicode.Is(unicode.Cf, r):
			// Format chars (bidi overrides, zero-width joiners) can disguise a path; drop them.
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// cell escapes s after bounding its length in runes and, after escaping, in
// bytes. It trims raw runes, never escaped output, so an escape sequence is
// never cut in half (a dangling backslash could swallow the cell's pipe).
func cell(s string) string {
	rs := []rune(s)
	if len(rs) > maxCellRunes {
		rs = rs[:maxCellRunes]
		s = string(rs) + "..."
	}
	out := Escape(s)
	for n := len(rs); len(out) > maxCellBytes && n > 0; {
		n = min(n-1, n*maxCellBytes/len(out))
		out = Escape(string(rs[:n]) + "...")
	}
	return out
}

func relLabel(rel string) string {
	if t, ok := relText[rel]; ok {
		return t
	}
	// Anything outside the known set (empty or hostile) is shown as unknown.
	return relText["unknown"]
}

func riskIndex(rel string) int {
	if i := slices.Index(relRisk, rel); i >= 0 {
		return i
	}
	return len(relRisk)
}

// Render writes the Markdown report. The whole document is built in memory
// and written once; it never exceeds MaxBytes.
func Render(w io.Writer, r *coveragejson.Report) error {
	if r == nil {
		return fmt.Errorf("markdown: nil report")
	}
	var gaps, others, allows []coveragejson.Finding
	for _, f := range r.Findings {
		switch f.Kind {
		case coveragejson.KindGap:
			gaps = append(gaps, f)
		case coveragejson.KindSuspiciousAllow:
			allows = append(allows, f)
		default:
			others = append(others, f)
		}
	}
	sort.SliceStable(gaps, func(i, j int) bool {
		a, b := gaps[i], gaps[j]
		return cmp.Or(cmp.Compare(riskIndex(a.Relationship), riskIndex(b.Relationship)),
			cmp.Compare(a.Endpoint, b.Endpoint), cmp.Compare(a.Relationship, b.Relationship),
			cmp.Compare(a.Message, b.Message)) < 0
	})
	kindIdx := func(k string) int {
		if i := slices.Index([]string{coveragejson.KindSuspiciousAllow, coveragejson.KindUnmatchedRequest, coveragejson.KindAmbiguousMatch, coveragejson.KindUndocumentedMeth}, k); i >= 0 {
			return i
		}
		return 99
	}
	sort.SliceStable(others, func(i, j int) bool {
		a, b := others[i], others[j]
		return cmp.Or(cmp.Compare(kindIdx(a.Kind), kindIdx(b.Kind)), cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.Endpoint, b.Endpoint), cmp.Compare(a.Relationship, b.Relationship),
			cmp.Compare(a.Message, b.Message)) < 0
	})

	sort.SliceStable(allows, func(i, j int) bool {
		a, b := allows[i], allows[j]
		return cmp.Or(cmp.Compare(riskIndex(a.Relationship), riskIndex(b.Relationship)),
			cmp.Compare(a.Endpoint, b.Endpoint), cmp.Compare(a.Message, b.Message)) < 0
	})
	nAllows := len(allows)
	if len(allows) > TopGaps { // the rest are listed with the other findings, which can be truncated
		others = append(slices.Clone(allows[TopGaps:]), others...)
		allows = allows[:TopGaps]
	}
	top := gaps
	var rest []coveragejson.Finding
	if len(gaps) > TopGaps {
		top, rest = gaps[:TopGaps], gaps[TopGaps:]
	}
	total := len(rest) + len(others)

	// Binary search the fewest omitted trailing detail rows that fit.
	lo, hi := 0, total
	for lo < hi {
		mid := (lo + hi) / 2
		if len(build(r, len(gaps), nAllows, allows, top, rest, others, mid)) <= MaxBytes {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	out := build(r, len(gaps), nAllows, allows, top, rest, others, lo)
	if len(out) > MaxBytes {
		return fmt.Errorf("markdown: report needs %d bytes, over the %d-byte limit", len(out), MaxBytes)
	}
	_, err := w.Write(out)
	return err
}

func build(r *coveragejson.Report, nGaps, nAllows int, allows, top, rest, others []coveragejson.Finding, omit int) []byte {
	keepOthers := len(others)
	keepRest := len(rest)
	for n := omit; n > 0; n-- {
		if keepOthers > 0 {
			keepOthers--
		} else {
			keepRest--
		}
	}
	var b bytes.Buffer
	s := r.Summary
	plural := "s"
	if nGaps == 1 {
		plural = ""
	}
	susp := ""
	if n := nAllows; n > 0 {
		sp := "s"
		if n == 1 {
			sp = ""
		}
		susp = fmt.Sprintf(", %d suspicious allow%s", n, sp)
	}
	fmt.Fprintf(&b, "**authzcov:** %d of %d required authorization checks covered (%.1f%%), %d gap%s%s.\n\n",
		s.Covered, s.Required, s.Percent, nGaps, plural, susp)
	b.WriteString("| Required | Covered | Waived | Gaps | Unmatched requests | Ambiguous matches |\n")
	b.WriteString("| ---: | ---: | ---: | ---: | ---: | ---: |\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d | %d | %d |\n\n", s.Required, s.Covered, s.Waived, nGaps, s.UnmatchedReqs, s.AmbiguousMatches)

	if len(allows) > 0 {
		b.WriteString("### Suspicious allows\n\n| Endpoint | Relationship | What happened |\n| --- | --- | --- |\n")
		for _, f := range allows {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", cell(f.Endpoint), relLabel(f.Relationship), cell(f.Message))
		}
		b.WriteString("\n")
	}
	if nGaps == 0 {
		b.WriteString("No gaps.\n\n")
	} else {
		b.WriteString("### Top gaps\n\n")
		gapTable(&b, top)
		b.WriteString("\n")
	}
	if keepRest > 0 {
		fmt.Fprintf(&b, "<details>\n<summary>%d more gap%s</summary>\n\n", len(rest), map[bool]string{true: "", false: "s"}[len(rest) == 1])
		gapTable(&b, rest[:keepRest])
		b.WriteString("\n</details>\n\n")
	}
	if keepOthers > 0 {
		fmt.Fprintf(&b, "<details>\n<summary>Other findings (%d)</summary>\n\n", len(others))
		b.WriteString("| Kind | Endpoint | Message |\n| --- | --- | --- |\n")
		for _, f := range others[:keepOthers] {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", cell(f.Kind), cell(f.Endpoint), cell(f.Message))
		}
		b.WriteString("\n</details>\n\n")
	}
	fmt.Fprintf(&b, "<sub>%s %s · %s</sub>\n", cell(r.Tool.Name), cell(r.Tool.Version), cell(r.Schema))
	if omit > 0 {
		fmt.Fprintf(&b, "\n_Output truncated: %d rows omitted; see coverage.json._\n", omit)
	}
	return b.Bytes()
}

func gapTable(b *bytes.Buffer, fs []coveragejson.Finding) {
	b.WriteString("| Endpoint | Missing test |\n| --- | --- |\n")
	for _, f := range fs {
		fmt.Fprintf(b, "| %s | %s |\n", cell(f.Endpoint), relLabel(f.Relationship))
	}
}
