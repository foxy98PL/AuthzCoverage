// Package htmlreport renders a coverage.json report as one self-contained HTML
// page: no external requests, one hashed inline script and one hashed inline
// style, and a Content-Security-Policy meta tag that allows nothing else.
//
// All report strings are plain html/template data and are escaped by it; the
// only template.JS and template.CSS values are the constant embedded files.
package htmlreport

import (
	"crypto/sha256"
	_ "embed" // report.js, report.css and the template are embedded
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strconv"
	"strings"

	"authzcov/internal/model"
	"authzcov/internal/report/coveragejson"
)

//go:embed report.js
var reportJS string

//go:embed report.css
var reportCSS string

//go:embed report.html.tmpl
var pageTmpl string

var (
	tmpl = template.Must(template.New("report").Parse(pageTmpl))
	csp  = buildCSP()
)

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func buildCSP() string {
	return "default-src 'none'; script-src " + hash(reportJS) + "; style-src " + hash(reportCSS) +
		"; img-src 'none'; connect-src 'none'; font-src 'none'; base-uri 'none'; form-action 'none'"
}

type cellView struct {
	Rel, State, Title, Text string
}

type findingView struct {
	Kind, Severity, Endpoint, Relationship, Message string
}

type rowView struct {
	ID, Label string
	Cells     []cellView
}

type pageView struct {
	CSP                          string
	JS                           template.JS
	CSS                          template.CSS
	Cols                         []string
	Rows                         []rowView
	Findings                     []findingView
	Covered, Required, Waived    int
	Gaps                         int
	Percent                      string
	GeneratedAt, Version, Schema string
}

// Render writes the report as an HTML page. Output depends only on r.
func Render(w io.Writer, r *coveragejson.Report) error {
	if r == nil {
		r = &coveragejson.Report{}
	}
	type key struct{ ep, rel string }
	cells := map[key]*coveragejson.Cell{}
	required := map[string]bool{}
	for i := range r.Cells {
		c := &r.Cells[i]
		cells[key{c.Endpoint, c.Relationship}] = c
		if c.Required {
			required[c.Relationship] = true
		}
	}
	var cols []string
	for _, rel := range model.Relationships() {
		if required[string(rel)] {
			cols = append(cols, string(rel))
		}
	}
	rows := make([]rowView, 0, len(r.Endpoints))
	for _, e := range r.Endpoints {
		row := rowView{ID: e.ID, Label: e.Method + " " + e.Template}
		for _, rel := range cols {
			row.Cells = append(row.Cells, cellFor(cells[key{e.ID, rel}], rel))
		}
		rows = append(rows, row)
	}
	s := r.Summary
	v := pageView{
		CSP: csp, JS: template.JS(reportJS), CSS: template.CSS(reportCSS), //nolint:gosec // constant embedded files only
		Cols: cols, Rows: rows, Findings: findings(r.Findings),
		Covered: s.Covered, Required: s.Required, Waived: s.Waived, Gaps: s.Gaps,
		Percent:     strconv.FormatFloat(s.Percent, 'f', 1, 64),
		GeneratedAt: r.GeneratedAt, Version: r.Tool.Version, Schema: r.Schema,
	}
	return tmpl.Execute(w, v)
}

// findings drops the endpoint from the start of a message: the endpoint has
// its own column, and repeating it thousands of times dominates the file size.
func findings(fs []coveragejson.Finding) []findingView {
	out := make([]findingView, len(fs))
	for i, f := range fs {
		msg := strings.TrimPrefix(f.Message, f.Endpoint+" ")
		if msg == "was never called as "+f.Relationship {
			msg = "-" // fully implied by kind, endpoint and relationship
		}
		out[i] = findingView{f.Kind, f.Severity, f.Endpoint, f.Relationship, msg}
	}
	return out
}

func cellFor(c *coveragejson.Cell, rel string) cellView {
	if c == nil {
		return cellView{Rel: rel, State: "na", Text: "-"}
	}
	v := cellView{Rel: rel}
	switch {
	case !c.Required:
		v.State, v.Text = "observed", "-"
	case c.Covered:
		v.State, v.Text = "covered", "ok"
		if c.MinConfidence == model.ConfInferred.String() {
			v.Text = "ok~"
		}
	case c.Waiver != nil:
		v.State, v.Text = "waived", "waived"
	default:
		v.State, v.Text = "gap", "GAP"
	}
	var parts []string
	if len(c.Statuses) > 0 {
		keys := make([]string, 0, len(c.Statuses))
		for k := range c.Statuses {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ss := make([]string, len(keys))
		for i, k := range keys {
			ss[i] = fmt.Sprintf("%sx%d", k, c.Statuses[k])
		}
		parts = append(parts, strings.Join(ss, ","))
	}
	// Identities of an uncovered cell only made weak evidence; leaving them out
	// of the title keeps large reports small. They stay in coverage.json.
	if ids := c.Identities; len(ids) > 0 && v.State != "gap" {
		parts = append(parts, strings.Join(ids, ","))
	}
	if c.Waiver != nil {
		parts = append(parts, "waiver "+c.Waiver.Reason)
	}
	v.Title = strings.Join(parts, " ")
	return v
}
