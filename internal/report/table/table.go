// Package table renders the coverage matrix as a plain text table.
package table

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"authzcov/internal/matrix"
	"authzcov/internal/model"
	"authzcov/internal/redact"
)

var headers = map[model.Relationship]string{
	model.RelOwner:             "OWNER",
	model.RelSameRoleOtherUser: "SAME_ROLE",
	model.RelLowerRole:         "LOWER",
	model.RelHigherRole:        "HIGHER",
	model.RelOtherTenant:       "OTHER_TENANT",
	model.RelAnonymous:         "ANON",
	model.RelUnknown:           "UNKNOWN",
}

// Options carries report data that is not part of the matrix.
type Options struct {
	// SuspiciousAllows adds a footer line when > 0.
	SuspiciousAllows int
}

// Render writes the coverage matrix as a text table to w via text/tabwriter.
func Render(w io.Writer, m *matrix.Matrix) error { return RenderWith(w, m, Options{}) }

// RenderWith is Render plus the optional footer lines in opt.
func RenderWith(w io.Writer, m *matrix.Matrix, opt Options) error {
	if m == nil {
		m = &matrix.Matrix{}
	}
	var cols []model.Relationship
	for _, rel := range model.Relationships() {
		for _, cs := range m.Cells {
			if slices.ContainsFunc(cs, func(c *model.CoverageCell) bool { return c != nil && c.Rel == rel && c.Required }) {
				cols = append(cols, rel)
				break
			}
		}
	}

	inferred := false
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	head := []string{"ENDPOINT"}
	for _, rel := range cols {
		head = append(head, headers[rel])
	}
	fmt.Fprintln(tw, strings.Join(head, "\t"))
	for _, ep := range m.Endpoints {
		if ep == nil {
			continue
		}
		row := []string{fmt.Sprintf("%-7s %s", redact.StripControl(ep.Method), redact.StripControl(ep.Template))}
		for _, rel := range cols {
			c := find(m.Cells[ep.ID], rel)
			if isInferred(c) {
				inferred = true
			}
			row = append(row, cellText(c))
		}
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\nrequired %d  covered %d (%.1f%%)  gaps %d\n",
		m.Summary.Required, m.Summary.Covered, m.Summary.Percent, m.Summary.Gaps); err != nil {
		return err
	}
	if inferred {
		if _, err := fmt.Fprintln(w, "~ covered only by inferred ownership evidence"); err != nil {
			return err
		}
	}
	if opt.SuspiciousAllows > 0 {
		_, err := fmt.Fprintf(w, "! %d suspicious allow(s): run \"authzcov report --format markdown\" for details\n", opt.SuspiciousAllows)
		return err
	}
	return nil
}

// isInferred reports a shown, covered cell whose weakest evidence is inferred.
func isInferred(c *model.CoverageCell) bool {
	return c != nil && c.Required && c.Covered && c.MinConf == model.ConfInferred
}

func find(cs []*model.CoverageCell, rel model.Relationship) *model.CoverageCell {
	for _, c := range cs {
		if c != nil && c.Rel == rel {
			return c
		}
	}
	return nil
}

func cellText(c *model.CoverageCell) string {
	switch {
	case c == nil || !c.Required:
		return "-"
	case !c.Covered:
		return "GAP"
	}
	var bad []int
	for s := range c.Statuses {
		if s < 200 || s > 299 {
			bad = append(bad, s)
		}
	}
	ok := "ok"
	if isInferred(c) {
		ok = "ok~"
	}
	if len(bad) == 0 {
		return ok
	}
	all := make([]int, 0, len(c.Statuses))
	for s := range c.Statuses {
		all = append(all, s)
	}
	slices.Sort(all)
	parts := make([]string, len(all))
	for i, s := range all {
		parts[i] = strconv.Itoa(s)
	}
	return ok + " " + strings.Join(parts, ",")
}
