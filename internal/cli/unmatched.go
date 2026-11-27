package cli

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"authzcov/internal/model"
	"authzcov/internal/redact"
	"authzcov/internal/report/coveragejson"
)

const maxShapeLines = 20

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexRe  = regexp.MustCompile(`^[0-9a-fA-F]{8,}$`)
	digRe  = regexp.MustCompile(`^[0-9]+$`)
)

func looksLikeID(seg string) bool {
	if seg == "" {
		return false
	}
	if digRe.MatchString(seg) || uuidRe.MatchString(seg) || hexRe.MatchString(seg) {
		return true
	}
	if len(seg) >= 24 {
		return true
	}
	var digit bool
	for _, r := range seg {
		if r >= '0' && r <= '9' {
			digit = true
		}
	}
	// A digit in a segment of 6+ bytes is ID-like; short ones (v1, 2fa) stay.
	return digit && len(seg) >= 6
}

// shapeOf returns "METHOD /path" with ID-looking segments replaced by <id>.
func shapeOf(x *model.Exchange) string {
	segs := strings.Split(x.Path, "/")
	for i, s := range segs {
		if j := strings.IndexByte(s, ';'); j >= 0 {
			s = s[:j]
		}
		if looksLikeID(s) {
			s = "<id>"
		}
		segs[i] = s
	}
	return redact.StripControl(strings.ToUpper(x.Method) + " " + strings.Join(segs, "/"))
}

// groupShapes groups exchanges by shape, most frequent first, then by shape.
func groupShapes(xs []*model.Exchange) []coveragejson.Shape {
	counts := map[string]int{}
	for _, x := range xs {
		counts[shapeOf(x)]++
	}
	out := make([]coveragejson.Shape, 0, len(counts))
	for s, n := range counts {
		out = append(out, coveragejson.Shape{Key: s, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// writeUnmatched prints up to maxShapeLines groups of unmatched requests.
func writeUnmatched(w io.Writer, xs []*model.Exchange) {
	if len(xs) == 0 {
		return
	}
	shapes := groupShapes(xs)
	_, _ = fmt.Fprintln(w, "unmatched requests by shape:")
	for i, s := range shapes {
		if i == maxShapeLines {
			_, _ = fmt.Fprintf(w, "  ... and %d more shapes\n", len(shapes)-maxShapeLines)
			break
		}
		_, _ = fmt.Fprintf(w, "  %d  %s\n", s.Count, s.Key)
	}
}
