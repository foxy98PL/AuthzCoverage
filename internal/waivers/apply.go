package waivers

import (
	"cmp"
	"fmt"
	"slices"
	"time"

	"authzcov/internal/report/coveragejson"
)

// Warning codes added by Apply.
const (
	WarnExpired = "waiver_expired"
	WarnUnused  = "waiver_unused"
)

// Apply marks required, uncovered cells waived when a non-expired waiver
// matches (first match in file order wins), sets Cell.Waiver, recomputes
// Summary.Waived/Gaps/Percent, drops the gap findings of waived cells, and adds
// waiver_expired / waiver_unused warnings (re-sorted as coveragejson.Build
// does). A covered cell is never waived. Expired waivers do nothing but warn.
// Apply is pure: today is passed in.
func Apply(r *coveragejson.Report, ws []Waiver, today time.Time) {
	used := make([]bool, len(ws)) // matched at least one endpoint
	for _, e := range r.Endpoints {
		for i, w := range ws {
			if Match(w.Endpoint, e.ID) {
				used[i] = true
			}
		}
	}
	waivedKey := map[[2]string]bool{}
	for i := range r.Cells {
		c := &r.Cells[i]
		if !c.Required || c.Covered {
			continue
		}
		for _, w := range ws {
			if w.Relationship != c.Relationship || w.Expired(today) || !Match(w.Endpoint, c.Endpoint) {
				continue
			}
			c.Waiver = &coveragejson.CellWaiver{Reason: w.Reason, Expires: w.ExpiresText}
			break
		}
	}
	waived := 0
	for _, c := range r.Cells {
		if c.Waiver != nil {
			waived++
			waivedKey[[2]string{c.Endpoint, c.Relationship}] = true
		}
	}
	kept := r.Findings[:0]
	for _, f := range r.Findings {
		if f.Kind == coveragejson.KindGap && waivedKey[[2]string{f.Endpoint, f.Relationship}] {
			continue
		}
		kept = append(kept, f)
	}
	r.Findings = kept
	r.Summary.Waived = waived
	r.Summary.Gaps = r.Summary.Required - r.Summary.Covered - waived
	r.Summary.Percent = coveragejson.Percent(r.Summary.Covered, r.Summary.Required, waived)

	for i, w := range ws {
		if w.Expired(today) {
			r.Warnings = append(r.Warnings, coveragejson.Warning{Code: WarnExpired,
				Message: fmt.Sprintf("waiver for %s %s expired on %s", w.Endpoint, w.Relationship, w.ExpiresText)})
		}
		if !used[i] {
			r.Warnings = append(r.Warnings, coveragejson.Warning{Code: WarnUnused,
				Message: fmt.Sprintf("waiver for %s %s matches no endpoint", w.Endpoint, w.Relationship)})
		}
	}
	slices.SortFunc(r.Warnings, func(a, b coveragejson.Warning) int {
		return cmp.Or(cmp.Compare(a.Code, b.Code), cmp.Compare(a.Message, b.Message))
	})
}
