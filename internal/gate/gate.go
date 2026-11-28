// Package gate decides whether a coverage result passes the CI gate. It is
// pure: it reads no files and no clock, so expired waivers arrive as messages.
package gate

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"authzcov/internal/baseline"
)

// Rule is one gate rule.
type Rule string

// The gate rules, in canonical (report) order.
const (
	NewGaps        Rule = "new-gaps"
	Regressions    Rule = "regressions"
	Drop           Rule = "drop"
	ExpiredWaivers Rule = "expired-waivers"
)

// AllRules returns every rule in canonical order.
func AllRules() []Rule { return []Rule{NewGaps, Regressions, Drop, ExpiredWaivers} }

// ParseRules parses a comma-separated rule list. It trims spaces, rejects
// empty and unknown names, removes duplicates and returns canonical order.
func ParseRules(s string) ([]Rule, error) {
	want := map[Rule]bool{}
	for _, part := range strings.Split(s, ",") {
		name := Rule(strings.TrimSpace(part))
		if name == "" {
			return nil, fmt.Errorf("empty rule name in %q", s)
		}
		if !slices.Contains(AllRules(), name) {
			return nil, fmt.Errorf("unknown rule %q (valid: new-gaps, regressions, drop, expired-waivers)", string(name))
		}
		want[name] = true
	}
	var out []Rule
	for _, r := range AllRules() {
		if want[r] {
			out = append(out, r)
		}
	}
	return out, nil
}

// Input is what Evaluate judges.
type Input struct {
	Diff    baseline.Diff
	Expired []string // human messages, one per expired waiver
	Rules   []Rule   // enabled rules
	MaxDrop float64  // allowed fall in percentage points
}

// Violation is one rule with the things that break it. Items are sorted.
type Violation struct {
	Rule  Rule
	Items []string
}

// Result is the gate verdict.
type Result struct {
	Pass       bool
	Violations []Violation // enabled rules that fail, in AllRules order
	Ignored    []Violation // disabled rules that would have failed
	Removed    []string    // endpoints gone from the spec; never a failure
	PercentWas float64
	PercentNow float64
}

func round1(x float64) float64 { return math.Round(x*10) / 10 }

// Evaluate applies the enabled rules to in.
func Evaluate(in Input) Result {
	d := in.Diff
	res := Result{Pass: true, Removed: slices.Clone(d.Removed), PercentWas: d.PercentWas, PercentNow: d.PercentNow}
	slices.Sort(res.Removed)

	checks := map[Rule][]string{}
	for _, c := range d.NewGaps {
		checks[NewGaps] = append(checks[NewGaps], c.Endpoint+"  "+c.Relationship)
	}
	for _, c := range d.Regressions {
		if c.Was == baseline.Covered && c.Now == baseline.Missing {
			checks[Regressions] = append(checks[Regressions], c.Endpoint+"  "+c.Relationship)
		}
	}
	was, now := round1(d.PercentWas), round1(d.PercentNow)
	if was-now > in.MaxDrop+1e-9 {
		checks[Drop] = []string{fmt.Sprintf("coverage %.1f%% -> %.1f%% (max drop %g)", was, now, in.MaxDrop)}
	}
	if len(in.Expired) > 0 {
		checks[ExpiredWaivers] = slices.Clone(in.Expired)
	}

	enabled := map[Rule]bool{}
	for _, r := range in.Rules {
		enabled[r] = true
	}
	for _, r := range AllRules() {
		items := checks[r]
		if len(items) == 0 {
			continue
		}
		slices.Sort(items)
		items = slices.Compact(items)
		v := Violation{Rule: r, Items: items}
		if enabled[r] {
			res.Violations = append(res.Violations, v)
			res.Pass = false
		} else {
			res.Ignored = append(res.Ignored, v)
		}
	}
	return res
}
