package gate

import (
	"slices"
	"testing"

	"authzcov/internal/baseline"
)

func ch(ep, rel, was, now string) baseline.Change {
	return baseline.Change{Endpoint: ep, Relationship: rel, Was: was, Now: now}
}

func rules(t *testing.T, got []Violation) []Rule {
	t.Helper()
	var out []Rule
	for _, v := range got {
		out = append(out, v.Rule)
	}
	return out
}

func eval(d baseline.Diff, exp []string, rs []Rule, maxDrop float64) Result {
	return Evaluate(Input{Diff: d, Expired: exp, Rules: rs, MaxDrop: maxDrop})
}

func TestCleanPasses(t *testing.T) {
	r := eval(baseline.Diff{PercentWas: 50, PercentNow: 50}, nil, AllRules(), 0)
	if !r.Pass || len(r.Violations) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestNewGaps(t *testing.T) {
	// (a) known endpoint gains a new missing cell -> fails; (b) new endpoint too.
	d := baseline.Diff{
		NewEndpoints: []string{"GET /new"},
		NewGaps:      []baseline.Change{ch("GET /new", "owner", "", "missing"), ch("GET /old", "lower_role", "", "missing")},
	}
	r := eval(d, nil, AllRules(), 0)
	if r.Pass || len(r.Violations) != 1 || r.Violations[0].Rule != NewGaps ||
		!slices.Equal(r.Violations[0].Items, []string{"GET /new  owner", "GET /old  lower_role"}) {
		t.Fatalf("%+v", r)
	}
}

func TestNewGapsKnownEndpointFails(t *testing.T) {
	d := baseline.Diff{NewGaps: []baseline.Change{ch("GET /old", "lower_role", "", "missing")}}
	r := eval(d, nil, AllRules(), 0)
	if r.Pass || !slices.Equal(r.Violations[0].Items, []string{"GET /old  lower_role"}) {
		t.Fatalf("%+v", r)
	}
}

func TestNewCellsCoveredWaivedUnchangedPass(t *testing.T) {
	d := baseline.Diff{
		Improvements: []baseline.Change{ch("GET /old", "owner", "", "covered")},
		Waived:       []baseline.Change{ch("GET /old", "lower_role", "", "waived")},
		PercentWas:   50, PercentNow: 50,
	}
	if r := eval(d, nil, AllRules(), 0); !r.Pass || len(r.Violations) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestRegressions(t *testing.T) {
	d := baseline.Diff{Regressions: []baseline.Change{
		ch("GET /b", "owner", "covered", "missing"),
		ch("GET /a", "owner", "covered", "missing"),
		ch("GET /w", "owner", "waived", "missing"),
	}}
	r := eval(d, nil, AllRules(), 0)
	if r.Pass || !slices.Equal(r.Violations[0].Items, []string{"GET /a  owner", "GET /b  owner"}) {
		t.Fatalf("%+v", r)
	}
	// waived -> missing alone is not a regression for the gate.
	d = baseline.Diff{Regressions: []baseline.Change{ch("GET /w", "owner", "waived", "missing")}}
	if r := eval(d, nil, AllRules(), 0); !r.Pass {
		t.Fatalf("waived->missing failed the gate: %+v", r)
	}
}

func TestDropBoundary(t *testing.T) {
	cases := []struct {
		was, now, max float64
		pass          bool
	}{
		{70, 70, 0, true},
		{70, 69.9, 0, false},
		{70, 69.9, 0.1, true},
		{70, 69.8, 0.1, false},
		{70.04, 69.96, 0, true}, // both round to 70.0
		{70.3, 70.0, 0.3, true}, // float noise must not fail
		{60, 80, 0, true},
		{0, 0, 0, true}, // no required cells on either side
	}
	for _, c := range cases {
		r := eval(baseline.Diff{PercentWas: c.was, PercentNow: c.now}, nil, []Rule{Drop}, c.max)
		if r.Pass != c.pass {
			t.Errorf("%v -> %v max %v: pass=%v", c.was, c.now, c.max, r.Pass)
		}
	}
	r := eval(baseline.Diff{PercentWas: 70, PercentNow: 65.5}, nil, []Rule{Drop}, 0)
	if r.Violations[0].Items[0] != "coverage 70.0% -> 65.5% (max drop 0)" {
		t.Errorf("%q", r.Violations[0].Items[0])
	}
}

func TestExpiredWaivers(t *testing.T) {
	r := eval(baseline.Diff{}, []string{"b", "a", "a"}, AllRules(), 0)
	if r.Pass || !slices.Equal(r.Violations[0].Items, []string{"a", "b"}) {
		t.Fatalf("%+v", r)
	}
}

func TestRemovedNeverFails(t *testing.T) {
	r := eval(baseline.Diff{Removed: []string{"DELETE /z", "DELETE /a"}, PercentWas: 40, PercentNow: 40}, nil, AllRules(), 0)
	if !r.Pass || !slices.Equal(r.Removed, []string{"DELETE /a", "DELETE /z"}) {
		t.Fatalf("%+v", r)
	}
}

func TestDisabledRulesIgnoredAndOrder(t *testing.T) {
	d := baseline.Diff{
		NewEndpoints: []string{"GET /n"},
		NewGaps:      []baseline.Change{ch("GET /n", "owner", "", "missing")},
		Regressions:  []baseline.Change{ch("GET /r", "owner", "covered", "missing")},
		PercentWas:   80, PercentNow: 70,
	}
	r := eval(d, []string{"x"}, []Rule{NewGaps}, 0)
	if r.Pass || !slices.Equal(rules(t, r.Violations), []Rule{NewGaps}) ||
		!slices.Equal(rules(t, r.Ignored), []Rule{Regressions, Drop, ExpiredWaivers}) {
		t.Fatalf("%+v", r)
	}
	r = eval(d, []string{"x"}, AllRules(), 0)
	if !slices.Equal(rules(t, r.Violations), AllRules()) {
		t.Fatalf("order: %v", rules(t, r.Violations))
	}
	// only a regression, regressions disabled -> pass
	d = baseline.Diff{Regressions: []baseline.Change{ch("GET /r", "owner", "covered", "missing")}}
	r = eval(d, nil, []Rule{NewGaps}, 0)
	if !r.Pass || len(r.Ignored) != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestParseRules(t *testing.T) {
	ok := []struct {
		in   string
		want []Rule
	}{
		{"new-gaps", []Rule{NewGaps}},
		{" drop , new-gaps ", []Rule{NewGaps, Drop}},
		{"expired-waivers,regressions,new-gaps,drop", AllRules()},
		{"drop,drop", []Rule{Drop}},
	}
	for _, c := range ok {
		got, err := ParseRules(c.in)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("%q: %v %v", c.in, got, err)
		}
	}
	for _, in := range []string{"", ",", "new-gaps,", "bogus", "New-Gaps", "new-gaps,,drop"} {
		if _, err := ParseRules(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestDeterministic(t *testing.T) {
	d := baseline.Diff{Regressions: []baseline.Change{ch("GET /a", "owner", "covered", "missing")}, PercentWas: 5, PercentNow: 1}
	a, b := eval(d, []string{"q", "p"}, AllRules(), 0), eval(d, []string{"p", "q"}, AllRules(), 0)
	if len(a.Violations) != len(b.Violations) {
		t.Fatal("differs")
	}
	for i := range a.Violations {
		if !slices.Equal(a.Violations[i].Items, b.Violations[i].Items) {
			t.Fatal("differs")
		}
	}
}
