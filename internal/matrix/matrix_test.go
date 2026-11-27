package matrix

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"

	"authzcov/internal/model"
)

var (
	objEP = &model.Endpoint{ID: "GET /b/{id}", Kind: model.ObjectLevel}
	fnEP  = &model.Endpoint{ID: "GET /admin", Kind: model.FunctionLevel}
)

func rels(r ...model.Relationship) []model.Relationship { return r }

func TestRequirements(t *testing.T) {
	tests := []struct {
		kind model.EndpointKind
		ten  bool
		want []model.Relationship
	}{
		{model.ObjectLevel, true, rels(model.RelOwner, model.RelSameRoleOtherUser, model.RelOtherTenant, model.RelAnonymous)},
		{model.ObjectLevel, false, rels(model.RelOwner, model.RelSameRoleOtherUser, model.RelAnonymous)},
		{model.FunctionLevel, true, rels(model.RelOwner, model.RelLowerRole, model.RelAnonymous)},
		{model.FunctionLevel, false, rels(model.RelOwner, model.RelLowerRole, model.RelAnonymous)},
	}
	for _, tc := range tests {
		got := Requirements(tc.kind, tc.ten)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%v %v: got %v want %v", tc.kind, tc.ten, got, tc.want)
		}
	}
}

func mk(ep *model.Endpoint, rel model.Relationship, name string, idc, oc model.Confidence, status int, src string) *model.Observation {
	return &model.Observation{
		Endpoint: ep, Rel: rel, Identity: &model.Identity{Name: name},
		IDConf: idc, OwnerConf: oc, X: &model.Exchange{Status: status, Source: src},
	}
}

func cell(m *Matrix, ep *model.Endpoint, rel model.Relationship) *model.CoverageCell {
	for _, c := range m.Cells[ep.ID] {
		if c.Rel == rel {
			return c
		}
	}
	return nil
}

func TestBuildCoverageRules(t *testing.T) {
	const (
		unk = model.ConfUnknown
		inf = model.ConfInferred
		lrn = model.ConfLearned
		dec = model.ConfDeclared
	)
	tests := []struct {
		name    string
		ep      *model.Endpoint
		o       *model.Observation
		rel     model.Relationship
		covered bool
		minConf model.Confidence
	}{
		{"declared object", objEP, mk(objEP, model.RelOwner, "a", dec, dec, 200, "a#1"), model.RelOwner, true, dec},
		{"learned id inferred owner", objEP, mk(objEP, model.RelOwner, "a", lrn, inf, 200, "a#1"), model.RelOwner, true, inf},
		{"min of id and owner", objEP, mk(objEP, model.RelOwner, "a", dec, lrn, 200, "a#1"), model.RelOwner, true, lrn},
		{"unknown id", objEP, mk(objEP, model.RelOwner, "a", unk, dec, 200, "a#1"), model.RelOwner, false, unk},
		{"inferred id", objEP, mk(objEP, model.RelOwner, "a", inf, dec, 200, "a#1"), model.RelOwner, false, unk},
		{"owner unknown object", objEP, mk(objEP, model.RelOwner, "a", dec, unk, 200, "a#1"), model.RelOwner, false, unk},
		{"owner unknown anonymous object", objEP, mk(objEP, model.RelAnonymous, "anon", dec, unk, 401, "a#1"), model.RelAnonymous, false, unk},
		{"anonymous object known owner", objEP, mk(objEP, model.RelAnonymous, "anon", dec, inf, 401, "a#1"), model.RelAnonymous, true, inf},
		{"function ignores owner conf", fnEP, mk(fnEP, model.RelLowerRole, "a", lrn, unk, 403, "a#1"), model.RelLowerRole, true, lrn},
		{"rel unknown never", objEP, mk(objEP, model.RelUnknown, "a", dec, dec, 200, "a#1"), model.RelUnknown, false, unk},
		{"rel empty is unknown", objEP, mk(objEP, "", "a", dec, dec, 200, "a#1"), model.RelUnknown, false, unk},
		{"rel bogus is unknown", objEP, mk(objEP, "bogus", "a", dec, dec, 200, "a#1"), model.RelUnknown, false, unk},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := Build([]*model.Endpoint{tc.ep}, []*model.Observation{tc.o}, true)
			c := cell(m, tc.ep, tc.rel)
			if c.Covered != tc.covered || c.MinConf != tc.minConf {
				t.Fatalf("covered=%v minconf=%s", c.Covered, c.MinConf)
			}
			if len(c.Statuses) != 1 || len(c.Evidence) != 1 || len(c.Identities) != 1 {
				t.Fatalf("observation not recorded: %+v", c)
			}
		})
	}
}

func TestMinConfAcrossObservations(t *testing.T) {
	obs := []*model.Observation{
		mk(objEP, model.RelOwner, "a", model.ConfDeclared, model.ConfDeclared, 200, "a#1"),
		mk(objEP, model.RelOwner, "b", model.ConfLearned, model.ConfInferred, 200, "a#2"),
		mk(objEP, model.RelOwner, "c", model.ConfUnknown, model.ConfDeclared, 200, "a#3"), // not counting
	}
	c := cell(Build([]*model.Endpoint{objEP}, obs, true), objEP, model.RelOwner)
	if !c.Covered || c.MinConf != model.ConfInferred {
		t.Fatalf("%+v", c)
	}
	if !slices.Equal(c.Identities, []string{"a", "b", "c"}) || c.Statuses[200] != 3 {
		t.Fatalf("%+v", c)
	}
}

func TestCellsShape(t *testing.T) {
	m := Build([]*model.Endpoint{objEP, fnEP, nil}, nil, false)
	if m.Endpoints[0] != fnEP || m.Endpoints[1] != objEP {
		t.Fatal("endpoints not sorted")
	}
	for _, e := range m.Endpoints {
		cs := m.Cells[e.ID]
		if len(cs) != 7 {
			t.Fatalf("%s: %d cells", e.ID, len(cs))
		}
		for i, rel := range model.Relationships() {
			c := cs[i]
			if c.Rel != rel || c.Endpoint != e.ID || c.Statuses == nil || c.Covered {
				t.Fatalf("bad cell %+v", c)
			}
			if c.Required != slices.Contains(Requirements(e.Kind, false), rel) {
				t.Fatalf("bad required %+v", c)
			}
		}
	}
	// 3 object + 3 function required; none covered.
	if s := m.Summary; s.Required != 6 || s.Covered != 0 || s.Gaps != 6 || s.Percent != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestIgnoresUnknownEndpointAndNil(t *testing.T) {
	other := &model.Endpoint{ID: "GET /other"}
	obs := []*model.Observation{nil, {}, mk(other, model.RelOwner, "a", 3, 3, 200, "x#1"),
		{Endpoint: objEP, Rel: model.RelOwner, IDConf: 3, OwnerConf: 3}} // nil X, nil Identity
	m := Build([]*model.Endpoint{objEP}, obs, true)
	if _, ok := m.Cells[other.ID]; ok {
		t.Fatal("unknown endpoint present")
	}
	c := cell(m, objEP, model.RelOwner)
	if !c.Covered || len(c.Statuses) != 0 || len(c.Identities) != 0 {
		t.Fatalf("%+v", c)
	}
}

func TestEvidenceSortCapDedup(t *testing.T) {
	var obs []*model.Observation
	for _, s := range []string{"a.har#10", "a.har#2", "a.har#2", "b.har#1", "a.har#1", "a.har#3", "a.har#4", "weird", "a.har#x"} {
		obs = append(obs, mk(objEP, model.RelOwner, "u", 3, 3, 200, s))
	}
	c := cell(Build([]*model.Endpoint{objEP}, obs, true), objEP, model.RelOwner)
	want := []string{"a.har#1", "a.har#2", "a.har#3", "a.har#4", "a.har#10"}
	if !slices.Equal(c.Evidence, want) {
		t.Fatalf("got %v", c.Evidence)
	}
	c = cell(Build([]*model.Endpoint{objEP}, obs[:3], true), objEP, model.RelOwner)
	if !slices.Equal(c.Evidence, []string{"a.har#2", "a.har#10"}) {
		t.Fatalf("got %v", c.Evidence)
	}
}

func TestIdentitiesDedupSorted(t *testing.T) {
	obs := []*model.Observation{
		mk(objEP, model.RelOwner, "zed", 3, 3, 200, "a#1"),
		mk(objEP, model.RelOwner, "amy", 3, 3, 200, "a#2"),
		mk(objEP, model.RelOwner, "zed", 3, 3, 404, "a#3"),
	}
	c := cell(Build([]*model.Endpoint{objEP}, obs, true), objEP, model.RelOwner)
	if !slices.Equal(c.Identities, []string{"amy", "zed"}) || c.Statuses[200] != 2 || c.Statuses[404] != 1 {
		t.Fatalf("%+v", c)
	}
}

func TestSummary(t *testing.T) {
	obs := []*model.Observation{
		mk(objEP, model.RelOwner, "a", 3, 3, 200, "a#1"),
		mk(objEP, model.RelAnonymous, "anon", 3, 3, 401, "a#2"),
		mk(objEP, model.RelOtherTenant, "t", 3, 3, 403, "a#3"), // not required: no tenants
		mk(fnEP, model.RelOwner, "a", 3, 0, 200, "a#4"),
	}
	m := Build([]*model.Endpoint{objEP, fnEP}, obs, false)
	s := m.Summary
	if s.Required != 6 || s.Covered != 3 || s.Gaps != 3 || s.Percent != 50 {
		t.Fatalf("%+v", s)
	}
	if !cell(m, objEP, model.RelOtherTenant).Covered || cell(m, objEP, model.RelOtherTenant).Required {
		t.Fatal("other_tenant cell wrong")
	}
}

func TestOrderIndependenceProperty(t *testing.T) {
	eps := []*model.Endpoint{objEP, fnEP, {ID: "DELETE /b/{id}", Kind: model.ObjectLevel}}
	all := model.Relationships()
	var obs []*model.Observation
	for i := range 60 {
		ep := eps[i%len(eps)]
		obs = append(obs, mk(ep, all[i%len(all)], fmt.Sprintf("u%d", i%4),
			model.Confidence(i%4), model.Confidence((i/2)%4), 200+i%5, fmt.Sprintf("f%d.har#%d", i%3, i)))
	}
	want := Build(eps, obs, true)
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // deterministic shuffle in a test
	for range 50 {
		o2 := slices.Clone(obs)
		rng.Shuffle(len(o2), func(i, j int) { o2[i], o2[j] = o2[j], o2[i] })
		e2 := slices.Clone(eps)
		rng.Shuffle(len(e2), func(i, j int) { e2[i], e2[j] = e2[j], e2[i] })
		if got := Build(e2, o2, true); !reflect.DeepEqual(got, want) {
			t.Fatal("matrix depends on input order")
		}
	}
}

func TestStrict(t *testing.T) {
	const (
		unk = model.ConfUnknown
		inf = model.ConfInferred
		lrn = model.ConfLearned
		dec = model.ConfDeclared
	)
	tenant := func(o *model.Observation) *model.Observation { o.ObjectTenantKnown = true; return o }
	tests := []struct {
		name          string
		ep            *model.Endpoint
		o             *model.Observation
		rel           model.Relationship
		loose, strict bool
	}{
		{"object learned owner", objEP, mk(objEP, model.RelOwner, "a", lrn, lrn, 200, "a#1"), model.RelOwner, true, true},
		{"object inferred owner", objEP, mk(objEP, model.RelOwner, "a", dec, inf, 200, "a#1"), model.RelOwner, true, false},
		{"object unknown owner", objEP, mk(objEP, model.RelOwner, "a", dec, unk, 200, "a#1"), model.RelOwner, false, false},
		{"object inferred id", objEP, mk(objEP, model.RelOwner, "a", inf, dec, 200, "a#1"), model.RelOwner, false, false},
		{"function ignores owner", fnEP, mk(fnEP, model.RelLowerRole, "a", lrn, unk, 403, "a#1"), model.RelLowerRole, true, true},
		{"function inferred id", fnEP, mk(fnEP, model.RelLowerRole, "a", inf, unk, 403, "a#1"), model.RelLowerRole, false, false},
		{"anonymous inferred owner", objEP, mk(objEP, model.RelAnonymous, "anon", dec, inf, 401, "a#1"), model.RelAnonymous, true, false},
		{"tenant param owner unknown", objEP, tenant(mk(objEP, model.RelOtherTenant, "c", lrn, unk, 403, "a#1")), model.RelOtherTenant, true, true},
		{"tenant param inferred id", objEP, tenant(mk(objEP, model.RelOtherTenant, "c", inf, unk, 403, "a#1")), model.RelOtherTenant, false, false},
		{"other tenant by owner needs owner", objEP, mk(objEP, model.RelOtherTenant, "c", lrn, unk, 403, "a#1"), model.RelOtherTenant, false, false},
		{"other tenant by inferred owner", objEP, mk(objEP, model.RelOtherTenant, "c", lrn, inf, 403, "a#1"), model.RelOtherTenant, true, false},
		{"tenant param on non-other_tenant rel", objEP, tenant(mk(objEP, model.RelOwner, "a", lrn, unk, 200, "a#1")), model.RelOwner, false, false},
	}
	for _, tc := range tests {
		for _, strict := range []bool{false, true} {
			want := tc.loose
			if strict {
				want = tc.strict
			}
			m := BuildWith([]*model.Endpoint{tc.ep}, []*model.Observation{tc.o}, true, Options{Strict: strict})
			if c := cell(m, tc.ep, tc.rel); c.Covered != want {
				t.Errorf("%s strict=%v: covered=%v want %v", tc.name, strict, c.Covered, want)
			}
		}
	}
}

func TestTenantParamMinConf(t *testing.T) {
	o := mk(objEP, model.RelOtherTenant, "c", model.ConfLearned, model.ConfUnknown, 403, "a#1")
	o.ObjectTenantKnown = true
	c := cell(Build([]*model.Endpoint{objEP}, []*model.Observation{o}, true), objEP, model.RelOtherTenant)
	if !c.Covered || c.MinConf != model.ConfLearned {
		t.Fatalf("%+v", c)
	}
}

func TestBuildIsNonStrict(t *testing.T) {
	obs := []*model.Observation{mk(objEP, model.RelOwner, "a", model.ConfDeclared, model.ConfInferred, 200, "a#1")}
	if !reflect.DeepEqual(Build([]*model.Endpoint{objEP}, obs, true), BuildWith([]*model.Endpoint{objEP}, obs, true, Options{})) {
		t.Fatal("Build != BuildWith(Options{})")
	}
}
