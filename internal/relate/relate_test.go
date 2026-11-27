package relate

import (
	"slices"
	"testing"

	"authzcov/internal/model"
)

func id(name string, rank int, tenant string) *model.Identity {
	return &model.Identity{Name: name, Rank: rank, Tenant: tenant}
}

var (
	objEP = &model.Endpoint{ID: "GET /b/{id}", Kind: model.ObjectLevel, ObjectParam: "id"}
	fnEP  = &model.Endpoint{ID: "GET /admin", Kind: model.FunctionLevel}
)

func TestClassify(t *testing.T) {
	const (
		unk = model.ConfUnknown
		inf = model.ConfInferred
		lrn = model.ConfLearned
		dec = model.ConfDeclared
	)
	tests := []struct {
		name string
		in   Input
		want model.Relationship
	}{
		{"caller nil", Input{Endpoint: objEP, Owner: id("a", 1, ""), OwnerConf: dec}, model.RelUnknown},
		{"anonymous object unknown owner", Input{Endpoint: objEP, Caller: &model.Identity{Name: "anon", Anonymous: true}}, model.RelAnonymous},
		{"anonymous function", Input{Endpoint: fnEP, Caller: &model.Identity{Anonymous: true}}, model.RelAnonymous},
		{"anonymous nil endpoint", Input{Caller: &model.Identity{Anonymous: true}}, model.RelAnonymous},
		{"caller conf unknown", Input{Endpoint: objEP, Caller: id("a", 1, ""), CallerConf: unk, Owner: id("a", 1, ""), OwnerConf: dec}, model.RelUnknown},
		{"endpoint nil", Input{Caller: id("a", 1, ""), CallerConf: dec}, model.RelUnknown},
		{"owner nil", Input{Endpoint: objEP, Caller: id("a", 1, ""), CallerConf: dec}, model.RelUnknown},
		{"owner conf unknown", Input{Endpoint: objEP, Caller: id("a", 1, ""), CallerConf: dec, Owner: id("b", 1, ""), OwnerConf: unk}, model.RelUnknown},
		{"owner conf unknown tenant differs", Input{Endpoint: objEP, Caller: id("a", 1, "x"), CallerConf: dec, Owner: id("b", 1, "y"), OwnerConf: unk}, model.RelUnknown},
		{"owner same name", Input{Endpoint: objEP, Caller: id("a", 1, ""), CallerConf: lrn, Owner: id("a", 1, ""), OwnerConf: inf}, model.RelOwner},
		{"same role other user", Input{Endpoint: objEP, Caller: id("a", 1, ""), CallerConf: lrn, Owner: id("b", 1, ""), OwnerConf: lrn}, model.RelSameRoleOtherUser},
		{"lower", Input{Endpoint: objEP, Caller: id("a", 1, ""), CallerConf: lrn, Owner: id("b", 2, ""), OwnerConf: lrn}, model.RelLowerRole},
		{"higher", Input{Endpoint: objEP, Caller: id("a", 3, ""), CallerConf: lrn, Owner: id("b", 2, ""), OwnerConf: lrn}, model.RelHigherRole},
		{"tenant differs", Input{Endpoint: objEP, Caller: id("a", 1, "x"), CallerConf: lrn, Owner: id("b", 1, "y"), OwnerConf: lrn}, model.RelOtherTenant},
		{"tenant differs inferred owner", Input{Endpoint: objEP, Caller: id("a", 1, "x"), CallerConf: lrn, Owner: id("b", 1, "y"), OwnerConf: inf}, model.RelOtherTenant},
		{"tenant star exempt", Input{Endpoint: objEP, Caller: id("a", 1, "*"), CallerConf: lrn, Owner: id("b", 1, "y"), OwnerConf: lrn}, model.RelSameRoleOtherUser},
		{"tenant equal falls through", Input{Endpoint: objEP, Caller: id("a", 1, "x"), CallerConf: lrn, Owner: id("b", 1, "x"), OwnerConf: lrn}, model.RelSameRoleOtherUser},
		{"tenant equal owner", Input{Endpoint: objEP, Caller: id("a", 1, "x"), CallerConf: lrn, Owner: id("a", 1, "x"), OwnerConf: lrn}, model.RelOwner},
		{"caller tenant empty owner acme", Input{Endpoint: objEP, Caller: id("a", 1, ""), CallerConf: lrn, Owner: id("b", 1, "acme"), OwnerConf: lrn}, model.RelOtherTenant},
		{"owner tenant empty never other", Input{Endpoint: objEP, Caller: id("a", 1, "x"), CallerConf: lrn, Owner: id("b", 1, ""), OwnerConf: lrn}, model.RelSameRoleOtherUser},
		{"param tenant differs owner unknown", Input{Endpoint: objEP, Caller: id("a", 1, "OrgB"), CallerConf: lrn, ObjectTenant: "OrgA", ObjectTenantKnown: true}, model.RelOtherTenant},
		{"param tenant differs owner known same tenant", Input{Endpoint: objEP, Caller: id("a", 1, "OrgB"), CallerConf: lrn, Owner: id("b", 1, "OrgB"), OwnerConf: lrn, ObjectTenant: "OrgA", ObjectTenantKnown: true}, model.RelOtherTenant},
		{"param tenant equal owner unknown", Input{Endpoint: objEP, Caller: id("a", 1, "OrgA"), CallerConf: lrn, ObjectTenant: "OrgA", ObjectTenantKnown: true}, model.RelUnknown},
		{"param tenant equal owner same", Input{Endpoint: objEP, Caller: id("a", 1, "OrgA"), CallerConf: lrn, Owner: id("a", 1, "OrgA"), OwnerConf: lrn, ObjectTenant: "OrgA", ObjectTenantKnown: true}, model.RelOwner},
		{"param tenant equal other user", Input{Endpoint: objEP, Caller: id("a", 1, "OrgA"), CallerConf: lrn, Owner: id("b", 1, "OrgA"), OwnerConf: inf, ObjectTenant: "OrgA", ObjectTenantKnown: true}, model.RelSameRoleOtherUser},
		{"param tenant star exempt", Input{Endpoint: objEP, Caller: id("a", 1, "*"), CallerConf: lrn, Owner: id("b", 1, ""), OwnerConf: lrn, ObjectTenant: "OrgA", ObjectTenantKnown: true}, model.RelSameRoleOtherUser},
		{"param tenant star exempt owner unknown", Input{Endpoint: objEP, Caller: id("a", 1, "*"), CallerConf: lrn, ObjectTenant: "OrgA", ObjectTenantKnown: true}, model.RelUnknown},
		{"param tenant caller no tenant", Input{Endpoint: objEP, Caller: id("a", 1, ""), CallerConf: lrn, ObjectTenant: "OrgA", ObjectTenantKnown: true}, model.RelOtherTenant},
		{"param tenant overrides owner tenant rule", Input{Endpoint: objEP, Caller: id("a", 1, "OrgA"), CallerConf: lrn, Owner: id("b", 1, "OrgZ"), OwnerConf: lrn, ObjectTenant: "OrgA", ObjectTenantKnown: true}, model.RelSameRoleOtherUser},
		{"param tenant anonymous", Input{Endpoint: objEP, Caller: &model.Identity{Anonymous: true}, ObjectTenant: "OrgA", ObjectTenantKnown: true}, model.RelAnonymous},
		{"param tenant caller conf unknown", Input{Endpoint: objEP, Caller: id("a", 1, "OrgB"), ObjectTenant: "OrgA", ObjectTenantKnown: true}, model.RelUnknown},
		{"param tenant function level ignored", Input{Endpoint: fnEP, Caller: id("a", 1, "OrgB"), CallerConf: lrn, ObjectTenant: "OrgA", ObjectTenantKnown: true}, model.RelUnknown},
		{"fn min unknown", Input{Endpoint: fnEP, Caller: id("a", 1, ""), CallerConf: lrn}, model.RelUnknown},
		{"fn lower", Input{Endpoint: fnEP, Caller: id("a", 1, ""), CallerConf: lrn, MinRank: 5, MinRankKnown: true}, model.RelLowerRole},
		{"fn higher", Input{Endpoint: fnEP, Caller: id("a", 9, ""), CallerConf: lrn, MinRank: 5, MinRankKnown: true}, model.RelHigherRole},
		{"fn equal", Input{Endpoint: fnEP, Caller: id("a", 5, ""), CallerConf: lrn, MinRank: 5, MinRankKnown: true}, model.RelOwner},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.in); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func ob(ep *model.Endpoint, who *model.Identity, conf model.Confidence, status int) *model.Observation {
	return &model.Observation{Endpoint: ep, Identity: who, IDConf: conf, X: &model.Exchange{Status: status}}
}

func TestMinRanks(t *testing.T) {
	fn2 := &model.Endpoint{ID: "GET /fn2", Kind: model.FunctionLevel}
	fn3 := &model.Endpoint{ID: "GET /fn3", Kind: model.FunctionLevel}
	obs := []*model.Observation{
		ob(fnEP, id("admin", 9, ""), model.ConfDeclared, 200),
		ob(fnEP, id("mid", 5, ""), model.ConfLearned, 204),
		ob(fnEP, id("low", 1, ""), model.ConfLearned, 403),                                         // 4xx ignored
		ob(fnEP, &model.Identity{Name: "anon", Rank: 0, Anonymous: true}, model.ConfDeclared, 200), // anon ignored
		ob(fnEP, id("guess", 0, ""), model.ConfInferred, 200),                                      // low conf
		ob(fnEP, id("unk", 0, ""), model.ConfUnknown, 200),
		ob(objEP, id("admin", 9, ""), model.ConfDeclared, 200), // object-level
		ob(fn2, id("low", 1, ""), model.ConfLearned, 403),
		ob(fn3, nil, model.ConfLearned, 200),
		nil,
		{Endpoint: fn3, Identity: id("x", 1, ""), IDConf: model.ConfLearned}, // nil X
		ob(nil, id("x", 1, ""), model.ConfLearned, 200),
	}
	got := MinRanks(obs)
	if len(got) != 1 || got[fnEP.ID] != 5 {
		t.Fatalf("got %v", got)
	}
}

var tsEP = &model.Endpoint{ID: "GET /orgs/{orgId}/orders", Kind: model.ObjectLevel, ObjectParam: "orgId", TenantScoped: true}

func TestClassifyTenantScoped(t *testing.T) {
	const lrn = model.ConfLearned
	declared := &model.Endpoint{ID: tsEP.ID, Kind: model.ObjectLevel, ObjectParam: "orgId", TenantScoped: true, MinRankDeclared: true, MinRank: 100, MinRole: "admin"}
	fnDeclared := &model.Endpoint{ID: "GET /admin", Kind: model.FunctionLevel, MinRankDeclared: true, MinRank: 100, MinRole: "admin"}
	tests := []struct {
		name string
		in   Input
		want model.Relationship
	}{
		{"same tenant at min", Input{Endpoint: tsEP, Caller: id("ann", 10, "A"), CallerConf: lrn, ObjectTenant: "A", ObjectTenantKnown: true, MinRank: 10, MinRankKnown: true}, model.RelOwner},
		{"same tenant above min", Input{Endpoint: tsEP, Caller: id("adm", 100, "A"), CallerConf: lrn, ObjectTenant: "A", ObjectTenantKnown: true, MinRank: 10, MinRankKnown: true}, model.RelOwner},
		{"same tenant below min", Input{Endpoint: tsEP, Caller: id("ann", 10, "A"), CallerConf: lrn, ObjectTenant: "A", ObjectTenantKnown: true, MinRank: 100, MinRankKnown: true}, model.RelLowerRole},
		{"other tenant", Input{Endpoint: tsEP, Caller: id("ben", 100, "B"), CallerConf: lrn, ObjectTenant: "A", ObjectTenantKnown: true, MinRank: 10, MinRankKnown: true}, model.RelOtherTenant},
		{"caller empty tenant is other tenant", Input{Endpoint: tsEP, Caller: id("nobody", 100, ""), CallerConf: lrn, ObjectTenant: "A", ObjectTenantKnown: true, MinRank: 10, MinRankKnown: true}, model.RelOtherTenant},
		{"other tenant without min", Input{Endpoint: tsEP, Caller: id("ben", 10, "B"), CallerConf: lrn, ObjectTenant: "A", ObjectTenantKnown: true}, model.RelOtherTenant},
		{"star tenant is a member", Input{Endpoint: tsEP, Caller: id("root", 100, "*"), CallerConf: lrn, ObjectTenant: "A", ObjectTenantKnown: true, MinRank: 10, MinRankKnown: true}, model.RelOwner},
		{"min unknown", Input{Endpoint: tsEP, Caller: id("ann", 10, "A"), CallerConf: lrn, ObjectTenant: "A", ObjectTenantKnown: true}, model.RelUnknown},
		{"object tenant unknown", Input{Endpoint: tsEP, Caller: id("ann", 10, "A"), CallerConf: lrn, MinRank: 10, MinRankKnown: true}, model.RelUnknown},
		{"caller conf unknown", Input{Endpoint: tsEP, Caller: id("ann", 10, "A"), ObjectTenant: "A", ObjectTenantKnown: true, MinRank: 10, MinRankKnown: true}, model.RelUnknown},
		{"anonymous", Input{Endpoint: tsEP, Caller: &model.Identity{Anonymous: true}, ObjectTenant: "A", ObjectTenantKnown: true}, model.RelAnonymous},
		{"declared beats learned (below)", Input{Endpoint: declared, Caller: id("ann", 10, "A"), CallerConf: lrn, ObjectTenant: "A", ObjectTenantKnown: true, MinRank: 10, MinRankKnown: true}, model.RelLowerRole},
		{"declared without learned", Input{Endpoint: declared, Caller: id("adm", 100, "A"), CallerConf: lrn, ObjectTenant: "A", ObjectTenantKnown: true}, model.RelOwner},
		{"declared function below", Input{Endpoint: fnDeclared, Caller: id("ann", 10, ""), CallerConf: lrn, MinRank: 10, MinRankKnown: true}, model.RelLowerRole},
		{"declared function at", Input{Endpoint: fnDeclared, Caller: id("adm", 100, ""), CallerConf: lrn}, model.RelOwner},
		{"declared function above learned-high", Input{Endpoint: fnDeclared, Caller: id("adm", 200, ""), CallerConf: lrn, MinRank: 300, MinRankKnown: true}, model.RelHigherRole},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.in); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func TestMinRanksTenantScoped(t *testing.T) {
	mk := func(who *model.Identity, tenant string, known bool, status int) *model.Observation {
		o := ob(tsEP, who, model.ConfLearned, status)
		o.ObjectTenant, o.ObjectTenantKnown = tenant, known
		return o
	}
	obs := []*model.Observation{
		mk(id("adm", 100, "A"), "A", true, 200),
		mk(id("ann", 10, "A"), "A", true, 200), // min so far 10
		mk(id("ben", 5, "B"), "A", true, 200),  // other tenant 2xx: must not lower the min
		mk(id("low", 1, "A"), "A", true, 403),  // 4xx ignored
		mk(id("nop", 2, "A"), "", false, 200),  // object tenant unknown: ignored
		mk(id("root", 7, "*"), "A", true, 200), // wildcard tenant counts as a member
		mk(&model.Identity{Anonymous: true}, "A", true, 200),
	}
	if got := MinRanks(obs); len(got) != 1 || got[tsEP.ID] != 7 {
		t.Fatalf("got %v", got)
	}
	// Order independence.
	slices.Reverse(obs)
	if got := MinRanks(obs); got[tsEP.ID] != 7 {
		t.Fatalf("reversed: got %v", got)
	}
}
