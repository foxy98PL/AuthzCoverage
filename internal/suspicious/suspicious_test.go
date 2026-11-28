package suspicious

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"authzcov/internal/model"
)

var (
	alice = &model.Identity{Name: "alice", Role: "user", Tenant: "t1", Rank: 1}
	bob   = &model.Identity{Name: "bob", Role: "user", Tenant: "t2", Rank: 1}
	anon  = &model.Identity{Name: "anonymous", Anonymous: true}
)

func obj(rel model.Relationship, status int, method string, body string) *model.Observation {
	x := &model.Exchange{Source: "a.har#1", Method: method, Status: status}
	if body != "" {
		x.RespJSON = []byte(body)
	}
	return &model.Observation{
		X: x, Endpoint: &model.Endpoint{ID: method + " /b/{id}", Kind: model.ObjectLevel},
		Identity: bob, IDConf: model.ConfLearned, Owner: alice, OwnerConf: model.ConfLearned, Rel: rel,
	}
}

func TestFindRules(t *testing.T) {
	mod := func(f func(o *model.Observation)) func() *model.Observation {
		return func() *model.Observation {
			o := obj(model.RelSameRoleOtherUser, 200, "GET", `{"a":1}`)
			f(o)
			return o
		}
	}
	tests := []struct {
		name string
		o    func() *model.Observation
		want bool
	}{
		{"baseline", mod(func(*model.Observation) {}), true},
		{"function level", mod(func(o *model.Observation) { o.Endpoint.Kind = model.FunctionLevel }), false},
		{"owner rel", mod(func(o *model.Observation) { o.Rel = model.RelOwner }), false},
		{"higher role", mod(func(o *model.Observation) { o.Rel = model.RelHigherRole }), false},
		{"unknown rel", mod(func(o *model.Observation) { o.Rel = model.RelUnknown }), false},
		{"lower role", mod(func(o *model.Observation) { o.Rel = model.RelLowerRole }), true},
		{"other tenant", mod(func(o *model.Observation) { o.Rel = model.RelOtherTenant }), true},
		{"status 199", mod(func(o *model.Observation) { o.X.Status = 199 }), false},
		{"status 299", mod(func(o *model.Observation) { o.X.Status = 299 }), true},
		{"status 300", mod(func(o *model.Observation) { o.X.Status = 300 }), false},
		{"401", mod(func(o *model.Observation) { o.X.Status = 401 }), false},
		{"403", mod(func(o *model.Observation) { o.X.Status = 403 }), false},
		{"404", mod(func(o *model.Observation) { o.X.Status = 404 }), false},
		{"caller inferred", mod(func(o *model.Observation) { o.IDConf = model.ConfInferred }), false},
		{"caller unknown", mod(func(o *model.Observation) { o.IDConf = model.ConfUnknown }), false},
		{"caller declared", mod(func(o *model.Observation) { o.IDConf = model.ConfDeclared }), true},
		{"anonymous with learned owner", mod(func(o *model.Observation) {
			o.Rel, o.Identity, o.IDConf = model.RelAnonymous, anon, model.ConfUnknown
		}), true},
		{"anonymous without owner", mod(func(o *model.Observation) {
			o.Rel, o.Identity, o.IDConf, o.Owner = model.RelAnonymous, anon, model.ConfUnknown, nil
		}), false},
		{"owner nil", mod(func(o *model.Observation) { o.Owner = nil }), false},
		{"owner inferred", mod(func(o *model.Observation) { o.OwnerConf = model.ConfInferred }), false},
		{"owner unknown conf", mod(func(o *model.Observation) { o.OwnerConf = model.ConfUnknown }), false},
		{"owner learned", mod(func(o *model.Observation) { o.OwnerConf = model.ConfLearned }), true},
		{"other_tenant by param, no owner", mod(func(o *model.Observation) {
			o.Rel, o.Owner, o.OwnerConf, o.ObjectTenantKnown, o.ObjectTenant = model.RelOtherTenant, nil, model.ConfUnknown, true, "t1"
		}), true},
		{"other_tenant by param but caller inferred", mod(func(o *model.Observation) {
			o.Rel, o.Owner, o.ObjectTenantKnown, o.IDConf = model.RelOtherTenant, nil, true, model.ConfInferred
		}), false},
		{"same_role with tenant known but no owner", mod(func(o *model.Observation) {
			o.Owner, o.ObjectTenantKnown = nil, true
		}), false},
		{"other_tenant without param, no owner", mod(func(o *model.Observation) {
			o.Rel, o.Owner = model.RelOtherTenant, nil
		}), false},
		{"GET nil body", mod(func(o *model.Observation) { o.X.RespJSON = nil }), false},
		{"GET []", mod(func(o *model.Observation) { o.X.RespJSON = []byte("[]") }), false},
		{"GET {}", mod(func(o *model.Observation) { o.X.RespJSON = []byte("{}") }), false},
		{"GET null", mod(func(o *model.Observation) { o.X.RespJSON = []byte("null") }), false},
		{"GET padded {}", mod(func(o *model.Observation) { o.X.RespJSON = []byte("  {} \n") }), false},
		{"GET empty string json", mod(func(o *model.Observation) { o.X.RespJSON = []byte(`""`) }), false},
		{"GET whitespace only", mod(func(o *model.Observation) { o.X.RespJSON = []byte(" \n") }), false},
		{"GET empty slice", mod(func(o *model.Observation) { o.X.RespJSON = []byte{} }), false},
		{"GET 204", mod(func(o *model.Observation) { o.X.Status = 204; o.X.RespJSON = []byte(`{"a":1}`) }), false},
		{"HEAD nil body", mod(func(o *model.Observation) { o.X.Method = "HEAD"; o.X.RespJSON = nil }), false},
		{"HEAD with body", mod(func(o *model.Observation) { o.X.Method = "HEAD" }), true},
		{"DELETE 204", mod(func(o *model.Observation) { o.X.Method, o.X.Status, o.X.RespJSON = "DELETE", 204, nil }), true},
		{"PUT 200 nil body", mod(func(o *model.Observation) { o.X.Method, o.X.RespJSON = "PUT", nil }), true},
		{"POST 201", mod(func(o *model.Observation) { o.X.Method, o.X.Status, o.X.RespJSON = "POST", 201, nil }), true},
		{"PATCH 401", mod(func(o *model.Observation) { o.X.Method, o.X.Status = "PATCH", 401 }), false},
		{"nil exchange", mod(func(o *model.Observation) { o.X = nil }), false},
		{"nil identity", mod(func(o *model.Observation) { o.Identity = nil }), false},
		{"nil endpoint", mod(func(o *model.Observation) { o.Endpoint = nil }), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Find([]*model.Observation{tc.o(), nil})
			if (len(got) == 1) != tc.want {
				t.Fatalf("Find = %+v, want finding=%v", got, tc.want)
			}
		})
	}
}

func TestMessages(t *testing.T) {
	o := obj(model.RelSameRoleOtherUser, 200, "GET", `{"a":1}`)
	got := Find([]*model.Observation{o})
	if len(got) != 1 || got[0].Message != "bob received 200 for an object owned by alice" ||
		got[0].Endpoint != "GET /b/{id}" || got[0].Relationship != "same_role_other_user" ||
		got[0].Count != 1 || !reflect.DeepEqual(got[0].Evidence, []string{"a.har#1"}) {
		t.Fatalf("got %+v", got)
	}
	ot := obj(model.RelOtherTenant, 200, "GET", `{"a":1}`)
	ot.Owner, ot.OwnerConf, ot.ObjectTenantKnown, ot.ObjectTenant = nil, model.ConfUnknown, true, "t1"
	got = Find([]*model.Observation{ot})
	if len(got) != 1 || got[0].Message != "bob (tenant t2) received 200 for an object in tenant t1" {
		t.Fatalf("got %+v", got)
	}
	an := obj(model.RelAnonymous, 200, "GET", `{"a":1}`)
	an.Identity, an.IDConf = anon, model.ConfUnknown
	got = Find([]*model.Observation{an})
	if len(got) != 1 || got[0].Message != "anonymous received 200 for an object owned by alice" {
		t.Fatalf("got %+v", got)
	}
}

func TestAggregation(t *testing.T) {
	var obs []*model.Observation
	for i := 12; i >= 1; i-- { // reversed, more than 5, with numeric sort traps (2 < 10)
		o := obj(model.RelSameRoleOtherUser, 200, "GET", `{"a":1}`)
		o.X.Source = fmt.Sprintf("a.har#%d", i)
		obs = append(obs, o)
	}
	dup := obj(model.RelSameRoleOtherUser, 200, "GET", `{"a":1}`)
	dup.X.Source = "a.har#3"
	obs = append(obs, dup)
	other := obj(model.RelLowerRole, 200, "GET", `{"a":1}`)
	obs = append(obs, other)
	got := Find(obs)
	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %+v", got)
	}
	var same Allow
	for _, a := range got {
		if a.Relationship == "same_role_other_user" {
			same = a
		}
	}
	if same.Count != 13 {
		t.Errorf("Count = %d, want 13", same.Count)
	}
	if !strings.HasSuffix(same.Message, " (and 12 more)") {
		t.Errorf("message = %q", same.Message)
	}
	if !strings.HasPrefix(same.Message, "bob received 200 for an object owned by alice") {
		t.Errorf("message = %q", same.Message)
	}
	want := []string{"a.har#1", "a.har#2", "a.har#3", "a.har#4", "a.har#5"}
	if !reflect.DeepEqual(same.Evidence, want) {
		t.Errorf("evidence = %v, want %v", same.Evidence, want)
	}

	three := []*model.Observation{}
	for i := 3; i >= 1; i-- {
		o := obj(model.RelSameRoleOtherUser, 200, "GET", `{"a":1}`)
		o.X.Source = fmt.Sprintf("a.har#%d", i)
		three = append(three, o)
	}
	g := Find(three)
	if len(g) != 1 || g[0].Count != 3 || !strings.HasSuffix(g[0].Message, " (and 2 more)") {
		t.Fatalf("got %+v", g)
	}
	// first example in evidence order (#1) names the message
	if !reflect.DeepEqual(g[0].Evidence, []string{"a.har#1", "a.har#2", "a.har#3"}) {
		t.Errorf("evidence %v", g[0].Evidence)
	}
}

func TestMessageUsesFirstEvidenceExample(t *testing.T) {
	a := obj(model.RelSameRoleOtherUser, 200, "GET", `{"a":1}`)
	a.X.Source, a.Identity = "a.har#2", &model.Identity{Name: "zed", Role: "user"}
	b := obj(model.RelSameRoleOtherUser, 200, "GET", `{"a":1}`)
	b.X.Source = "a.har#1"
	g := Find([]*model.Observation{a, b})
	if g[0].Message != "bob received 200 for an object owned by alice (and 1 more)" {
		t.Fatalf("msg %q", g[0].Message)
	}
}

func TestOrderIndependence(t *testing.T) {
	var obs []*model.Observation
	for i := 0; i < 8; i++ {
		for _, rel := range []model.Relationship{model.RelSameRoleOtherUser, model.RelLowerRole, model.RelOtherTenant} {
			o := obj(rel, 200, "GET", `{"a":1}`)
			o.Endpoint = &model.Endpoint{ID: fmt.Sprintf("GET /e%d/{id}", i%3), Kind: model.ObjectLevel}
			o.X.Source = fmt.Sprintf("a.har#%d", i*3+len(rel))
			if i%2 == 0 {
				o.Identity = &model.Identity{Name: fmt.Sprintf("u%d", i), Role: "user"}
			}
			obs = append(obs, o)
		}
	}
	want := Find(obs)
	if len(want) == 0 {
		t.Fatal("no findings")
	}
	r := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic shuffle in a test
	for i := 0; i < 50; i++ {
		sh := append([]*model.Observation(nil), obs...)
		r.Shuffle(len(sh), func(a, b int) { sh[a], sh[b] = sh[b], sh[a] })
		if got := Find(sh); !reflect.DeepEqual(got, want) {
			t.Fatalf("shuffle %d differs:\n%+v\n%+v", i, got, want)
		}
	}
	for i := 1; i < len(want); i++ {
		a, b := want[i-1], want[i]
		if a.Endpoint > b.Endpoint || (a.Endpoint == b.Endpoint && a.Relationship >= b.Relationship) {
			t.Fatalf("not sorted: %v then %v", a, b)
		}
	}
}

func TestFindEmpty(t *testing.T) {
	if got := Find(nil); got == nil || len(got) != 0 {
		t.Fatalf("got %#v, want empty non-nil", got)
	}
}

// Review KAN-88 F3, F4, R3.
func TestReviewFixes(t *testing.T) {
	// F3: an anonymous identity under a non-anonymous relationship is ignored.
	o := obj(model.RelSameRoleOtherUser, 200, "GET", `{"a":1}`)
	o.Identity, o.IDConf = anon, model.ConfUnknown
	if got := Find([]*model.Observation{o}); len(got) != 0 {
		t.Errorf("anonymous under same_role_other_user flagged: %+v", got)
	}
	// F4: tenant mismatch plus a learned owner names both.
	ot := obj(model.RelOtherTenant, 200, "GET", `{"a":1}`)
	ot.ObjectTenantKnown, ot.ObjectTenant = true, "t1"
	got := Find([]*model.Observation{ot})
	if len(got) != 1 || got[0].Message != "bob (tenant t2) received 200 for an object owned by alice in tenant t1" {
		t.Fatalf("got %+v", got)
	}
	// R3: messages carry names and status only, never the object ID or body.
	id := obj(model.RelSameRoleOtherUser, 200, "GET", `{"secret":"s3cr3t-value"}`)
	id.X.Path = "/b/obj-9f8e7d6c5b4a"
	id.Params = map[string]string{"id": "obj-9f8e7d6c5b4a"}
	m := Find([]*model.Observation{id})[0].Message
	if strings.Contains(m, "obj-9f8e7d6c5b4a") || strings.Contains(m, "s3cr3t") || strings.Contains(m, "/b/") {
		t.Errorf("message leaks request data: %q", m)
	}
}

func fnObs(ep *model.Endpoint, rel model.Relationship, who *model.Identity, idc model.Confidence, status int) *model.Observation {
	return &model.Observation{
		X:        &model.Exchange{Source: "a.har#1", Method: "GET", Status: status, RespJSON: []byte(`{"a":1}`)},
		Endpoint: ep, Identity: who, IDConf: idc, Rel: rel,
	}
}

func TestFindFunctionLevelAndTenantScoped(t *testing.T) {
	fn := func(auth bool) *model.Endpoint {
		return &model.Endpoint{ID: "GET /admin", Kind: model.FunctionLevel, AuthRequired: auth}
	}
	ts := func(auth bool) *model.Endpoint {
		return &model.Endpoint{ID: "GET /orgs/{orgId}/customers", Kind: model.ObjectLevel, ObjectParam: "orgId", TenantScoped: true, AuthRequired: auth}
	}
	minAdmin := func(e *model.Endpoint) *model.Endpoint {
		e.MinRankDeclared, e.MinRank, e.MinRole = true, 100, "admin"
		return e
	}
	cust := &model.Identity{Name: "ann", Role: "customer", Rank: 10, Tenant: "A"}
	tests := []struct {
		name string
		o    *model.Observation
		want bool
	}{
		{"fn anonymous 200 auth required", fnObs(fn(true), model.RelAnonymous, anon, model.ConfDeclared, 200), true},
		{"fn anonymous 200 public", fnObs(fn(false), model.RelAnonymous, anon, model.ConfDeclared, 200), false},
		{"fn anonymous 401 auth required", fnObs(fn(true), model.RelAnonymous, anon, model.ConfDeclared, 401), false},
		{"fn anonymous 204 write", func() *model.Observation {
			o := fnObs(fn(true), model.RelAnonymous, anon, model.ConfDeclared, 204)
			o.X.Method, o.X.RespJSON = "DELETE", nil
			return o
		}(), true},
		{"fn anonymous empty body GET", func() *model.Observation {
			o := fnObs(fn(true), model.RelAnonymous, anon, model.ConfDeclared, 200)
			o.X.RespJSON = []byte(`[]`)
			return o
		}(), false},
		{"ts anonymous 200 auth required", fnObs(ts(true), model.RelAnonymous, anon, model.ConfDeclared, 200), true},
		{"ts anonymous 200 public", fnObs(ts(false), model.RelAnonymous, anon, model.ConfDeclared, 200), false},
		{"fn lower_role 200 without declaration", fnObs(fn(true), model.RelLowerRole, cust, model.ConfLearned, 200), false},
		{"fn lower_role 200 declared", fnObs(minAdmin(fn(true)), model.RelLowerRole, cust, model.ConfLearned, 200), true},
		{"fn lower_role 403 declared", fnObs(minAdmin(fn(true)), model.RelLowerRole, cust, model.ConfLearned, 403), false},
		{"fn lower_role declared inferred caller", fnObs(minAdmin(fn(true)), model.RelLowerRole, cust, model.ConfInferred, 200), false},
		{"fn lower_role declared public spec", fnObs(minAdmin(fn(false)), model.RelLowerRole, cust, model.ConfLearned, 200), true},
		{"ts lower_role 200 declared", fnObs(minAdmin(ts(true)), model.RelLowerRole, cust, model.ConfLearned, 200), true},
		{"ts lower_role 200 learned only", fnObs(ts(true), model.RelLowerRole, cust, model.ConfLearned, 200), false},
		{"fn owner 200", fnObs(minAdmin(fn(true)), model.RelOwner, cust, model.ConfLearned, 200), false},
		{"fn same_role_other_user", fnObs(fn(true), model.RelSameRoleOtherUser, cust, model.ConfLearned, 200), false},
	}
	for _, tc := range tests {
		got := Find([]*model.Observation{tc.o})
		if (len(got) == 1) != tc.want {
			t.Errorf("%s: got %v, want finding=%v", tc.name, got, tc.want)
		}
	}
	got := Find([]*model.Observation{fnObs(fn(true), model.RelAnonymous, anon, model.ConfDeclared, 200)})
	if len(got) != 1 || got[0].Endpoint != "GET /admin" || got[0].Relationship != "anonymous" || got[0].Count != 1 ||
		!strings.Contains(got[0].Message, "anonymous") || !strings.Contains(got[0].Message, "200") {
		t.Errorf("shape: %+v", got)
	}
	got = Find([]*model.Observation{fnObs(minAdmin(fn(true)), model.RelLowerRole, cust, model.ConfLearned, 200)})
	if len(got) != 1 || got[0].Relationship != "lower_role" || !strings.Contains(got[0].Message, "ann") || !strings.Contains(got[0].Message, "admin") {
		t.Errorf("lower_role message: %+v", got)
	}
	// Object-level anonymous behaviour is unchanged: no owner, no finding.
	o := obj(model.RelAnonymous, 200, "GET", `{"a":1}`)
	o.Identity, o.IDConf, o.Owner = anon, model.ConfUnknown, nil
	o.Endpoint.AuthRequired = true
	if got := Find([]*model.Observation{o}); len(got) != 0 {
		t.Errorf("object-level anonymous without owner: %v", got)
	}
}

func TestFindDeclaredEdges(t *testing.T) {
	minAdmin := &model.Endpoint{ID: "GET /admin", Kind: model.FunctionLevel, AuthRequired: true, MinRankDeclared: true, MinRank: 100, MinRole: "admin"}
	// Unknown caller 2xx: never a finding.
	for _, rel := range []model.Relationship{model.RelLowerRole, model.RelAnonymous, model.RelUnknown} {
		o := fnObs(minAdmin, rel, &model.Identity{Name: "unknown-1"}, model.ConfUnknown, 200)
		if got := Find([]*model.Observation{o}); len(got) != 0 {
			t.Errorf("unknown caller rel=%s: %v", rel, got)
		}
	}
	// No security anywhere in the spec: anonymous 2xx on a function-level endpoint is fine.
	pub := &model.Endpoint{ID: "GET /health", Kind: model.FunctionLevel}
	if got := Find([]*model.Observation{fnObs(pub, model.RelAnonymous, anon, model.ConfDeclared, 200)}); len(got) != 0 {
		t.Errorf("public endpoint: %v", got)
	}
}

func TestFindTenantScopedOtherTenantMessage(t *testing.T) {
	ts := &model.Endpoint{ID: "GET /orgs/{orgId}/customers", Kind: model.ObjectLevel, ObjectParam: "orgId", TenantScoped: true}
	o := fnObs(ts, model.RelOtherTenant, &model.Identity{Name: "ben", Tenant: "B", Rank: 10}, model.ConfLearned, 200)
	o.ObjectTenantKnown, o.ObjectTenant = true, "A"
	o.Owner, o.OwnerConf = alice, model.ConfLearned // a stray owner must not leak into the message
	got := Find([]*model.Observation{o})
	if len(got) != 1 {
		t.Fatalf("got %v", got)
	}
	if want := "ben (tenant B) received 200 for tenant A"; !strings.Contains(got[0].Message, want) || strings.Contains(got[0].Message, "owned by") {
		t.Errorf("message %q, want %q and no \"owned by\"", got[0].Message, want)
	}
}

// KAN-102: a list-learned owner (exclusive rule) is Learned and yields a
// finding; a plain list owner stays Inferred and yields none.
func TestFindListOwnerConfidence(t *testing.T) {
	for conf, want := range map[model.Confidence]bool{model.ConfLearned: true, model.ConfInferred: false} {
		o := obj(model.RelSameRoleOtherUser, 200, "GET", `{"a":1}`)
		o.OwnerConf = conf
		if got := len(Find([]*model.Observation{o})) > 0; got != want {
			t.Errorf("owner conf %s: finding=%v, want %v", conf, got, want)
		}
	}
}
