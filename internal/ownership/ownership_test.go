package ownership

import (
	"slices"
	"testing"

	"authzcov/internal/model"
)

var (
	alice = &model.Identity{Name: "alice", Subject: "sub-a", Rank: 1}
	bob   = &model.Identity{Name: "bob", Subject: "sub-b", Rank: 1}
	anon  = &model.Identity{Name: "anon", Anonymous: true}

	getEP = &model.Endpoint{ID: "GET /books/{id}", Method: "GET", Template: "/books/{id}",
		ObjectParam: "id", Resource: "books", Kind: model.ObjectLevel}
	userEP = &model.Endpoint{ID: "GET /users/{sub}", Method: "GET", Template: "/users/{sub}",
		ObjectParam: "sub", Resource: "users", Kind: model.ObjectLevel}
	postEP = &model.Endpoint{ID: "POST /books", Method: "POST", Template: "/books", Kind: model.FunctionLevel}
)

func create(who *model.Identity, conf model.Confidence, status int, body string) *model.Observation {
	return &model.Observation{Endpoint: postEP, Identity: who, IDConf: conf,
		X: &model.Exchange{Method: "POST", Path: "/books", Status: status, ReqJSON: []byte(body)}}
}

func read(who *model.Identity, ep *model.Endpoint, param, val string) *model.Observation {
	return &model.Observation{Endpoint: ep, Identity: who, IDConf: model.ConfLearned,
		Params: map[string]string{param: val}, X: &model.Exchange{Method: "GET", Status: 200}}
}

func cfg() Config {
	return Config{
		SelfParams: map[string]string{"sub": "subject"},
		Create:     []CreateRule{{Method: "POST", Path: "/books", Resource: "books", IDField: "title"}},
	}
}

func expect(t *testing.T, r *Registry, o *model.Observation, want *model.Identity, conf model.Confidence) {
	t.Helper()
	got, c := r.Owner(o)
	if got != want || c != conf {
		t.Fatalf("got (%v,%s) want (%v,%s)", got, c, want, conf)
	}
}

func TestSelfParamOwnDeclared(t *testing.T) {
	r := New(cfg())
	expect(t, r, read(alice, userEP, "sub", "sub-a"), alice, model.ConfDeclared)
}

func TestSelfParamOtherLearned(t *testing.T) {
	r := New(cfg())
	r.Learn(read(bob, userEP, "sub", "sub-b"))
	expect(t, r, read(alice, userEP, "sub", "sub-b"), bob, model.ConfLearned)
}

func TestSelfParamUnseenUnknown(t *testing.T) {
	r := New(cfg())
	r.Learn(read(alice, userEP, "sub", "sub-a"))
	expect(t, r, read(alice, userEP, "sub", "sub-zzz"), nil, model.ConfUnknown)
}

func TestSelfParamSubjectConflict(t *testing.T) {
	r := New(cfg())
	r.Learn(read(&model.Identity{Name: "x", Subject: "s"}, userEP, "sub", "s"))
	r.Learn(read(&model.Identity{Name: "y", Subject: "s"}, userEP, "sub", "s"))
	expect(t, r, read(alice, userEP, "sub", "s"), nil, model.ConfUnknown)
}

func TestSubjectIgnoresAnonAndLowConf(t *testing.T) {
	r := New(cfg())
	r.Learn(read(&model.Identity{Name: "anon", Subject: "s", Anonymous: true}, userEP, "sub", "s"))
	o := read(bob, userEP, "sub", "q")
	o.IDConf = model.ConfInferred
	o.Identity = &model.Identity{Name: "inf", Subject: "q"}
	r.Learn(o)
	expect(t, r, read(alice, userEP, "sub", "s"), nil, model.ConfUnknown)
	expect(t, r, read(alice, userEP, "sub", "q"), nil, model.ConfUnknown)
}

func TestCreateLearnedThenReadByOther(t *testing.T) {
	r := New(cfg())
	r.Learn(create(alice, model.ConfLearned, 201, `{"title":"t1"}`))
	expect(t, r, read(bob, getEP, "id", "t1"), alice, model.ConfLearned)
	expect(t, r, read(bob, getEP, "id", "other"), nil, model.ConfUnknown)
}

func TestCreateNotLearned(t *testing.T) {
	tests := []struct {
		name string
		o    *model.Observation
	}{
		{"4xx", create(alice, model.ConfLearned, 400, `{"title":"t1"}`)},
		{"3xx", create(alice, model.ConfLearned, 302, `{"title":"t1"}`)},
		{"unknown identity", create(alice, model.ConfUnknown, 201, `{"title":"t1"}`)},
		{"inferred identity", create(alice, model.ConfInferred, 201, `{"title":"t1"}`)},
		{"anonymous", create(anon, model.ConfDeclared, 201, `{"title":"t1"}`)},
		{"nil identity", create(nil, model.ConfDeclared, 201, `{"title":"t1"}`)},
		{"malformed json", create(alice, model.ConfLearned, 201, `{"title":`)},
		{"empty body", create(alice, model.ConfLearned, 201, ``)},
		{"bool leaf", create(alice, model.ConfLearned, 201, `{"title":true}`)},
		{"object leaf", create(alice, model.ConfLearned, 201, `{"title":{"a":1}}`)},
		{"missing field", create(alice, model.ConfLearned, 201, `{"x":"t1"}`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := New(cfg())
			r.Learn(tc.o)
			expect(t, r, read(bob, getEP, "id", "t1"), nil, model.ConfUnknown)
		})
	}
}

func TestCreateMatchesByTemplateOrPath(t *testing.T) {
	c := cfg()
	c.Create[0].Path = "/other"
	r := New(c)
	r.Learn(create(alice, model.ConfLearned, 201, `{"title":"t1"}`)) // neither matches
	expect(t, r, read(bob, getEP, "id", "t1"), nil, model.ConfUnknown)
	o := create(alice, model.ConfLearned, 201, `{"title":"t1"}`)
	o.Endpoint = &model.Endpoint{Template: "/other"}
	r.Learn(o)
	expect(t, r, read(bob, getEP, "id", "t1"), alice, model.ConfLearned)
}

func TestResourcesOverride(t *testing.T) {
	c := cfg()
	c.Resources = map[string]string{"id": "books"}
	ep := &model.Endpoint{ID: "GET /v1/{id}", ObjectParam: "id", Resource: "v1", Kind: model.ObjectLevel}
	r := New(c)
	if got := r.ResourceOf(ep); got != "books" {
		t.Fatalf("ResourceOf = %q", got)
	}
	r.Learn(create(alice, model.ConfLearned, 201, `{"title":"t1"}`))
	expect(t, r, read(bob, ep, "id", "t1"), alice, model.ConfLearned)
	// Without the override the resource is "v1" and nothing is found.
	r2 := New(cfg())
	r2.Learn(create(alice, model.ConfLearned, 201, `{"title":"t1"}`))
	if got := r2.ResourceOf(ep); got != "v1" {
		t.Fatalf("ResourceOf = %q", got)
	}
	expect(t, r2, read(bob, ep, "id", "t1"), nil, model.ConfUnknown)
}

func TestConflictEqualConfUnknownSticky(t *testing.T) {
	r := New(cfg())
	r.Learn(create(alice, model.ConfLearned, 201, `{"title":"t1"}`))
	r.Learn(create(bob, model.ConfLearned, 201, `{"title":"t1"}`))
	expect(t, r, read(alice, getEP, "id", "t1"), nil, model.ConfUnknown)
	r.Learn(create(alice, model.ConfLearned, 201, `{"title":"t1"}`))
	expect(t, r, read(alice, getEP, "id", "t1"), nil, model.ConfUnknown)
}

func TestConflictSameOwnerNoConflict(t *testing.T) {
	r := New(cfg())
	r.Learn(create(alice, model.ConfLearned, 201, `{"title":"t1"}`))
	r.Learn(create(alice, model.ConfLearned, 201, `{"title":"t1"}`))
	expect(t, r, read(bob, getEP, "id", "t1"), alice, model.ConfLearned)
}

func TestHigherConfWins(t *testing.T) {
	r := New(cfg())
	r.mergeOwner(key{"books", "t1"}, claim{id: alice, conf: model.ConfLearned})
	r.mergeOwner(key{"books", "t1"}, claim{id: bob, conf: model.ConfLearned}) // conflict
	r.mergeOwner(key{"books", "t1"}, claim{id: bob, conf: model.ConfDeclared})
	expect(t, r, read(alice, getEP, "id", "t1"), bob, model.ConfDeclared)
	r.mergeOwner(key{"books", "t1"}, claim{id: alice, conf: model.ConfLearned}) // lower ignored
	expect(t, r, read(alice, getEP, "id", "t1"), bob, model.ConfDeclared)
}

func TestIDFieldNestedAndNumeric(t *testing.T) {
	c := cfg()
	c.Create = []CreateRule{
		{Method: "POST", Path: "/books", Resource: "books", IDField: "data.title"},
		{Method: "POST", Path: "/books", Resource: "nums", IDField: "n"},
	}
	r := New(c)
	r.Learn(create(alice, model.ConfLearned, 200, `{"data":{"title":"deep"},"n":42}`))
	expect(t, r, read(bob, getEP, "id", "deep"), alice, model.ConfLearned)
	ep := &model.Endpoint{ObjectParam: "id", Resource: "nums", Kind: model.ObjectLevel}
	expect(t, r, read(bob, ep, "id", "42"), alice, model.ConfLearned)
}

func TestOwnerBadInput(t *testing.T) {
	r := New(cfg())
	r.Learn(nil)
	r.Learn(&model.Observation{})
	expect(t, r, nil, nil, model.ConfUnknown)
	expect(t, r, &model.Observation{}, nil, model.ConfUnknown)
	expect(t, r, read(alice, postEP, "id", "x"), nil, model.ConfUnknown)
	expect(t, r, read(alice, getEP, "id", ""), nil, model.ConfUnknown)
	if r.ResourceOf(nil) != "" {
		t.Fatal("nil endpoint")
	}
}

func TestOrderIndependence(t *testing.T) {
	obs := []*model.Observation{
		create(alice, model.ConfLearned, 201, `{"title":"t1"}`),
		create(bob, model.ConfLearned, 201, `{"title":"t2"}`),
		create(bob, model.ConfLearned, 201, `{"title":"t1"}`), // conflicts with alice
		create(alice, model.ConfLearned, 500, `{"title":"t3"}`),
		read(alice, userEP, "sub", "sub-a"),
		read(bob, userEP, "sub", "sub-b"),
	}
	queries := []*model.Observation{
		read(bob, getEP, "id", "t1"), read(bob, getEP, "id", "t2"), read(bob, getEP, "id", "t3"),
		read(alice, userEP, "sub", "sub-b"), read(bob, userEP, "sub", "sub-a"),
	}
	fwd, rev := New(cfg()), New(cfg())
	for i := range obs {
		fwd.Learn(obs[i])
		rev.Learn(obs[len(obs)-1-i])
	}
	for i, q := range queries {
		a, ac := fwd.Owner(q)
		b, bc := rev.Owner(q)
		if a != b || ac != bc {
			t.Fatalf("query %d differs: (%v,%s) vs (%v,%s)", i, a, ac, b, bc)
		}
	}
	expect(t, fwd, queries[0], nil, model.ConfUnknown)
	expect(t, fwd, queries[1], bob, model.ConfLearned)
}

func TestJSONValues(t *testing.T) {
	tests := []struct {
		name, body, path string
		want             []string
	}{
		{"nested array", `{"books":[{"t":"a"},{"t":"b"},{"x":"c"}]}`, "books[].t", []string{"a", "b"}},
		{"top-level array", `[{"id":1},{"id":"two"}]`, "[].id", []string{"1", "two"}},
		{"deep", `{"data":{"items":[{"id":"x"}]}}`, "data.items[].id", []string{"x"}},
		{"array of scalars", `{"ids":["a","b",""]}`, "ids[]", []string{"a", "b"}},
		{"plain field", `{"a":{"b":"v"}}`, "a.b", []string{"v"}},
		{"nested arrays", `{"g":[{"i":[{"id":"1"},{"id":"2"}]},{"i":[{"id":"3"}]}]}`, "g[].i[].id", []string{"1", "2", "3"}},
		{"missing", `{"a":1}`, "b[].id", nil},
		{"not array", `{"b":{"id":"x"}}`, "b[].id", nil},
		{"object leaf", `{"b":[{"id":{"k":1}}]}`, "b[].id", nil},
		{"bool leaf", `{"b":[{"id":true}]}`, "b[].id", nil},
		{"empty body", ``, "b[].id", nil},
		{"bad json", `{`, "b", nil},
		{"empty path", `{"a":"b"}`, "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := jsonValues([]byte(tc.body), tc.path)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func listObs(who *model.Identity, conf model.Confidence, status int, body string) *model.Observation {
	return &model.Observation{Endpoint: listEP, Identity: who, IDConf: conf,
		X: &model.Exchange{Method: "GET", Path: "/books", Status: status, RespJSON: []byte(body)}}
}

var listEP = &model.Endpoint{ID: "GET /books", Method: "GET", Template: "/books", Kind: model.FunctionLevel}

func listCfg() Config {
	return Config{Lists: []ListRule{{Method: "GET", Path: "/books", Resource: "books", IDsPath: "items[].id"}}}
}

func TestLearnFromLists(t *testing.T) {
	r := New(listCfg())
	r.Learn(listObs(alice, model.ConfLearned, 200, `{"items":[{"id":"a1"},{"id":"a2"}]}`))
	expect(t, r, read(alice, getEP, "id", "a1"), alice, model.ConfInferred)
	expect(t, r, read(bob, getEP, "id", "a2"), alice, model.ConfInferred)
	expect(t, r, read(bob, getEP, "id", "zz"), nil, model.ConfUnknown)
}

func TestLearnFromListsIgnored(t *testing.T) {
	body := `{"items":[{"id":"a1"}]}`
	for name, o := range map[string]*model.Observation{
		"non-2xx":      listObs(alice, model.ConfLearned, 403, body),
		"inferred id":  listObs(alice, model.ConfInferred, 200, body),
		"anonymous":    listObs(anon, model.ConfDeclared, 200, body),
		"nil response": listObs(alice, model.ConfLearned, 200, ""),
		"wrong method": {Endpoint: listEP, Identity: alice, IDConf: model.ConfLearned, X: &model.Exchange{Method: "POST", Path: "/books", Status: 200, RespJSON: []byte(body)}},
		"wrong path":   {Endpoint: &model.Endpoint{ID: "GET /other", Template: "/other"}, Identity: alice, IDConf: model.ConfLearned, X: &model.Exchange{Method: "GET", Path: "/other", Status: 200, RespJSON: []byte(body)}},
	} {
		r := New(listCfg())
		r.Learn(o)
		if got, c := r.Owner(read(alice, getEP, "id", "a1")); got != nil || c != model.ConfUnknown {
			t.Errorf("%s: owner (%v,%s), want unknown", name, got, c)
		}
	}
}

func TestListsConflictAndPrecedence(t *testing.T) {
	body := `{"items":[{"id":"x"}]}`
	a, b := listObs(alice, model.ConfLearned, 200, body), listObs(bob, model.ConfLearned, 200, body)
	for _, order := range [][]*model.Observation{{a, b}, {b, a}} {
		r := New(listCfg())
		for _, o := range order {
			r.Learn(o)
		}
		expect(t, r, read(alice, getEP, "id", "x"), nil, model.ConfUnknown)
	}
	// A learned create outranks an inferred list claim in either order.
	cfg := listCfg()
	cfg.Create = []CreateRule{{Method: "POST", Path: "/books", Resource: "books", IDField: "title"}}
	for _, order := range [][]*model.Observation{
		{listObs(alice, model.ConfLearned, 200, body), create(bob, model.ConfLearned, 200, `{"title":"x"}`)},
		{create(bob, model.ConfLearned, 200, `{"title":"x"}`), listObs(alice, model.ConfLearned, 200, body)},
	} {
		r := New(cfg)
		for _, o := range order {
			r.Learn(o)
		}
		expect(t, r, read(alice, getEP, "id", "x"), bob, model.ConfLearned)
	}
}

func TestObjects(t *testing.T) {
	c := cfg()
	c.Lists = []ListRule{{Method: "GET", Path: "/mine", Resource: "books", IDsPath: "ids[]"}}
	r := New(c)
	r.Learn(create(alice, model.ConfLearned, 200, `{"title":"b2"}`))
	r.Learn(create(bob, model.ConfLearned, 200, `{"title":"b1"}`))
	// conflicting equal-confidence claims on b3 drop the object.
	r.Learn(create(alice, model.ConfLearned, 200, `{"title":"b3"}`))
	r.Learn(create(bob, model.ConfLearned, 200, `{"title":"b3"}`))
	listEP := &model.Endpoint{ID: "GET /mine", Method: "GET", Template: "/mine", Kind: model.FunctionLevel}
	r.Learn(&model.Observation{Endpoint: listEP, Identity: alice, IDConf: model.ConfLearned,
		X: &model.Exchange{Method: "GET", Path: "/mine", Status: 200, RespJSON: []byte(`{"ids":["b9"]}`)}})

	type row struct {
		res, id, owner, source string
		conf                   model.Confidence
	}
	var got []row
	for _, o := range r.Objects() {
		got = append(got, row{o.Resource, o.ID, o.Owner.Name, o.Source, o.Conf})
	}
	want := []row{
		{"books", "b1", "bob", SourceCreate, model.ConfLearned},
		{"books", "b2", "alice", SourceCreate, model.ConfLearned},
		{"books", "b9", "alice", SourceList, model.ConfInferred},
		{SubjectResource, "sub-a", "alice", SourceSelf, model.ConfLearned},
		{SubjectResource, "sub-b", "bob", SourceSelf, model.ConfLearned},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Objects() = %v\nwant %v", got, want)
	}
	if len(New(Config{}).Objects()) != 0 {
		t.Error("empty registry should list no objects")
	}
}

func respCreate(who *model.Identity, conf model.Confidence, status int, body string) *model.Observation {
	return &model.Observation{Endpoint: postEP, Identity: who, IDConf: conf,
		X: &model.Exchange{Method: "POST", Path: "/books", Status: status, RespJSON: []byte(body)}}
}

func books(r *Registry) []Object {
	var out []Object
	for _, o := range r.Objects() {
		if o.Resource == "books" {
			out = append(out, o)
		}
	}
	return out
}

func respCfg() Config {
	return Config{Create: []CreateRule{{Method: "POST", Path: "/books", Resource: "books", IDFromResponse: "id"}}}
}

// Rule 1.
func TestCreateResponseLearned(t *testing.T) {
	r := New(respCfg())
	r.Learn(respCreate(alice, model.ConfLearned, 201, `{"id":"b1"}`))
	r.Learn(respCreate(alice, model.ConfLearned, 201, `{"id":42}`))
	expect(t, r, read(bob, getEP, "id", "b1"), alice, model.ConfLearned)
	expect(t, r, read(bob, getEP, "id", "42"), alice, model.ConfLearned)
	r2 := New(respCfg())
	r2.Learn(respCreate(alice, model.ConfInferred, 201, `{"id":"b1"}`))
	expect(t, r2, read(bob, getEP, "id", "b1"), nil, model.ConfUnknown)
}

// Rules 2 and 3.
func TestCreateResponseNotLearned(t *testing.T) {
	bodies := map[string]struct {
		st   int
		body string
	}{
		"non2xx":      {400, `{"id":"b1"}`},
		"nonjson":     {201, `not json`},
		"empty":       {201, ``},
		"missing":     {201, `{"x":"b1"}`},
		"object":      {201, `{"id":{"a":1}}`},
		"array":       {201, `{"id":["b1"]}`},
		"bool":        {201, `{"id":true}`},
		"null":        {201, `{"id":null}`},
		"emptystring": {201, `{"id":""}`},
		"redacted":    {201, `{"id":"[redacted:0123456789ab]"}`},
		"redacted2":   {201, `{"id":"[redacted]"}`},
	}
	for name, b := range bodies {
		t.Run(name, func(t *testing.T) {
			r := New(respCfg())
			r.Learn(respCreate(alice, model.ConfLearned, b.st, b.body))
			if n := len(books(r)); n != 0 {
				t.Fatalf("learned %d objects: %v", n, books(r))
			}
		})
	}
}

// Rule 4.
func TestCreateResponseOrderIndependence(t *testing.T) {
	obs := []*model.Observation{
		respCreate(alice, model.ConfLearned, 201, `{"id":"b1"}`),
		respCreate(bob, model.ConfLearned, 201, `{"id":"b2"}`),
		respCreate(bob, model.ConfLearned, 201, `{"id":"b1"}`),
		respCreate(alice, model.ConfLearned, 201, `{"id":"b3"}`),
	}
	var first []Object
	for i := 0; i < 4; i++ {
		r := New(respCfg())
		for j := range obs {
			r.Learn(obs[(i+j)%len(obs)])
		}
		got := books(r)
		if i == 0 {
			first = got
		} else if !slices.EqualFunc(first, got, func(a, b Object) bool { return a == b }) {
			t.Fatalf("rotation %d differs: %v vs %v", i, got, first)
		}
	}
	if len(first) != 2 { // b1 conflicted
		t.Fatalf("objects = %v", first)
	}
}

// Rule 5.
func TestCreateResponseConflict(t *testing.T) {
	r := New(respCfg())
	r.Learn(respCreate(alice, model.ConfLearned, 201, `{"id":"b1"}`))
	r.Learn(respCreate(bob, model.ConfLearned, 201, `{"id":"b1"}`))
	expect(t, r, read(alice, getEP, "id", "b1"), nil, model.ConfUnknown)
}

func TestCreateResponseNestedPath(t *testing.T) {
	r := New(Config{Create: []CreateRule{{Method: "POST", Path: "/books", Resource: "books", IDFromResponse: "data.id"}}})
	r.Learn(respCreate(alice, model.ConfLearned, 201, `{"data":{"id":"n1"}}`))
	expect(t, r, read(bob, getEP, "id", "n1"), alice, model.ConfLearned)
}
