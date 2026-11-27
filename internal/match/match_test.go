package match

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

var routes = []struct{ method, tmpl string }{
	{"GET", "/"},
	{"GET", "/books/v1"},
	{"POST", "/books/v1"},
	{"GET", "/books/v1/{book_title}"},
	{"GET", "/users/v1/_debug"},
	{"GET", "/users/v1/{username}"},
	{"DELETE", "/users/v1/{username}"},
	{"PUT", "/users/v1/{username}/email"},
	{"GET", "/{entity}/me"},
	{"GET", "/books/{id}"},
	{"GET", "/orgs/{org}/repos/{repo}"},
	{"GET", "/files/{name}"},
}

func newTestTrie(t testing.TB) *Trie {
	t.Helper()
	tr := New()
	for _, r := range routes {
		if err := tr.Add(r.method, r.tmpl, r.method+" "+r.tmpl); err != nil {
			t.Fatalf("Add(%s %s): %v", r.method, r.tmpl, err)
		}
	}
	return tr
}

func TestMatch(t *testing.T) {
	tr := newTestTrie(t)
	tests := []struct {
		name       string
		method     string
		path       string
		wantID     string // "" => no op
		wantParams map[string]string
		wantAmbig  []string
		wantMiss   bool
	}{
		{"literal beats param", "GET", "/users/v1/_debug", "GET /users/v1/_debug", map[string]string{}, nil, false},
		{"param binds", "GET", "/users/v1/alice", "GET /users/v1/{username}", map[string]string{"username": "alice"}, nil, false},
		{"first differing segment literal wins, other ambiguous", "GET", "/books/me", "GET /books/{id}", map[string]string{"id": "me"}, []string{"GET /{entity}/me"}, false},
		{"param-first template wins when literal path absent", "GET", "/users/me", "GET /{entity}/me", map[string]string{"entity": "users"}, nil, false},
		{"multiple params bind in order", "GET", "/orgs/acme/repos/web", "GET /orgs/{org}/repos/{repo}", map[string]string{"org": "acme", "repo": "web"}, nil, false},
		{"%2F stays inside one segment", "GET", "/files/a%2Fb", "GET /files/{name}", map[string]string{"name": "a/b"}, nil, false},
		{"real slash is a new segment", "GET", "/files/a/b", "", nil, nil, false},
		{"percent-decoding per segment", "GET", "/users/v1/al%69ce", "GET /users/v1/{username}", map[string]string{"username": "alice"}, nil, false},
		{"encoded literal matches", "GET", "/users/v1/%5Fdebug", "GET /users/v1/_debug", map[string]string{}, nil, false},
		{"jsessionid matrix param dropped", "GET", "/users/v1/alice;jsessionid=ABC", "GET /users/v1/{username}", map[string]string{"username": "alice"}, nil, false},
		{"matrix param on literal dropped", "GET", "/books/v1;x=1", "GET /books/v1", map[string]string{}, nil, false},
		{"encoded semicolon is data", "GET", "/users/v1/a%3Bb", "GET /users/v1/{username}", map[string]string{"username": "a;b"}, nil, false},
		{"trailing slash ignored", "GET", "/books/v1/", "GET /books/v1", map[string]string{}, nil, false},
		{"trailing slash on param path", "PUT", "/users/v1/bob/email/", "PUT /users/v1/{username}/email", map[string]string{"username": "bob"}, nil, false},
		{"root", "GET", "/", "GET /", map[string]string{}, nil, false},
		{"query string ignored", "GET", "/books/v1?limit=1", "GET /books/v1", map[string]string{}, nil, false},
		{"lower-case method normalised", "post", "/books/v1", "POST /books/v1", map[string]string{}, nil, false},
		{"unknown path", "GET", "/nope/x/y", "", nil, nil, false},
		{"case-sensitive literals", "GET", "/Books/v1", "", nil, nil, false},
		{"method miss", "PATCH", "/books/v1", "", nil, nil, true},
		{"method miss on param path", "POST", "/users/v1/alice", "", nil, nil, true},
		{"empty segment never binds", "PUT", "/users/v1//email", "", nil, nil, false},
		{"segment empty after matrix strip never binds", "GET", "/users/v1/;jsessionid=X", "", nil, nil, false},
		{"double slash is not root", "GET", "//", "", nil, nil, false},
		{"invalid escape never matches", "GET", "/users/v1/%zz", "", nil, nil, false},
		{"empty path", "GET", "", "", nil, nil, false},
		{"no leading slash", "GET", "books/v1", "", nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tr.Match(tt.method, tt.path)
			var gotID string
			if got.Op != nil {
				gotID = got.Op.ID
			}
			if gotID != tt.wantID {
				t.Fatalf("op = %q, want %q (result %+v)", gotID, tt.wantID, got)
			}
			if tt.wantID != "" && !reflect.DeepEqual(got.Params, tt.wantParams) {
				t.Errorf("params = %v, want %v", got.Params, tt.wantParams)
			}
			if tt.wantID == "" && got.Params != nil {
				t.Errorf("params = %v, want nil on no match", got.Params)
			}
			var ambig []string
			for _, a := range got.Ambiguous {
				ambig = append(ambig, a.ID)
			}
			if !reflect.DeepEqual(ambig, tt.wantAmbig) {
				t.Errorf("ambiguous = %v, want %v", ambig, tt.wantAmbig)
			}
			if got.MethodMiss != tt.wantMiss {
				t.Errorf("MethodMiss = %v, want %v", got.MethodMiss, tt.wantMiss)
			}
		})
	}
}

func TestAddErrors(t *testing.T) {
	tests := []struct {
		name   string
		method string
		tmpl   string
		want   error
	}{
		{"exact duplicate", "GET", "/books/v1", ErrDuplicate},
		{"duplicate with other param name", "GET", "/books/v1/{title}", ErrDuplicate},
		{"duplicate via trailing slash", "GET", "/books/v1/", ErrDuplicate},
		{"partial segment param", "GET", "/x/{id}.json", ErrTemplate},
		{"empty segment", "GET", "/x//y", ErrTemplate},
		{"no leading slash", "GET", "x", ErrTemplate},
		{"empty method", "", "/z", ErrTemplate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := newTestTrie(t)
			err := tr.Add(tt.method, tt.tmpl, tt.method+" "+tt.tmpl)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if !strings.Contains(err.Error(), tt.tmpl) {
				t.Errorf("error %q does not name the template", err)
			}
		})
	}
}

func TestAmbiguousSortedAndExcludesWinner(t *testing.T) {
	tr := New()
	for _, tmpl := range []string{"/{a}/x", "/{b}/{c}/z", "/y/{d}", "/{e}/{f}"} {
		if err := tr.Add("GET", tmpl, tmpl); err != nil {
			t.Fatal(err)
		}
	}
	// /y/x: candidates /y/{d} (literal first), /{a}/x (literal second), /{e}/{f} (no literals).
	got := tr.Match("GET", "/y/x")
	if got.Op == nil || got.Op.ID != "/y/{d}" {
		t.Fatalf("winner = %+v", got.Op)
	}
	var ambig []string
	for _, a := range got.Ambiguous {
		ambig = append(ambig, a.ID)
	}
	if !reflect.DeepEqual(ambig, []string{"/{a}/x"}) {
		t.Fatalf("ambiguous = %v", ambig)
	}
}

func FuzzMatch(f *testing.F) {
	for _, s := range []string{"/", "/books/me", "/users/v1/%2F;x", "//", "/%", "/a/b/c/d/e/f/g", "/files/%zz", "?", ";;;"} {
		f.Add("GET", s)
	}
	tr := newTestTrie(f)
	f.Fuzz(func(t *testing.T, method, path string) {
		r := tr.Match(method, path)
		if e := tr.Explain(method, path); !reflect.DeepEqual(e.Result, r) {
			t.Fatalf("Explain result %+v != Match %+v", e.Result, r)
		}
		if r.Op == nil {
			if r.Params != nil || len(r.Ambiguous) != 0 {
				t.Fatalf("no op but params/ambiguous set: %+v", r)
			}
			return
		}
		if r.MethodMiss {
			t.Fatalf("op and MethodMiss both set: %+v", r)
		}
		if len(r.Params) != len(r.Op.Params) {
			t.Fatalf("bound %d params, op has %d", len(r.Params), len(r.Op.Params))
		}
		for _, a := range r.Ambiguous {
			if a == r.Op {
				t.Fatal("winner listed as ambiguous")
			}
		}
	})
}

func FuzzExplain(f *testing.F) {
	for _, s := range []string{"/", "/books/me", "/users/v1/%2F;x", "//", "/%", "/books/v1", "?"} {
		f.Add("GET", s)
	}
	tr := newTestTrie(f)
	f.Fuzz(func(t *testing.T, method, path string) {
		want := tr.Match(method, path)
		e := tr.Explain(method, path)
		if !reflect.DeepEqual(e.Result, want) {
			t.Fatalf("Explain result %+v != Match %+v", e.Result, want)
		}
		if e.Reason == "" {
			t.Fatal("empty reason")
		}
		if want.Op != nil && (len(e.Candidates) == 0 || e.Candidates[0].Op != want.Op) {
			t.Fatalf("winner not first: %+v", e.Candidates)
		}
	})
}

func TestExplain(t *testing.T) {
	tr := newTestTrie(t)
	tests := []struct {
		name       string
		method     string
		path       string
		wantSegs   []string
		wantCands  []string // "ID lit=N method=ok|no"
		wantReason string
	}{
		{"literal beats param", "GET", "/users/v1/_debug", []string{"users", "v1", "_debug"},
			[]string{"GET /users/v1/_debug 3 true", "DELETE /users/v1/{username} 2 false", "GET /users/v1/{username} 2 true"},
			`literal "_debug" beats parameter {username} at segment 3`},
		{"first differing segment", "GET", "/books/me", []string{"books", "me"},
			[]string{"GET /books/{id} 1 true", "GET /{entity}/me 1 true"},
			`literal "books" beats parameter {entity} at segment 1`},
		{"only candidate", "GET", "/files/x", []string{"files", "x"},
			[]string{"GET /files/{name} 1 true"}, "only candidate"},
		{"no match", "GET", "/nope/x/y", []string{"nope", "x", "y"}, nil, "no template matches this path"},
		{"method miss", "PATCH", "/books/v1", []string{"books", "v1"},
			[]string{"GET /books/v1 2 false", "POST /books/v1 2 false", "GET /books/{id} 1 false"},
			"path matches but method PATCH is not defined (allowed: GET, POST)"},
		{"matrix stripped and unescaped", "GET", "/users/v1/a%2Fb;x=1", []string{"users", "v1", "a/b"},
			[]string{"GET /users/v1/{username} 2 true", "DELETE /users/v1/{username} 2 false"}, "only candidate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := tr.Explain(tt.method, tt.path)
			if !reflect.DeepEqual(e.Segments, tt.wantSegs) {
				t.Errorf("segments = %q, want %q", e.Segments, tt.wantSegs)
			}
			if !reflect.DeepEqual(e.Result, tr.Match(tt.method, tt.path)) {
				t.Errorf("result differs from Match: %+v", e.Result)
			}
			var got []string
			for _, c := range e.Candidates {
				got = append(got, c.Op.ID+" "+strconv.Itoa(c.Literals)+" "+boolStr(c.MethodOK))
			}
			if !reflect.DeepEqual(got, tt.wantCands) {
				t.Errorf("candidates = %q, want %q", got, tt.wantCands)
			}
			if e.Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", e.Reason, tt.wantReason)
			}
		})
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
