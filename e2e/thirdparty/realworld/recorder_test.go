package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeRealworld is a tiny in-memory RealWorld API (no network beyond httptest): tokens are "tok-<username>",
// articles and comments have owners, PUT/DELETE by a non-owner answer like the real app (404 / 401).
// The first failRegs POST /api/users calls answer 500 (a service that is not settled yet).
type fakeRealworld struct {
	srv      *httptest.Server
	failRegs int32
	regs     atomic.Int32
	opens    atomic.Int32
	articles map[string]string // slug -> owner
	comments map[string]string // id -> owner
	nextID   int
}

func newFake(t *testing.T, failRegs int32) *fakeRealworld {
	t.Helper()
	f := &fakeRealworld{failRegs: failRegs, articles: map[string]string{}, comments: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRealworld) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")
	reply := func(code int, s string) { w.WriteHeader(code); io.WriteString(w, s) }
	who := strings.TrimPrefix(r.Header.Get("Authorization"), "Token tok-")
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Token tok-") {
		who = ""
	}
	p := strings.TrimPrefix(r.URL.Path, "/api")
	parts := strings.Split(strings.Trim(p, "/"), "/")
	switch {
	case p == "/users" && r.Method == "POST":
		if f.regs.Add(1) <= f.failRegs {
			reply(500, `{"errors":{"body":"boom"}}`)
			return
		}
		reply(201, `{"user":{}}`)
	case p == "/users/login":
		var in struct{ User struct{ Email string } }
		_ = json.Unmarshal(body, &in)
		reply(200, `{"user":{"token":"tok-`+strings.Split(in.User.Email, "@")[0]+`"}}`)
	case who == "" && (r.Method != "GET" || p == "/user" || p == "/articles/feed"):
		reply(401, `{"errors":{"body":"missing or malformed jwt"}}`)
	case p == "/articles" && r.Method == "POST":
		var in struct{ Article struct{ Title string } }
		_ = json.Unmarshal(body, &in)
		slug := strings.ReplaceAll(strings.ToLower(in.Article.Title), " ", "-")
		f.articles[slug] = who
		reply(201, `{"article":{"slug":"`+slug+`"}}`)
	case len(parts) == 2 && parts[0] == "articles" && (r.Method == "PUT" || r.Method == "DELETE"):
		if f.articles[parts[1]] != who {
			reply(404, `{"errors":{"body":"resource not found"}}`)
			return
		}
		if r.Method == "DELETE" {
			delete(f.articles, parts[1])
		}
		reply(200, `{"article":{}}`)
	case len(parts) == 3 && parts[2] == "comments" && r.Method == "POST":
		f.nextID++
		id := string(rune('0' + f.nextID%10))
		f.comments[parts[1]+"/"+id] = who
		reply(201, `{"comment":{"id":`+id+`}}`)
	case len(parts) == 4 && parts[2] == "comments" && r.Method == "DELETE":
		if f.comments[parts[1]+"/"+parts[3]] != who {
			reply(401, `{"errors":{"body":"unauthorized action"}}`)
			return
		}
		reply(200, `{}`)
	default:
		reply(200, `{}`)
	}
}

func (f *fakeRealworld) open() (stack, func()) {
	f.opens.Add(1)
	return stack{web: f.srv.URL}, func() {}
}

func TestRecordSessionRetriesSetupError(t *testing.T) {
	f := newFake(t, 1)
	r, stop := recordSession(f.open, "honest", 3)
	stop()
	if f.opens.Load() != 2 {
		t.Fatalf("expected a retry on a fresh stack, opened %d", f.opens.Load())
	}
	// entries of the failed attempt are discarded: exactly one register call per user
	n := 0
	for _, e := range r.entries {
		if e.Request.Method == "POST" && strings.HasSuffix(e.Request.URL, "/api/users") {
			n++
		}
	}
	if n != len(names) {
		t.Fatalf("%d registrations in the HAR, want %d", n, len(names))
	}
}

func TestRecordGivesUpAfterAttempts(t *testing.T) {
	f := newFake(t, 100)
	var last setupError
	r := newRecorder(stack{web: f.srv.URL})
	if tryRecord(r, "honest", &last) || last == "" {
		t.Fatalf("tryRecord should fail with a setup error, got %q", last)
	}
}

func TestTryRecordRepanicsOtherErrors(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a non-setup panic must propagate")
		}
	}()
	r := newRecorder(stack{web: "http://127.0.0.1:1"})
	r.client = nil // a nil dereference is a runtime error, not a setupError
	var last setupError
	tryRecord(r, "honest", &last)
}

func TestHonestUsesTokenSchemeAndAPIBase(t *testing.T) {
	f := newFake(t, 0)
	r := newRecorder(stack{web: f.srv.URL})
	r.honest()
	sawAuth := false
	for _, e := range r.entries {
		if !strings.HasPrefix(e.Request.URL, fakeHost+"/api/") {
			t.Fatalf("URL %q is not under %s/api/", e.Request.URL, fakeHost)
		}
		for _, h := range e.Request.Headers {
			if h.Name == "Authorization" {
				sawAuth = true
				if !strings.HasPrefix(h.Value, "Token ") {
					t.Fatalf("Authorization %q does not use the Token scheme", h.Value)
				}
			}
		}
	}
	if !sawAuth {
		t.Fatal("no authenticated call recorded")
	}
	for _, s := range r.steps {
		if s.Tag != "" {
			t.Fatalf("honest suite must make no tagged cross-user probe: %+v", s)
		}
	}
}

func TestAttackProbesMatchGroundTruthAndAreDenied(t *testing.T) {
	f := newFake(t, 0)
	r := newRecorder(stack{web: f.srv.URL})
	r.attack()
	gt, err := loadGroundTruth("groundtruth.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range gt {
		if probeStatus(r.steps, g.Probe) == "" {
			t.Errorf("%s: probe %q was never recorded", g.ID, g.Probe)
		}
	}
	for _, s := range r.steps {
		if s.Tag == "article_put_other" || s.Tag == "article_del_other" {
			if s.Status != 404 {
				t.Errorf("%s %s by %s: status %d, want 404", s.Method, s.Path, s.Who, s.Status)
			}
		}
		if s.Tag == "comment_del_other" && s.Status != 401 {
			t.Errorf("comment_del_other by %s: status %d, want 401", s.Who, s.Status)
		}
	}
}

func TestGroundTruthParses(t *testing.T) {
	gt, err := loadGroundTruth("groundtruth.yaml")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, g := range gt {
		if g.ID == "" || g.Category == "" || g.Source == "" || g.Expect == "" || g.Probe == "" {
			t.Errorf("incomplete ground-truth item %+v", g)
		}
		if g.Category != "control" && g.Category != "quirk" {
			t.Errorf("%s: unknown category %q", g.ID, g.Category)
		}
		if seen[g.ID] {
			t.Errorf("duplicate id %s", g.ID)
		}
		seen[g.ID] = true
	}
	if len(gt) < 15 {
		t.Errorf("only %d ground-truth items", len(gt))
	}
}

func TestComposePinsEveryImage(t *testing.T) {
	m := composeImages("compose.yaml")
	if len(m) != 2 {
		t.Fatalf("want the app and the relay image pinned by digest, got %v", m)
	}
	if _, ok := m[realworldImage]; !ok {
		t.Fatalf("app image %s missing: %v", realworldImage, m)
	}
}
