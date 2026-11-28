package exec

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"authzcov/internal/probe/credentials"
	"authzcov/internal/probe/items"
	"authzcov/internal/probe/safety"
)

type fakeRes struct {
	mu    sync.Mutex
	calls int
	seq   [][]netip.Addr
}

func (f *fakeRes) LookupNetIP(_ context.Context, _ string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.calls
	f.calls++
	if i >= len(f.seq) {
		i = len(f.seq) - 1
	}
	return f.seq[i], nil
}

func newChecker(t *testing.T, r safety.Resolver) *safety.Checker {
	t.Helper()
	c, err := safety.New(safety.Policy{}, r)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newExec(t *testing.T, base string, mut func(*Config)) (*Executor, *bytes.Buffer) {
	t.Helper()
	audit := &bytes.Buffer{}
	cfg := Config{
		BaseURL: base, Checker: newChecker(t, NewResolver()), Audit: audit,
		RunID: "run-1", Version: "9.9", Rate: 1000,
	}
	if mut != nil {
		mut(&cfg)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e, audit
}

func item(id, path, who string) items.Item {
	return items.Item{ProbeID: id, Method: "GET", Path: path, AttackerIdentity: who, Expect: "deny", Executable: true}
}

func TestHeadersAndAudit(t *testing.T) {
	var ua, run atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua.Store(r.Header.Get("User-Agent"))
		run.Store(r.Header.Get("X-Authzcov-Run"))
		w.WriteHeader(403)
	}))
	defer srv.Close()
	e, audit := newExec(t, srv.URL, nil)
	res, err := e.Run(context.Background(), []items.Item{item("p1", "/a/1?token=SECRETQ", "")})
	if err != nil {
		t.Fatal(err)
	}
	if ua.Load() != "authzcov/9.9" || run.Load() != "run-1" {
		t.Fatalf("ua=%v run=%v", ua.Load(), run.Load())
	}
	if len(res) != 1 || res[0].Status != 403 {
		t.Fatalf("%+v", res)
	}
	if strings.Contains(audit.String(), "SECRETQ") {
		t.Fatalf("query value in audit: %s", audit.String())
	}
	lines := strings.Split(strings.TrimSpace(audit.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want intent+result lines, got %d: %s", len(lines), audit.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"run_id", "seq", "probe_id", "method", "path_fp", "expect", "status", "duration_ms"} {
		if _, ok := m[k]; !ok {
			t.Errorf("audit missing %s: %v", k, m)
		}
	}
}

func TestRedirectOffHostNotFollowed(t *testing.T) {
	var other atomic.Int32
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other.Add(1) }))
	defer b.Close()
	var auth atomic.Value
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
		http.Redirect(w, r, b.URL+"/x", http.StatusFound)
	}))
	defer a.Close()
	e, _ := newExec(t, a.URL, nil)
	res, err := e.Run(context.Background(), []items.Item{item("p", "/r", "")})
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Status != 302 || !res[0].Redirect {
		t.Fatalf("%+v", res[0])
	}
	if other.Load() != 0 {
		t.Fatalf("second server saw %d requests", other.Load())
	}
}

func TestSameHostRedirectNotFollowed(t *testing.T) {
	var hits atomic.Int32
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer a.Close()
	e, _ := newExec(t, a.URL, nil)
	res, _ := e.Run(context.Background(), []items.Item{item("p", "/r", "")})
	if hits.Load() != 1 || res[0].Status != 302 {
		t.Fatalf("hits=%d %+v", hits.Load(), res)
	}
}

func TestDialPinningAgainstRebinding(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if !strings.HasPrefix(r.Host, "app.test") {
			t.Errorf("Host header = %q", r.Host)
		}
	}))
	defer srv.Close()
	port := portOf(t, srv.URL)
	res := &fakeRes{seq: [][]netip.Addr{
		{netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("169.254.169.254")}, // rebinds after the check
	}}
	e, _ := newExec(t, "http://app.test:"+port, func(c *Config) { c.Checker = newChecker(t, res) })
	out, err := e.Run(context.Background(), []items.Item{item("p", "/", "")})
	if err != nil || out[0].Status != 200 || hits.Load() != 1 {
		t.Fatalf("err=%v out=%+v hits=%d", err, out, hits.Load())
	}
	res.mu.Lock()
	defer res.mu.Unlock()
	if res.calls != 1 {
		t.Fatalf("resolver called %d times; dial must reuse the checked decision", res.calls)
	}
}

func TestMetadataAnswerRefusedNoRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	res := &fakeRes{seq: [][]netip.Addr{{netip.MustParseAddr("169.254.169.254")}}}
	e, _ := newExec(t, "http://app.test:"+portOf(t, srv.URL), func(c *Config) { c.Checker = newChecker(t, res) })
	_, err := e.Run(context.Background(), []items.Item{item("p", "/", "")})
	if !errors.Is(err, ErrRefused) || hits.Load() != 0 {
		t.Fatalf("err=%v hits=%d", err, hits.Load())
	}
}

func TestDialPinnedRejectsBadAddr(t *testing.T) {
	e, _ := newExec(t, "http://127.0.0.1:1", nil)
	d := safety.Decision{Allowed: true, Host: "app.test", Port: 80,
		Addrs: []netip.Addr{netip.MustParseAddr("169.254.169.254")}}
	ctx := context.WithValue(context.Background(), decisionKey{}, d)
	if c, err := e.dialPinned(ctx, "tcp", "app.test:80"); err == nil {
		_ = c.Close()
		t.Fatal("dial to metadata address succeeded")
	}
	d.Addrs = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	ctx = context.WithValue(context.Background(), decisionKey{}, d)
	if c, err := e.dialPinned(ctx, "tcp", "evil.test:80"); err == nil {
		_ = c.Close()
		t.Fatal("dial to a host other than the checked one succeeded")
	}
	if c, err := e.dialPinned(context.Background(), "tcp", "app.test:80"); err == nil {
		_ = c.Close()
		t.Fatal("dial without a decision succeeded")
	}
}

func TestRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	e, _ := newExec(t, srv.URL, func(c *Config) { c.Rate = 20 })
	its := []items.Item{item("a", "/", ""), item("b", "/", ""), item("c", "/", ""), item("d", "/", ""), item("e", "/", "")}
	start := time.Now()
	if _, err := e.Run(context.Background(), its); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el < 150*time.Millisecond {
		t.Fatalf("5 requests at 20/s took %v", el)
	}
}

func TestDefaults(t *testing.T) {
	e, _ := newExec(t, "http://127.0.0.1:1", func(c *Config) { c.Rate = 0 })
	if e.cfg.Rate != 5 || e.cfg.Budget != 500 || e.cfg.Breaker != 5 {
		t.Fatalf("%+v", e.cfg)
	}
}

func TestBudgetStops(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	e, _ := newExec(t, srv.URL, func(c *Config) { c.Budget = 3 })
	var its []items.Item
	for i := 0; i < 10; i++ {
		its = append(its, item(fmt.Sprintf("p%d", i), "/", ""))
	}
	res, err := e.Run(context.Background(), its)
	if !errors.Is(err, ErrBudget) || hits.Load() != 3 || len(res) != 3 {
		t.Fatalf("err=%v hits=%d res=%d", err, hits.Load(), len(res))
	}
}

func TestBreaker(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(503)
	}))
	defer srv.Close()
	e, _ := newExec(t, srv.URL, nil)
	var its []items.Item
	for i := 0; i < 10; i++ {
		its = append(its, item(fmt.Sprintf("p%d", i), "/", ""))
	}
	_, err := e.Run(context.Background(), its)
	if !errors.Is(err, ErrBreaker) || hits.Load() != 5 {
		t.Fatalf("err=%v hits=%d", err, hits.Load())
	}
}

func TestBreakerResetsOnNon5xx(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1)%3 == 0 {
			return
		}
		w.WriteHeader(500)
	}))
	defer srv.Close()
	e, _ := newExec(t, srv.URL, nil)
	var its []items.Item
	for i := 0; i < 9; i++ {
		its = append(its, item(fmt.Sprintf("p%d", i), "/", ""))
	}
	if _, err := e.Run(context.Background(), its); err != nil {
		t.Fatal(err)
	}
}

func TestContextCancelStops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	e, _ := newExec(t, srv.URL, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := e.Run(ctx, []items.Item{item("p", "/", "")})
	if !errors.Is(err, context.Canceled) || len(res) != 0 {
		t.Fatalf("err=%v res=%v", err, res)
	}
}

func TestProxyEnvIgnored(t *testing.T) {
	var proxied atomic.Int32
	px := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxied.Add(1) }))
	defer px.Close()
	t.Setenv("HTTP_PROXY", px.URL)
	t.Setenv("HTTPS_PROXY", px.URL)
	t.Setenv("http_proxy", px.URL)
	t.Setenv("NO_PROXY", "")
	var direct atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { direct.Add(1) }))
	defer srv.Close()
	e, _ := newExec(t, srv.URL, nil)
	if _, err := e.Run(context.Background(), []items.Item{item("p", "/", "")}); err != nil {
		t.Fatal(err)
	}
	if direct.Load() != 1 || proxied.Load() != 0 {
		t.Fatalf("direct=%d proxied=%d", direct.Load(), proxied.Load())
	}
	if e.client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("Transport.Proxy must be nil")
	}
}

func TestHTTP2DebugRefused(t *testing.T) {
	t.Setenv("GODEBUG", "http2debug=2")
	_, err := New(Config{BaseURL: "http://127.0.0.1:1", Checker: newChecker(t, NewResolver()), Audit: &bytes.Buffer{}, RunID: "r"})
	if err == nil {
		t.Fatal("expected refusal")
	}
}

func TestTLSVerifyOn(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	e, _ := newExec(t, srv.URL, nil)
	res, err := e.Run(context.Background(), []items.Item{item("p", "/", "")})
	if err == nil && len(res) > 0 && res[0].Status != 0 {
		t.Fatalf("untrusted certificate accepted: %+v", res)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	e2, _ := newExec(t, srv.URL, func(c *Config) { c.rootCAs = pool })
	res, err = e2.Run(context.Background(), []items.Item{item("p", "/", "")})
	if err != nil || res[0].Status != 204 {
		t.Fatalf("err=%v res=%+v", err, res)
	}
}

// --- login / credentials ---

func recipe(user string) credentials.Recipe {
	return credentials.Recipe{
		Method: "POST", Path: "/auth/login", ContentType: "json",
		Fields:    map[string]string{"username": user, "password": "${PW_" + strings.ToUpper(user) + "}"},
		TokenFrom: credentials.TokenFrom{Kind: "json", Name: "/access_token"},
		Apply:     credentials.Apply{Kind: "bearer"},
	}
}

const canaryTok = "CANARYTOKEN-abc123"
const canaryBody = "BODYCANARY-xyz789"

func loginServer(t *testing.T, logins *atomic.Int32, seen *sync.Map) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/login" {
			logins.Add(1)
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"access_token":"%s-%s","note":"%s"}`, canaryTok, in["username"], canaryBody)
			return
		}
		seen.Store(r.URL.Path, r.Header.Get("Authorization"))
		w.WriteHeader(401)
		fmt.Fprint(w, canaryBody)
	}))
}

func TestPerIdentityCredentialsAndNoRelogin(t *testing.T) {
	var logins atomic.Int32
	var seen sync.Map
	srv := loginServer(t, &logins, &seen)
	defer srv.Close()
	p := credentials.NewProvider(map[string]credentials.Recipe{"alice": recipe("alice"), "bob": recipe("bob")})
	p.Lookup = func(k string) string { return "pw-" + k }
	e, audit := newExec(t, srv.URL, func(c *Config) { c.Provider = p })
	its := []items.Item{item("1", "/a", "alice"), item("2", "/b", "bob"), item("3", "/c", "alice")}
	res, err := e.Run(context.Background(), its)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.Status != 401 {
			t.Fatalf("%+v", r)
		}
	}
	if logins.Load() != 2 {
		t.Fatalf("logins=%d want 2 (one per identity, none on 401)", logins.Load())
	}
	want := map[string]string{"/a": "Bearer " + canaryTok + "-alice", "/b": "Bearer " + canaryTok + "-bob", "/c": "Bearer " + canaryTok + "-alice"}
	for path, w := range want {
		if got, _ := seen.Load(path); got != w {
			t.Errorf("%s sent %v want %s", path, got, w)
		}
	}
	a := audit.String()
	for _, bad := range []string{canaryTok, canaryBody, "pw-PW_ALICE", "Bearer"} {
		if strings.Contains(a, bad) {
			t.Errorf("audit contains %q", bad)
		}
	}
	if !strings.Contains(a, "login identity=alice status=200 fp=") {
		t.Errorf("no login line: %s", a)
	}
	if res[0].Redirect {
		t.Error("not a redirect")
	}
}

func TestLoginFailureIsUnknownAndLeakFree(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(401)
		fmt.Fprint(w, canaryBody)
	}))
	defer srv.Close()
	p := credentials.NewProvider(map[string]credentials.Recipe{"alice": recipe("alice")})
	p.Lookup = func(string) string { return "pw-SECRETPW" }
	e, audit := newExec(t, srv.URL, func(c *Config) { c.Provider = p })
	res, err := e.Run(context.Background(), []items.Item{item("1", "/a", "alice"), item("2", "/b", "alice")})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.Outcome != OutcomeUnknown || r.Status != 0 {
			t.Fatalf("%+v", r)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("hits=%d: failed login must not be retried and items must not be sent", hits.Load())
	}
	all := audit.String() + fmt.Sprint(res)
	for _, bad := range []string{canaryBody, "SECRETPW"} {
		if strings.Contains(all, bad) {
			t.Errorf("leak %q in %s", bad, all)
		}
	}
}

func TestNoRecipeIdentityIsUnknown(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	p := credentials.NewProvider(map[string]credentials.Recipe{})
	e, _ := newExec(t, srv.URL, func(c *Config) { c.Provider = p })
	res, _ := e.Run(context.Background(), []items.Item{item("1", "/a", "carol")})
	if hits.Load() != 0 || res[0].Outcome != OutcomeUnknown {
		t.Fatalf("hits=%d %+v", hits.Load(), res)
	}
}

func TestLoginCountsAgainstBudgetAndPathUnmodified(t *testing.T) {
	var gotPath atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			gotPath.Store(r.RequestURI)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"t"}`)
		}
	}))
	defer srv.Close()
	rc := recipe("alice")
	rc.Path = "/auth/a%7Eb/login?x=1"
	p := credentials.NewProvider(map[string]credentials.Recipe{"alice": rc})
	p.Lookup = func(string) string { return "pw" }
	e, _ := newExec(t, srv.URL, func(c *Config) { c.Provider = p; c.Budget = 1 })
	res, err := e.Run(context.Background(), []items.Item{item("1", "/a", "alice")})
	if !errors.Is(err, ErrBudget) || len(res) != 0 {
		t.Fatalf("err=%v res=%v", err, res)
	}
	if gotPath.Load() != "/auth/a%7Eb/login?x=1" {
		t.Fatalf("login path = %v", gotPath.Load())
	}
}

func TestNonExecutableSkipped(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	e, _ := newExec(t, srv.URL, nil)
	it := item("1", "/a/{id}", "")
	it.Executable, it.Reason = false, "no_id"
	res, err := e.Run(context.Background(), []items.Item{it})
	if err != nil || hits.Load() != 0 || res[0].Outcome != OutcomeSkipped {
		t.Fatalf("err=%v hits=%d %+v", err, hits.Load(), res)
	}
}

func TestF1PathMustStayOnConfirmedTarget(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	for _, p := range []string{".evil.example/x", ":8080/x", "//evil.example/x", "/a\\b", "@evil.example/x", "x", ""} {
		e, _ := newExec(t, srv.URL, nil)
		res, err := e.Run(context.Background(), []items.Item{item("1", p, "")})
		if !errors.Is(err, ErrRefused) {
			t.Errorf("path %q: err=%v res=%v", p, err, res)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("hits=%d", hits.Load())
	}
}

func TestF2LoginAuditOnlyWhenLoggedIn(t *testing.T) {
	var logins atomic.Int32
	var seen sync.Map
	srv := loginServer(t, &logins, &seen)
	defer srv.Close()
	p := credentials.NewProvider(map[string]credentials.Recipe{"alice": recipe("alice")})
	p.Lookup = func(string) string { return "pw" }
	e, audit := newExec(t, srv.URL, func(c *Config) { c.Provider = p })
	its := []items.Item{item("1", "/a", "alice"), item("2", "/b", "alice"), item("3", "/c", "alice")}
	if _, err := e.Run(context.Background(), its); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(audit.String(), `"event":"login"`); n != 1 {
		t.Fatalf("login lines=%d want 1: %s", n, audit.String())
	}
}

func TestF2LoginAuditPerIdentityStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/login" {
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["username"] == "bob" {
				w.WriteHeader(403)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"t"}`)
			return
		}
		w.WriteHeader(401)
	}))
	defer srv.Close()
	p := credentials.NewProvider(map[string]credentials.Recipe{"alice": recipe("alice"), "bob": recipe("bob")})
	p.Lookup = func(string) string { return "pw" }
	e, audit := newExec(t, srv.URL, func(c *Config) { c.Provider = p })
	its := []items.Item{item("1", "/a", "alice"), item("2", "/b", "bob"), item("3", "/c", "alice"), item("4", "/d", "bob")}
	if _, err := e.Run(context.Background(), its); err != nil {
		t.Fatal(err)
	}
	a := audit.String()
	if !strings.Contains(a, "login identity=alice status=200") || strings.Contains(a, "identity=alice status=403") {
		t.Fatalf("wrong login evidence: %s", a)
	}
	if n := strings.Count(a, `"event":"login"`); n != 2 {
		t.Fatalf("login lines=%d want 2", n)
	}
}

func TestF4AuditHasNoRawPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	e, audit := newExec(t, srv.URL, nil)
	if _, err := e.Run(context.Background(), []items.Item{item("p9", "/orgs/RAWID-777/x?q=1", "")}); err != nil {
		t.Fatal(err)
	}
	a := audit.String()
	if strings.Contains(a, "RAWID-777") || !strings.Contains(a, `"probe_id":"p9"`) || !strings.Contains(a, "path_fp") {
		t.Fatalf("audit: %s", a)
	}
}

type failWriter struct{ ok int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.ok <= 0 {
		return 0, errors.New("disk full")
	}
	f.ok--
	return len(p), nil
}

func TestF5AuditFailureStopsRun(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	e, _ := newExec(t, srv.URL, func(c *Config) { c.Audit = &failWriter{} })
	res, err := e.Run(context.Background(), []items.Item{item("1", "/a", ""), item("2", "/b", "")})
	if err == nil || !errors.Is(err, ErrAudit) || hits.Load() != 0 || len(res) != 0 {
		t.Fatalf("err=%v hits=%d res=%v", err, hits.Load(), res)
	}
}

func TestF3StaticTokenSent(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization"))
	}))
	defer srv.Close()
	p := credentials.NewProvider(map[string]credentials.Recipe{})
	p.TokenEnv = map[string]string{"alice": "ALICE_TOK"}
	p.Lookup = func(string) string { return "static-canary" }
	e, audit := newExec(t, srv.URL, func(c *Config) { c.Provider = p })
	res, err := e.Run(context.Background(), []items.Item{item("1", "/a", "alice")})
	if err != nil || res[0].Outcome != OutcomeSent || got.Load() != "Bearer static-canary" {
		t.Fatalf("err=%v res=%+v got=%v", err, res, got.Load())
	}
	if strings.Contains(audit.String(), "static-canary") {
		t.Fatal("token in audit")
	}
}
