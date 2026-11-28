package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const canary = "s3cr3t-CANARY-\"&=value"

func TestSecretRedaction(t *testing.T) {
	s := NewSecret([]byte(canary))
	type wrap struct {
		Name string
		Sec  Secret
		Ptr  *Secret
	}
	w := wrap{"x", s, &s}
	var outs []string
	for _, v := range []any{s, &s, w, &w} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
			outs = append(outs, fmt.Sprintf(verb, v))
		}
	}
	outs = append(outs, fmt.Sprint(s), fmt.Sprintln(w))
	for _, o := range outs {
		if strings.Contains(o, "CANARY") || strings.Contains(o, "s3cr3t") || strings.Contains(o, fmt.Sprintf("%x", canary)) {
			t.Fatalf("leak: %q", o)
		}
	}
	if got := s.String(); !strings.HasPrefix(got, "[REDACTED:") {
		t.Fatalf("String = %q", got)
	}
	j, err := json.Marshal(w)
	if err != nil || bytes.Contains(j, []byte("CANARY")) {
		t.Fatalf("json: %s %v", j, err)
	}
	y, err := yaml.Marshal(w)
	if err != nil || bytes.Contains(y, []byte("CANARY")) {
		t.Fatalf("yaml: %s %v", y, err)
	}
	tx, _ := s.MarshalText()
	if bytes.Contains(tx, []byte("CANARY")) {
		t.Fatal("text leak")
	}
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, nil))
	lg.Info("m", "s", s, "w", w)
	lg2 := slog.New(slog.NewJSONHandler(&buf, nil))
	lg2.Info("m", "s", s, slog.Any("w", w))
	if strings.Contains(buf.String(), "CANARY") {
		t.Fatalf("slog leak: %s", buf.String())
	}
	if s.Expose() != canary {
		t.Fatal("expose")
	}
	s.Zero()
	if s.Expose() != "" {
		t.Fatal("zero did not clear")
	}
}

func TestLoadEnv(t *testing.T) {
	cases := []struct {
		name, val string
		ok        bool
		want      string
	}{
		{"plain", "abc", true, "abc"},
		{"trailing LF", "abc\n", true, "abc"},
		{"trailing CRLF", "abc\r\n", true, "abc"},
		{"inner spaces kept", " a b ", true, " a b "},
		{"only one newline stripped", "abc\n\n", false, ""},
		{"empty", "", false, ""},
		{"whitespace only", "   ", false, ""},
		{"newline only", "\n", false, ""},
		{"inner CR", "a\rb", false, ""},
		{"inner LF", "a\nb", false, ""},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			name := "AUTHZCOV_TEST_CRED" + strconv.Itoa(i)
			t.Setenv(name, c.val)
			s, err := LoadEnv(name)
			if c.ok {
				if err != nil || s.Expose() != c.want {
					t.Fatalf("got %v %v", s, err)
				}
				return
			}
			if err == nil {
				t.Fatal("want error")
			}
			if !strings.Contains(err.Error(), name) {
				t.Fatalf("error lacks var name: %v", err)
			}
			if c.val != "" && strings.TrimSpace(c.val) != "" && strings.Contains(err.Error(), strings.TrimSpace(c.val)) {
				t.Fatalf("error leaks value: %v", err)
			}
		})
	}
	if _, err := loadEnv("X_NUL", func(string) string { return "a\x00b" }); err == nil {
		t.Fatal("NUL accepted")
	}
	if _, err := LoadEnv("AUTHZCOV_TEST_UNSET_VAR"); err == nil || !strings.Contains(err.Error(), "env var AUTHZCOV_TEST_UNSET_VAR is empty or unset") {
		t.Fatalf("unset: %v", err)
	}
}

func TestCheckEnvNameDenied(t *testing.T) {
	for _, n := range []string{"PATH", "HOME", "GOGC", "SOURCE_DATE_EPOCH", "LD_PRELOAD", "LD_LIBRARY_PATH", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"} {
		if err := CheckEnvName(n); err == nil {
			t.Errorf("%s should be denied", n)
		}
	}
	for _, n := range []string{"ALICE_PASS", "AUTHZCOV_TEST_TOK", "_X1"} {
		if err := CheckEnvName(n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	for _, n := range []string{"lower", "1A", "A-B", "", "A B"} {
		if err := CheckEnvName(n); err == nil {
			t.Errorf("%q should be invalid", n)
		}
	}
}

func goodRecipe() Recipe {
	return Recipe{
		Method: "POST", Path: "/auth/login", ContentType: "json",
		Fields:    map[string]string{"username": "${ALICE_USER}", "password": "${ALICE_PASS}", "tenant": "acme"},
		TokenFrom: TokenFrom{Kind: "json", Name: "/access_token"},
		Apply:     Apply{Kind: "bearer"},
	}
}

func TestRecipeValidate(t *testing.T) {
	if err := goodRecipe().Validate(); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(*Recipe)) Recipe { r := goodRecipe(); f(&r); return r }
	bad := []struct {
		name  string
		r     Recipe
		field string
	}{
		{"GET", mut(func(r *Recipe) { r.Method = "GET" }), "method"},
		{"lower", mut(func(r *Recipe) { r.Method = "post" }), "method"},
		{"no slash", mut(func(r *Recipe) { r.Path = "login" }), "path"},
		{"absolute url", mut(func(r *Recipe) { r.Path = "http://evil.example.com/x" }), "path"},
		{"scheme-relative", mut(func(r *Recipe) { r.Path = "//evil/x" }), "path"},
		{"inner //", mut(func(r *Recipe) { r.Path = "/a//b" }), "path"},
		{"backslash", mut(func(r *Recipe) { r.Path = `/a\b` }), "path"},
		{"dotdot", mut(func(r *Recipe) { r.Path = "/a/../b" }), "path"},
		{"dotdot end", mut(func(r *Recipe) { r.Path = "/a/.." }), "path"},
		{"encoded dotdot", mut(func(r *Recipe) { r.Path = "/a/%2e%2E/b" }), "path"},
		{"at", mut(func(r *Recipe) { r.Path = "/a@evil" }), "path"},
		{"CRLF", mut(func(r *Recipe) { r.Path = "/a\r\nX: y" }), "path"},
		{"hash", mut(func(r *Recipe) { r.Path = "/a#f" }), "path"},
		{"bad ct", mut(func(r *Recipe) { r.ContentType = "xml" }), "content_type"},
		{"no fields", mut(func(r *Recipe) { r.Fields = nil }), "fields"},
		{"concat placeholder", mut(func(r *Recipe) { r.Fields["password"] = "pre${ALICE_PASS}" }), "fields.password"},
		{"suffix placeholder", mut(func(r *Recipe) { r.Fields["password"] = "${ALICE_PASS}x" }), "fields.password"},
		{"dollar var", mut(func(r *Recipe) { r.Fields["password"] = "$ALICE_PASS" }), "fields.password"},
		{"nested", mut(func(r *Recipe) { r.Fields["password"] = "${${X}}" }), "fields.password"},
		{"lower placeholder", mut(func(r *Recipe) { r.Fields["password"] = "${alice}" }), "fields.password"},
		{"denied env", mut(func(r *Recipe) { r.Fields["password"] = "${PATH}" }), "fields.password"},
		{"literal CRLF", mut(func(r *Recipe) { r.Fields["tenant"] = "a\r\nb" }), "fields.tenant"},
		{"empty key", mut(func(r *Recipe) { r.Fields[""] = "x" }), "fields"},
		{"bad token_from", mut(func(r *Recipe) { r.TokenFrom = TokenFrom{Kind: "body", Name: "x"} }), "token_from"},
		{"empty pointer", mut(func(r *Recipe) { r.TokenFrom = TokenFrom{Kind: "json", Name: ""} }), "token_from"},
		{"pointer no slash", mut(func(r *Recipe) { r.TokenFrom = TokenFrom{Kind: "json", Name: "access_token"} }), "token_from"},
		{"set-cookie header", mut(func(r *Recipe) { r.TokenFrom = TokenFrom{Kind: "header", Name: "Set-Cookie"} }), "token_from"},
		{"bad header name", mut(func(r *Recipe) { r.TokenFrom = TokenFrom{Kind: "header", Name: "X Bad"} }), "token_from"},
		{"bad cookie name", mut(func(r *Recipe) { r.TokenFrom = TokenFrom{Kind: "cookie", Name: "a;b"} }), "token_from"},
		{"apply unknown", mut(func(r *Recipe) { r.Apply = Apply{Kind: "query", Name: "t"} }), "apply"},
		{"apply Host", mut(func(r *Recipe) { r.Apply = Apply{Kind: "header", Name: "Host"} }), "apply"},
		{"apply Authorization header", mut(func(r *Recipe) { r.Apply = Apply{Kind: "header", Name: "Authorization"} }), "apply"},
		{"apply Content-Length", mut(func(r *Recipe) { r.Apply = Apply{Kind: "header", Name: "Content-Length"} }), "apply"},
		{"apply Cookie hdr", mut(func(r *Recipe) { r.Apply = Apply{Kind: "header", Name: "Cookie"} }), "apply"},
		{"apply header no name", mut(func(r *Recipe) { r.Apply = Apply{Kind: "header"} }), "apply"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			err := c.r.Validate()
			var re *RecipeError
			if !errors.As(err, &re) {
				t.Fatalf("want RecipeError, got %v", err)
			}
			if re.Field != c.field {
				t.Fatalf("field = %q want %q (%v)", re.Field, c.field, err)
			}
		})
	}
	for _, ok := range []Recipe{
		mut(func(r *Recipe) { r.Method = "PUT"; r.ContentType = "form" }),
		mut(func(r *Recipe) {
			r.TokenFrom = TokenFrom{Kind: "header", Name: "X-Auth-Token"}
			r.Apply = Apply{Kind: "header", Name: "X-Token"}
		}),
		mut(func(r *Recipe) {
			r.TokenFrom = TokenFrom{Kind: "cookie", Name: "sid"}
			r.Apply = Apply{Kind: "cookie", Name: "sid"}
		}),
	} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
}

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestBuildLoginRequestEncoding(t *testing.T) {
	env := envMap(map[string]string{"ALICE_USER": "alice", "ALICE_PASS": canary + "\n"})
	r := goodRecipe()
	req, err := r.BuildRequest(env)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.Path != "/auth/login" || req.Header["Content-Type"] != "application/json" {
		t.Fatalf("%+v", req)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(req.Body.Expose()), &got); err != nil {
		t.Fatalf("body not valid json (injection?): %v", err)
	}
	if got["password"] != canary || got["username"] != "alice" || got["tenant"] != "acme" || len(got) != 3 {
		t.Fatalf("%v", got)
	}
	if s := fmt.Sprintf("%+v %#v %v", req, req, req); strings.Contains(s, "CANARY") || strings.Contains(s, "alice") && strings.Contains(s, "password") {
		t.Fatalf("LoginRequest leaks: %s", s)
	}

	r.ContentType = "form"
	req, err = r.BuildRequest(env)
	if err != nil {
		t.Fatal(err)
	}
	if req.Header["Content-Type"] != "application/x-www-form-urlencoded" {
		t.Fatal(req.Header)
	}
	b := req.Body.Expose()
	if strings.Count(b, "&") != 2 || strings.Contains(b, `"`) || strings.Contains(b, "CANARY=") {
		t.Fatalf("form not encoded: %q", b)
	}
	if !strings.Contains(b, "password=s3cr3t-CANARY-%22%26%3Dvalue") {
		t.Fatalf("form body %q", b)
	}
}

func TestBuildRequestEnvFailures(t *testing.T) {
	r := goodRecipe()
	for _, v := range []string{"", "a\r\nX: y", "   "} {
		_, err := r.BuildRequest(envMap(map[string]string{"ALICE_USER": "alice", "ALICE_PASS": v}))
		if err == nil || !strings.Contains(err.Error(), "ALICE_PASS") {
			t.Fatalf("value %q: %v", v, err)
		}
		if v != "" && strings.Contains(err.Error(), strings.TrimSpace(v)) && strings.TrimSpace(v) != "" {
			t.Fatalf("leak: %v", err)
		}
	}
}

type fakeResp struct {
	status int
	header map[string][]string
	body   string
	err    error
}

type fakeDoer struct {
	resp  map[string]fakeResp // keyed by username canary? keyed by path
	calls int
	reqs  []LoginRequest
}

func (d *fakeDoer) Do(_ context.Context, req LoginRequest) (LoginResponse, error) {
	d.calls++
	d.reqs = append(d.reqs, req)
	r := d.resp[req.Path]
	if r.err != nil {
		return LoginResponse{}, r.err
	}
	return LoginResponse{Status: r.status, Header: r.header, Body: io.NopCloser(strings.NewReader(r.body))}, nil
}

func jsonHdr() map[string][]string {
	return map[string][]string{"Content-Type": {"application/json; charset=utf-8"}}
}

func TestExtractToken(t *testing.T) {
	big := `{"access_token":"` + strings.Repeat("a", 70*1024) + `"}`
	cases := []struct {
		name   string
		from   TokenFrom
		resp   fakeResp
		want   string
		reason string
	}{
		{"json ok", TokenFrom{"json", "/access_token"}, fakeResp{200, jsonHdr(), `{"access_token":"tok1"}`, nil}, "tok1", ""},
		{"json nested/escaped", TokenFrom{"json", "/a~1b/c~0d"}, fakeResp{200, jsonHdr(), `{"a/b":{"c~d":"tok2"}}`, nil}, "tok2", ""},
		{"json +json type", TokenFrom{"json", "/t"}, fakeResp{201, map[string][]string{"content-type": {"application/vnd.api+json"}}, `{"t":"tok3"}`, nil}, "tok3", ""},
		{"json array idx", TokenFrom{"json", "/t/0"}, fakeResp{200, jsonHdr(), `{"t":["tok4"]}`, nil}, "tok4", ""},
		{"json missing", TokenFrom{"json", "/access_token"}, fakeResp{200, jsonHdr(), `{"other":"x"}`, nil}, "", ReasonTokenNotFound},
		{"json not string", TokenFrom{"json", "/access_token"}, fakeResp{200, jsonHdr(), `{"access_token":5}`, nil}, "", ReasonTokenNotFound},
		{"json empty", TokenFrom{"json", "/access_token"}, fakeResp{200, jsonHdr(), `{"access_token":""}`, nil}, "", ReasonTokenNotFound},
		{"json CRLF", TokenFrom{"json", "/access_token"}, fakeResp{200, jsonHdr(), `{"access_token":"a\r\nX: y"}`, nil}, "", ReasonTokenInvalid},
		{"json NUL", TokenFrom{"json", "/access_token"}, fakeResp{200, jsonHdr(), `{"access_token":"a\u0000b"}`, nil}, "", ReasonTokenInvalid},
		{"json malformed", TokenFrom{"json", "/access_token"}, fakeResp{200, jsonHdr(), `not json`, nil}, "", ReasonTokenNotFound},
		{"json wrong ctype", TokenFrom{"json", "/access_token"}, fakeResp{200, map[string][]string{"Content-Type": {"text/html"}}, `{"access_token":"x"}`, nil}, "", ReasonContentType},
		{"json over cap", TokenFrom{"json", "/access_token"}, fakeResp{200, jsonHdr(), big, nil}, "", ReasonBodyTooLarge},
		{"401", TokenFrom{"json", "/access_token"}, fakeResp{401, jsonHdr(), `{"access_token":"x"}`, nil}, "", ReasonStatus},
		{"500", TokenFrom{"json", "/access_token"}, fakeResp{500, jsonHdr(), ``, nil}, "", ReasonStatus},
		{"redirect json", TokenFrom{"json", "/access_token"}, fakeResp{302, map[string][]string{"Location": {"http://evil.example.com/"}}, ``, nil}, "", ReasonRedirect},
		{"header ok", TokenFrom{"header", "X-Auth-Token"}, fakeResp{200, map[string][]string{"x-auth-token": {"tokH"}}, ``, nil}, "tokH", ""},
		{"header bearer prefix", TokenFrom{"header", "Authorization"}, fakeResp{200, map[string][]string{"Authorization": {"Bearer tokB"}}, ``, nil}, "tokB", ""},
		{"header missing", TokenFrom{"header", "X-Auth-Token"}, fakeResp{200, nil, ``, nil}, "", ReasonTokenNotFound},
		{"header CRLF", TokenFrom{"header", "X-Auth-Token"}, fakeResp{200, map[string][]string{"X-Auth-Token": {"a\r\nb"}}, ``, nil}, "", ReasonTokenInvalid},
		{"cookie ok", TokenFrom{"cookie", "sid"}, fakeResp{200, map[string][]string{"Set-Cookie": {"other=1; Path=/", "sid=tokC; HttpOnly"}}, ``, nil}, "tokC", ""},
		{"cookie on 3xx", TokenFrom{"cookie", "sid"}, fakeResp{302, map[string][]string{"Set-Cookie": {"sid=tokD"}, "Location": {"http://evil.example.com/"}}, ``, nil}, "tokD", ""},
		{"cookie missing", TokenFrom{"cookie", "sid"}, fakeResp{200, map[string][]string{"Set-Cookie": {"x=1"}}, ``, nil}, "", ReasonTokenNotFound},
		{"cookie 3xx missing", TokenFrom{"cookie", "sid"}, fakeResp{302, nil, ``, nil}, "", ReasonRedirect},
		{"transport", TokenFrom{"json", "/t"}, fakeResp{err: errors.New("dial https://h.example.com/login?pw=" + canary)}, "", ReasonTransport},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := goodRecipe()
			r.TokenFrom = c.from
			env := envMap(map[string]string{"ALICE_USER": "alice", "ALICE_PASS": canary})
			p := NewProvider(map[string]Recipe{"alice": r})
			p.Lookup = env
			d := &fakeDoer{resp: map[string]fakeResp{"/auth/login": c.resp}}
			cred, err := p.For(context.Background(), "alice", d)
			if c.reason == "" {
				if err != nil {
					t.Fatal(err)
				}
				if cred.Token.Expose() != c.want {
					t.Fatalf("token = %q", cred.Token.Expose())
				}
				return
			}
			var le *LoginError
			if !errors.As(err, &le) {
				t.Fatalf("want LoginError, got %v", err)
			}
			if le.Reason != c.reason {
				t.Fatalf("reason = %s want %s", le.Reason, c.reason)
			}
			msg := err.Error()
			for _, bad := range []string{"CANARY", "evil", "x\"", "access_token\":", "tokH", "?pw"} {
				if strings.Contains(msg, bad) {
					t.Fatalf("message leaks %q: %s", bad, msg)
				}
			}
			if !strings.Contains(msg, "login identity=alice") || !strings.Contains(msg, "reason="+c.reason) {
				t.Fatalf("message format: %s", msg)
			}
		})
	}
}

func TestProviderOneLoginPerIdentityNoRelogin(t *testing.T) {
	r := goodRecipe()
	p := NewProvider(map[string]Recipe{"alice": r, "bob": r})
	p.Lookup = envMap(map[string]string{"ALICE_USER": "alice", "ALICE_PASS": "pw"})
	d := &fakeDoer{resp: map[string]fakeResp{"/auth/login": {200, jsonHdr(), `{"access_token":"tokA"}`, nil}}}
	for i := 0; i < 5; i++ { // a 401 on a probe item calls For again; it must not log in again
		c, err := p.For(context.Background(), "alice", d)
		if err != nil || c.Token.Expose() != "tokA" {
			t.Fatal(err)
		}
	}
	if d.calls != 1 {
		t.Fatalf("login count = %d, want 1", d.calls)
	}
	d.resp["/auth/login"] = fakeResp{200, jsonHdr(), `{"access_token":"tokB"}`, nil}
	cb, err := p.For(context.Background(), "bob", d)
	if err != nil || d.calls != 2 {
		t.Fatalf("bob: %v calls=%d", err, d.calls)
	}
	ca, _ := p.For(context.Background(), "alice", d)
	if ca.Token.Expose() != "tokA" || cb.Token.Expose() != "tokB" || ca.Identity != "alice" || cb.Identity != "bob" {
		t.Fatal("cross-identity token mix")
	}
}

func TestProviderFailureIsCachedAndFailsClosed(t *testing.T) {
	p := NewProvider(map[string]Recipe{"alice": goodRecipe()})
	p.Lookup = envMap(map[string]string{"ALICE_USER": "a", "ALICE_PASS": "pw"})
	d := &fakeDoer{resp: map[string]fakeResp{"/auth/login": {401, jsonHdr(), `{}`, nil}}}
	for i := 0; i < 3; i++ {
		if _, err := p.For(context.Background(), "alice", d); err == nil {
			t.Fatal("want error")
		}
	}
	if d.calls != 1 {
		t.Fatalf("calls = %d", d.calls)
	}
	if _, err := p.For(context.Background(), "nobody", d); !errors.Is(err, ErrNoRecipe) {
		t.Fatalf("got %v", err)
	}
	if d.calls != 1 {
		t.Fatal("login attempted for unknown identity")
	}
}

func TestProviderEnvMissingNoRequestSent(t *testing.T) {
	p := NewProvider(map[string]Recipe{"alice": goodRecipe()})
	p.Lookup = envMap(map[string]string{"ALICE_USER": "a"})
	d := &fakeDoer{}
	_, err := p.For(context.Background(), "alice", d)
	if err == nil || d.calls != 0 || strings.Contains(err.Error(), "alice_pw") {
		t.Fatalf("err=%v calls=%d", err, d.calls)
	}
	var le *LoginError
	if !errors.As(err, &le) || le.Reason != ReasonEnv {
		t.Fatalf("reason: %v", err)
	}
}

func TestProviderFingerprintCheck(t *testing.T) {
	p := NewProvider(map[string]Recipe{"alice": goodRecipe()})
	p.Lookup = envMap(map[string]string{"ALICE_USER": "a", "ALICE_PASS": "pw"})
	p.ExpectFP = map[string]string{"alice": "000000000000"}
	d := &fakeDoer{resp: map[string]fakeResp{"/auth/login": {200, jsonHdr(), `{"access_token":"tokA"}`, nil}}}
	_, err := p.For(context.Background(), "alice", d)
	var le *LoginError
	if !errors.As(err, &le) || le.Reason != ReasonFingerprint {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "tokA") {
		t.Fatal("leak")
	}
}

func TestCredentialApply(t *testing.T) {
	tok := NewSecret([]byte("TOK"))
	cases := []struct {
		a          Apply
		name, want string
	}{
		{Apply{Kind: "bearer"}, "Authorization", "Bearer TOK"},
		{Apply{Kind: "header", Name: "X-Token"}, "X-Token", "TOK"},
		{Apply{Kind: "cookie", Name: "sid"}, "Cookie", "sid=TOK"},
	}
	for _, c := range cases {
		cred := Credential{Identity: "a", Apply: c.a, Token: tok}
		var gn, gv string
		cred.SetOn(func(n, v string) { gn, gv = n, v })
		if gn != c.name || gv != c.want {
			t.Errorf("%v: %s=%s", c.a, gn, gv)
		}
		if s := fmt.Sprintf("%v %+v %#v", cred, cred, cred); strings.Contains(s, "TOK") && !strings.Contains(s, "REDACTED") {
			t.Errorf("credential leaks: %s", s)
		}
		if strings.Contains(fmt.Sprintf("%+v", cred), "TOK") {
			t.Errorf("credential leaks: %+v", cred)
		}
	}
}

func TestProviderClose(t *testing.T) {
	p := NewProvider(map[string]Recipe{"alice": goodRecipe()})
	p.Lookup = envMap(map[string]string{"ALICE_USER": "a", "ALICE_PASS": "pw"})
	d := &fakeDoer{resp: map[string]fakeResp{"/auth/login": {200, jsonHdr(), `{"access_token":"tokA"}`, nil}}}
	c, _ := p.For(context.Background(), "alice", d)
	p.Close()
	if strings.Trim(c.Token.Expose(), "\x00") != "" {
		t.Fatal("token not zeroed")
	}
}

// TestNoNetworkImports keeps credentials free of dialing packages: login is
// sent by exec through its pinned, safety-checked client.
func TestNoNetworkImports(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	banned := map[string]bool{"net": true, "net/http": true, "net/rpc": true, "net/smtp": true, "net/textproto": true, "os/exec": true, "crypto/tls": true}
	fset := token.NewFileSet()
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if banned[p] {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
}

// KAN-39 F3: static token_env credentials.
func TestProviderStaticToken(t *testing.T) {
	p := NewProvider(map[string]Recipe{})
	p.TokenEnv = map[string]string{"alice": "ALICE_TOK", "bob": "BOB_TOK"}
	p.Lookup = func(k string) string {
		if k == "ALICE_TOK" {
			return "static-canary\n"
		}
		return ""
	}
	c, err := p.For(context.Background(), "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	var h, v string
	c.SetOn(func(n, val string) { h, v = n, val })
	if h != "Authorization" || v != "Bearer static-canary" {
		t.Fatalf("%q %q", h, v)
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", c, c, c), "static-canary") {
		t.Fatal("token leaked in formatting")
	}
	if _, err := p.For(context.Background(), "bob", nil); err == nil || strings.Contains(err.Error(), "BOB_TOK=") {
		t.Fatalf("unset env must fail: %v", err)
	}
	if _, err := p.For(context.Background(), "carol", nil); !errors.Is(err, ErrNoRecipe) {
		t.Fatalf("carol: %v", err)
	}
	if err := p.CheckEnv(); err == nil || !strings.Contains(err.Error(), "BOB_TOK") {
		t.Fatalf("CheckEnv must flag the unset var: %v", err)
	}
}
