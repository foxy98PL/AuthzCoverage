package identity

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"authzcov/internal/model"
	"authzcov/internal/redact"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestNewExtractor(t *testing.T) {
	alice := mkJWT(t, jwt.MapClaims{"sub": "alice"})
	basic := b64("carol:p4ssw0rd-secret")
	bearerTok := CredSpec{Type: "bearer", Header: "Authorization", Schemes: []string{"Bearer", "Token"}}
	cookieSess := CredSpec{Type: "cookie", Name: "SESSION"}
	apikey := CredSpec{Type: "apikey", Header: "X-Custom-Key"}
	basicSpec := CredSpec{Type: "basic"}
	tests := []struct {
		name  string
		specs []CredSpec
		h     func(string) []string
		kind  string
		fp    string
		user  string // expected basic_user claim, "" = no claims
		sub   string // expected sub claim
	}{
		{"nil specs default bearer", nil, hdr("Authorization", "Bearer "+alice), KindBearer, redact.Fingerprint(alice), "", "alice"},
		{"token scheme", []CredSpec{bearerTok}, hdr("Authorization", "Token tok-123456"), KindBearer, redact.Fingerprint("tok-123456"), "", ""},
		{"token scheme not default", nil, hdr("Authorization", "Token tok-123456"), KindAuthorization, redact.Fingerprint("Token tok-123456"), "", ""},
		{"scheme case-insensitive", []CredSpec{bearerTok}, hdr("Authorization", "token tok-1"), KindBearer, redact.Fingerprint("tok-1"), "", ""},
		{"bearer custom header", []CredSpec{{Type: "bearer", Header: "X-Auth", Schemes: []string{"Bearer"}}}, hdr("X-Auth", "Bearer abc"), KindBearer, redact.Fingerprint("abc"), "", ""},
		{"cookie by name among several", []CredSpec{cookieSess}, hdr("Cookie", "a=1; SESSION=sess-value; b=2"), KindCookie, redact.Fingerprint("sess-value"), "", ""},
		{"cookie across headers", []CredSpec{cookieSess}, hdr("Cookie", "a=1", "Cookie", "SESSION=v2"), KindCookie, redact.Fingerprint("v2"), "", ""},
		{"cookie name exact", []CredSpec{cookieSess}, hdr("Cookie", "XSESSION=zz; session=yy"), KindCookie, redact.Fingerprint("XSESSION=zz; session=yy"), "", ""},
		{"apikey header", []CredSpec{apikey}, hdr("X-Custom-Key", "key-value-1"), KindAPIKey, redact.Fingerprint("key-value-1"), "", ""},
		{"basic", []CredSpec{basicSpec}, hdr("Authorization", "Basic "+basic), KindBasic, redact.Fingerprint("basic:carol"), "carol", ""},
		{"basic bad base64", []CredSpec{basicSpec}, hdr("Authorization", "Basic !!!notb64"), KindBasic, redact.Fingerprint("basic:invalid"), "", ""},
		{"basic not in specs falls back", nil, hdr("Authorization", "Basic "+basic), KindAuthorization, redact.Fingerprint("Basic " + basic), "", ""},
		{"order: cookie before bearer", []CredSpec{cookieSess, bearerTok}, hdr("Authorization", "Bearer "+alice, "Cookie", "SESSION=s1"), KindCookie, redact.Fingerprint("s1"), "", ""},
		{"order: bearer before cookie", []CredSpec{bearerTok, cookieSess}, hdr("Authorization", "Bearer "+alice, "Cookie", "SESSION=s1"), KindBearer, redact.Fingerprint(alice), "", "alice"},
		{"spec miss falls to later spec", []CredSpec{cookieSess, apikey}, hdr("X-Custom-Key", "kk-1"), KindAPIKey, redact.Fingerprint("kk-1"), "", ""},
		{"fallback cookie unknown", []CredSpec{cookieSess}, hdr("Cookie", "other=1"), KindCookie, redact.Fingerprint("other=1"), "", ""},
		{"fallback x-api-key", []CredSpec{cookieSess}, hdr("X-API-Key", "k9"), KindAPIKey, redact.Fingerprint("k9"), "", ""},
		{"none", []CredSpec{cookieSess, basicSpec}, hdr(), KindNone, "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewExtractor(tt.specs)(tt.h)
			if c.Kind != tt.kind || c.Fingerprint != tt.fp {
				t.Fatalf("got kind=%q fp=%q, want %q %q", c.Kind, c.Fingerprint, tt.kind, tt.fp)
			}
			if tt.user != "" && c.Claims["basic_user"] != tt.user {
				t.Errorf("claims = %v, want basic_user %q", c.Claims, tt.user)
			}
			if tt.user == "" && tt.sub == "" && c.Claims != nil {
				t.Errorf("claims = %v, want nil", c.Claims)
			}
			if tt.sub != "" && c.Claims["sub"] != tt.sub {
				t.Errorf("claims = %v, want sub %q", c.Claims, tt.sub)
			}
		})
	}
}

func TestExtractorNeverLeaksSecrets(t *testing.T) {
	basic := b64("carol:p4ssw0rd-secret")
	specs := []CredSpec{{Type: "cookie", Name: "SESSION"}, {Type: "apikey", Header: "X-K"}, {Type: "basic"}}
	for _, h := range []func(string) []string{
		hdr("Authorization", "Basic "+basic),
		hdr("Cookie", "SESSION=cookie-secret-val"),
		hdr("X-K", "apikey-secret-val"),
	} {
		c := NewExtractor(specs)(h)
		out := fmt.Sprintf("%+v", c)
		for _, s := range []string{"p4ssw0rd-secret", basic, "cookie-secret-val", "apikey-secret-val"} {
			if strings.Contains(out, s) {
				t.Errorf("%q leaked into %s", s, out)
			}
		}
	}
}

func TestResolveV1(t *testing.T) {
	alice := mkJWT(t, jwt.MapClaims{"sub": "alice"})
	basic := b64("carol:pw")
	fpTok := redact.Fingerprint("opaque-token-1")
	fpCookie := redact.Fingerprint("sess-1")
	specs := []CredSpec{{Type: "cookie", Name: "SESSION"}, {Type: "basic"}, {Type: "bearer", Header: "Authorization", Schemes: []string{"Bearer"}}}
	ex := NewExtractor(specs)
	idA := model.Identity{Name: "alice", Role: "user", Rank: 10}
	tests := []struct {
		name  string
		rules []Rule
		h     func(string) []string
		want  string
		conf  model.Confidence
		subj  string
	}{
		{"by token fp", []Rule{{Identity: idA, TokenFP: fpTok}}, hdr("Authorization", "Bearer opaque-token-1"), "alice", model.ConfDeclared, ""},
		{"by cookie fp", []Rule{{Identity: idA, TokenFP: fpCookie}}, hdr("Cookie", "SESSION=sess-1"), "alice", model.ConfDeclared, ""},
		{"by basic user", []Rule{{Identity: idA, BasicUser: "carol"}}, hdr("Authorization", "Basic "+basic), "alice", model.ConfDeclared, "carol"},
		{"basic user mismatch", []Rule{{Identity: idA, BasicUser: "dave"}}, hdr("Authorization", "Basic "+basic), "unknown-" + redact.Fingerprint("basic:carol")[:8], model.ConfUnknown, ""},
		{"jwt AND token ok", []Rule{{Identity: idA, JWT: map[string]string{"sub": "alice"}, TokenFP: redact.Fingerprint(alice)}}, hdr("Authorization", "Bearer "+alice), "alice", model.ConfDeclared, "alice"},
		{"jwt AND token mismatch", []Rule{{Identity: idA, JWT: map[string]string{"sub": "alice"}, TokenFP: "000000000000"}}, hdr("Authorization", "Bearer "+alice), "unknown-" + redact.Fingerprint(alice)[:8], model.ConfUnknown, ""},
		{"two matches unknown", []Rule{{Identity: idA, TokenFP: fpTok}, {Identity: model.Identity{Name: "b"}, TokenFP: fpTok}}, hdr("Authorization", "Bearer opaque-token-1"), "unknown-" + fpTok[:8], model.ConfUnknown, ""},
		{"login-only never matches", []Rule{{Identity: idA, Login: "alice"}}, hdr("Authorization", "Bearer opaque-token-1"), "unknown-" + fpTok[:8], model.ConfUnknown, ""},
		{"empty rule never matches", []Rule{{Identity: idA}}, hdr("Authorization", "Bearer opaque-token-1"), "unknown-" + fpTok[:8], model.ConfUnknown, ""},
		{"jwt rule ignores cookie", []Rule{{Identity: idA, JWT: map[string]string{"sub": "alice"}}}, hdr("Cookie", "SESSION=sess-1"), "unknown-" + fpCookie[:8], model.ConfUnknown, ""},
		{"anonymous", []Rule{{Identity: idA, TokenFP: fpTok}}, hdr(), "anonymous", model.ConfDeclared, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, conf := NewResolver(tt.rules, "sub").Resolve(ex(tt.h))
			if id.Name != tt.want || conf != tt.conf || id.Subject != tt.subj {
				t.Errorf("got %+v %v", *id, conf)
			}
		})
	}
}

func TestLearnedTokens(t *testing.T) {
	ex := NewExtractor([]CredSpec{{Type: "bearer", Header: "Authorization", Schemes: []string{"Bearer"}}})
	rules := []Rule{
		{Identity: model.Identity{Name: "alice", Role: "user", Rank: 10}, Login: "alice-login"},
		{Identity: model.Identity{Name: "bob", Role: "user", Rank: 10}, JWT: map[string]string{"sub": "bob-sub"}},
		{Identity: model.Identity{Name: "carol", Role: "admin", Rank: 100}},
	}
	call := func(r *Resolver, tok string) (*model.Identity, model.Confidence) {
		return r.Resolve(ex(hdr("Authorization", "Bearer "+tok)))
	}
	t.Run("by login, jwt subject and name", func(t *testing.T) {
		r := NewResolver(rules, "sub")
		r.LearnToken(redact.Fingerprint("t1"), "alice-login")
		r.LearnToken(redact.Fingerprint("t2"), "bob-sub")
		r.LearnToken(redact.Fingerprint("t3"), "carol")
		for tok, want := range map[string]string{"t1": "alice", "t2": "bob", "t3": "carol"} {
			id, conf := call(r, tok)
			if id.Name != want || conf != model.ConfLearned {
				t.Errorf("%s: got %+v %v", tok, *id, conf)
			}
		}
		id, _ := call(r, "t1")
		if id.Subject != "alice-login" || id.Role != "user" || id.Rank != 10 {
			t.Errorf("got %+v", *id)
		}
	})
	t.Run("unmatched login ignored", func(t *testing.T) {
		r := NewResolver(rules, "sub")
		r.LearnToken(redact.Fingerprint("t1"), "nobody")
		r.LearnToken("", "alice-login")
		if id, conf := call(r, "t1"); conf != model.ConfUnknown || !strings.HasPrefix(id.Name, "unknown-") {
			t.Errorf("got %+v %v", *id, conf)
		}
	})
	t.Run("conflict never resolves", func(t *testing.T) {
		r := NewResolver(rules, "sub")
		fp := redact.Fingerprint("t1")
		r.LearnToken(fp, "alice-login")
		r.LearnToken(fp, "bob-sub")
		r.LearnToken(fp, "alice-login")
		if id, conf := call(r, "t1"); conf != model.ConfUnknown || id.Name != "unknown-"+fp[:8] {
			t.Errorf("got %+v %v", *id, conf)
		}
	})
	t.Run("same identity twice ok", func(t *testing.T) {
		r := NewResolver(rules, "sub")
		fp := redact.Fingerprint("t1")
		r.LearnToken(fp, "alice-login")
		r.LearnToken(fp, "alice-login")
		if id, conf := call(r, "t1"); id.Name != "alice" || conf != model.ConfLearned {
			t.Errorf("got %+v %v", *id, conf)
		}
	})
	t.Run("declared beats learned", func(t *testing.T) {
		fp := redact.Fingerprint("t1")
		rs := append([]Rule{{Identity: model.Identity{Name: "dave"}, TokenFP: fp}}, rules...)
		r := NewResolver(rs, "sub")
		r.LearnToken(fp, "alice-login")
		if id, conf := call(r, "t1"); id.Name != "dave" || conf != model.ConfDeclared {
			t.Errorf("got %+v %v", *id, conf)
		}
	})
}

func TestLoginToken(t *testing.T) {
	rule := LoginRule{Method: "POST", Path: "/users/v1/login", LoginField: "username", TokenField: "auth_token"}
	red := "[redacted:" + redact.Fingerprint("secret-tok") + "]"
	mk := func(mod func(*model.Exchange)) *model.Exchange {
		x := &model.Exchange{Method: "POST", Path: "/users/v1/login", Status: 200,
			ReqJSON: []byte(`{"username":"alice","password":"[redacted:aaaaaaaaaaaa]"}`), RespJSON: []byte(`{"auth_token":"` + red + `"}`)}
		if mod != nil {
			mod(x)
		}
		return x
	}
	tests := []struct {
		name     string
		x        *model.Exchange
		template string
		wantFP   string
		wantOK   bool
	}{
		{"redacted token", mk(nil), "", redact.Fingerprint("secret-tok"), true},
		{"plain token", mk(func(x *model.Exchange) { x.RespJSON = []byte(`{"auth_token":"plain-tok"}`) }), "", redact.Fingerprint("plain-tok"), true},
		{"template match", mk(func(x *model.Exchange) { x.Path = "/v1/login/123" }), "/users/v1/login", redact.Fingerprint("secret-tok"), true},
		{"nested field", mk(func(x *model.Exchange) { x.RespJSON = []byte(`{"data":{"auth_token":"nt"}}`) }), "", "", false},
		{"401 ignored", mk(func(x *model.Exchange) { x.Status = 401 }), "", "", false},
		{"299 ok", mk(func(x *model.Exchange) { x.Status = 204 }), "", redact.Fingerprint("secret-tok"), true},
		{"wrong path", mk(func(x *model.Exchange) { x.Path = "/other" }), "/other", "", false},
		{"wrong method", mk(func(x *model.Exchange) { x.Method = "GET" }), "", "", false},
		{"no login field", mk(func(x *model.Exchange) { x.ReqJSON = []byte(`{"user":"alice"}`) }), "", "", false},
		{"login not string", mk(func(x *model.Exchange) { x.ReqJSON = []byte(`{"username":5}`) }), "", "", false},
		{"no token", mk(func(x *model.Exchange) { x.RespJSON = []byte(`{}`) }), "", "", false},
		{"bad json", mk(func(x *model.Exchange) { x.RespJSON = []byte(`{`) }), "", "", false},
		{"empty bodies", mk(func(x *model.Exchange) { x.ReqJSON, x.RespJSON = nil, nil }), "", "", false},
		{"nil exchange", nil, "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp, login, ok := LoginToken(rule, tt.x, tt.template)
			if ok != tt.wantOK || fp != tt.wantFP || (ok && login != "alice") {
				t.Errorf("got %q %q %v", fp, login, ok)
			}
		})
	}
	t.Run("dot path", func(t *testing.T) {
		r := rule
		r.TokenField = "data.auth_token"
		x := mk(func(x *model.Exchange) { x.RespJSON = []byte(`{"data":{"auth_token":"nt"}}`) })
		if fp, _, ok := LoginToken(r, x, ""); !ok || fp != redact.Fingerprint("nt") {
			t.Errorf("got %q %v", fp, ok)
		}
	})
}

func FuzzExtractSpecs(f *testing.F) {
	f.Add("Bearer abcdefghijkl", "SESSION=abcdefgh1", "kkkkkkkk1")
	f.Add("Basic dXNlcjpwYXNz", "a=b", "")
	f.Add("Token eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.sig", "", "x")
	ex := NewExtractor([]CredSpec{
		{Type: "cookie", Name: "SESSION"},
		{Type: "apikey", Header: "X-K"},
		{Type: "basic"},
		{Type: "bearer", Header: "Authorization", Schemes: []string{"Bearer", "Token"}},
	})
	f.Fuzz(func(t *testing.T, auth, cookie, key string) {
		c := ex(hdr("Authorization", auth, "Cookie", cookie, "X-K", key))
		out := fmt.Sprintf("%+v", c)
		for _, raw := range []string{auth, cookie, key} {
			if len(raw) >= 8 && strings.Contains(out, raw) {
				t.Fatalf("raw header value leaked into %q", out)
			}
		}
		id, _ := NewResolver(nil, "sub").Resolve(c)
		if c.Kind != KindNone && id.Anonymous {
			t.Fatal("credentialed request resolved anonymous")
		}
	})
}

func TestBasicFingerprintIndependentOfPassword(t *testing.T) {
	spec := []CredSpec{{Type: "basic"}}
	ex := NewExtractor(spec)
	get := func(user, pw string) (model.Credential, string) {
		v := base64.StdEncoding.EncodeToString([]byte(user + ":" + pw))
		return ex(hdr("Authorization", "Basic "+v)), v
	}
	c1, v1 := get("carol", "pw-one")
	c2, _ := get("carol", "pw-two")
	if c1.Fingerprint != c2.Fingerprint {
		t.Errorf("fingerprint depends on password: %s vs %s", c1.Fingerprint, c2.Fingerprint)
	}
	for _, bad := range []string{v1, "pw-one", "carol:pw-one", "Basic " + v1} {
		if c1.Fingerprint == redact.Fingerprint(bad) {
			t.Errorf("fingerprint equals Fingerprint(%q)", bad)
		}
	}
	if d, _ := get("dave", "pw-one"); d.Fingerprint == c1.Fingerprint {
		t.Error("different users share a fingerprint")
	}
	bad := ex(hdr("Authorization", "Basic !!!raw-secret"))
	if bad.Fingerprint != redact.Fingerprint("basic:invalid") || len(bad.Claims) != 0 {
		t.Errorf("invalid basic = %+v", bad)
	}
}
