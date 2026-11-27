package config

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"authzcov/internal/redact"
)

const v1Full = `version: 1
roles: {user: 10, admin: 100}
credentials:
  - {type: bearer, header: Authorization, schemes: [Bearer, Token]}
  - {type: cookie, name: SESSION}
  - {type: apikey, header: X-API-Key}
  - {type: basic}
jwt: {subject: claims.sub}
identities:
  - name: alice
    role: user
    tenant: acme
    match: {token_sha256: ` + h64a + `}
    markers: [alice-marker]
  - name: bob
    role: user
    tenant: acme
    match: {apikey_sha256: ` + h64b + `}
  - name: carol
    role: admin
    match: {basic_user: carol, login: carol-login}
  - {name: dave, role: user, tenant: acme, match: {jwt: {sub: dave}, login: dave}}
learn_tokens:
  - match: {method: POST, path: /users/v1/login}
    identity_from: {request_json: username}
    token_from: {response_json: auth_token}
`

const (
	h64a = "aaaaaaaaaaaabbbbbbbbbbbbccccccccccccddddddddddddeeeeeeeeeeeeffff"
	h64b = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestParseV1Full(t *testing.T) {
	f, err := Parse([]byte(v1Full), "ids.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := &File{
		Path:    "ids.yaml",
		Version: 1,
		Roles:   map[string]int{"user": 10, "admin": 100},
		Credentials: []Credential{
			{Type: "bearer", Header: "Authorization", Schemes: []string{"Bearer", "Token"}, Line: 4},
			{Type: "cookie", Name: "SESSION", Line: 5},
			{Type: "apikey", Header: "X-API-Key", Line: 6},
			{Type: "basic", Line: 7},
		},
		JWTSubject: "claims.sub",
		Identities: []Identity{
			{Name: "alice", Role: "user", Tenant: "acme", TokenFP: h64a[:12], Markers: []string{"alice-marker"}, Line: 10},
			{Name: "bob", Role: "user", Tenant: "acme", TokenFP: h64b[:12], Line: 15},
			{Name: "carol", Role: "admin", BasicUser: "carol", Login: "carol-login", Line: 19},
			{Name: "dave", Role: "user", Tenant: "acme", JWT: map[string]string{"sub": "dave"}, Login: "dave", Line: 22},
		},
		Resources: map[string]string{},
		LearnTokens: []LearnToken{
			{Method: "POST", Path: "/users/v1/login", IdentityFromRequestJSON: "username", TokenFromResponseJSON: "auth_token", Line: 24},
		},
	}
	if !reflect.DeepEqual(f, want) {
		t.Errorf("got  %+v\nwant %+v", f, want)
	}
}

func TestV1Defaults(t *testing.T) {
	f, err := Parse([]byte(base), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	wantCred := []Credential{{Type: "bearer", Header: "Authorization", Schemes: []string{"Bearer"}}}
	if !reflect.DeepEqual(f.Credentials, wantCred) || f.JWTSubject != "sub" || f.LearnTokens != nil {
		t.Errorf("defaults: %+v %q %v", f.Credentials, f.JWTSubject, f.LearnTokens)
	}
	// bearer defaults
	y := strings.Replace(base, "identities:", "credentials: [{type: bearer}]\nidentities:", 1)
	f, err = Parse([]byte(y), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c := f.Credentials[0]
	if c.Header != "Authorization" || !reflect.DeepEqual(c.Schemes, []string{"Bearer"}) {
		t.Errorf("bearer defaults: %+v", c)
	}
}

func TestV1Errors(t *testing.T) {
	cred := func(s string) []string { return []string{"identities:", "credentials: " + s + "\nidentities:"} }
	match := func(s string) []string { return []string{"match: {jwt: {sub: bob}}", "match: " + s} }
	learn := func(s string) []string { return []string{"resources:", "learn_tokens:\n" + s + "resources:"} }
	const lt = "  - match: {method: POST, path: /login}\n    identity_from: {request_json: u}\n    token_from: {response_json: t}\n"
	tests := []struct {
		name string
		mut  []string
		line int
		path string
		msg  string
	}{
		{"cred bad type", cred("[{type: oauth}]"), 3, "credentials[0].type", "must be one of"},
		{"cred missing type", cred("[{header: X}]"), 3, "credentials[0].type", "required"},
		{"cred not list", cred("{type: basic}"), 3, "credentials", "must be a list"},
		{"cred empty list", cred("[]"), 3, "credentials", "between 1 and 20"},
		{"cookie no name", cred("[{type: cookie}]"), 3, "credentials[0].name", "required"},
		{"apikey no header", cred("[{type: apikey}]"), 3, "credentials[0].header", "required"},
		{"basic extra key", cred("[{type: basic, header: X}]"), 3, "credentials[0]", `unknown key "header"`},
		{"bearer name key", cred("[{type: bearer, name: X}]"), 3, "credentials[0]", `unknown key "name"`},
		{"bearer empty scheme", cred("[{type: bearer, schemes: ['']}]"), 3, "credentials[0].schemes[0]", "must not be empty"},
		{"bearer schemes not list", cred("[{type: bearer, schemes: Bearer}]"), 3, "credentials[0].schemes", "must be a list"},
		{"bearer empty header", cred("[{type: bearer, header: ''}]"), 3, "credentials[0].header", "must not be empty"},
		{"jwt subject deep", []string{"identities:", "jwt: {subject: a.b.c.d.e.f}\nidentities:"}, 3, "jwt.subject", "depth"},
		{"jwt subject bad", []string{"identities:", "jwt: {subject: 'a..b'}\nidentities:"}, 3, "jwt.subject", "dot path"},
		{"jwt unknown key", []string{"identities:", "jwt: {sub: x}\nidentities:"}, 3, "jwt", `unknown key "sub"`},
		{"sha wrong length", match("{token_sha256: abcd}"), 5, "identities[1].match.token_sha256", "64 lower-case hex"},
		{"sha upper", match("{token_sha256: " + strings.ToUpper(h64a) + "}"), 5, "identities[1].match.token_sha256", "64 lower-case hex"},
		{"sha non hex", match("{apikey_sha256: " + strings.Repeat("z", 64) + "}"), 5, "identities[1].match.apikey_sha256", "64 lower-case hex"},
		{"both sha", match("{token_sha256: " + h64a + ", apikey_sha256: " + h64a + "}"), 5, "identities[1].match", "only one of"},
		{"bad env name", match("{token_env: lower}"), 5, "identities[1].match.token_env", "must match"},
		{"empty match", match("{}"), 5, "identities[1].match", "at least one"},
		{"unknown match key", match("{foo: bar}"), 5, "identities[1].match", `unknown key "foo"`},
		{"empty basic_user", match("{basic_user: ''}"), 5, "identities[1].match.basic_user", "must not be empty"},
		{"empty login", match("{login: ''}"), 5, "identities[1].match.login", "must not be empty"},
		{"short marker", []string{"tenant: acme, match", "tenant: acme, markers: [abc], match"}, 5, "identities[1].markers[0]", "at least 6"},
		{"markers not list", []string{"tenant: acme, match", "tenant: acme, markers: abcdefgh, match"}, 5, "identities[1].markers", "must be a list"},
		{"learn bad method", learn(strings.Replace(lt, "POST", "post", 1)), 7, "learn_tokens[0].match.method", "upper-case"},
		{"learn bad path", learn(strings.Replace(lt, "/login", "login", 1)), 7, "learn_tokens[0].match.path", `start with "/"`},
		{"learn no identity_from", learn(strings.Replace(lt, "    identity_from: {request_json: u}\n", "", 1)), 7, "learn_tokens[0].identity_from", "required"},
		{"learn no token_from", learn(strings.Replace(lt, "    token_from: {response_json: t}\n", "", 1)), 7, "learn_tokens[0].token_from", "required"},
		{"learn request_form", learn(strings.Replace(lt, "request_json: u", "request_form: u", 1)), 8, "learn_tokens[0].identity_from.request_form", "not supported yet"},
		{"learn identity basic_user", learn(strings.Replace(lt, "request_json: u", "basic_user: u", 1)), 8, "learn_tokens[0].identity_from.basic_user", "not supported yet"},
		{"learn response_header", learn(strings.Replace(lt, "response_json: t", "response_header: t", 1)), 9, "learn_tokens[0].token_from.response_header", "not supported yet"},
		{"learn set_cookie", learn(strings.Replace(lt, "response_json: t", "set_cookie: t", 1)), 9, "learn_tokens[0].token_from.set_cookie", "not supported yet"},
		{"learn empty field", learn(strings.Replace(lt, "request_json: u", "request_json: ''", 1)), 8, "learn_tokens[0].identity_from.request_json", "must not be empty"},
		{"raw secret key in credentials", cred("[{type: cookie, name: S, token: abc123}]"), 3, "credentials[0]", "raw credentials"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y := base
			for i := 0; i+1 < len(tt.mut); i += 2 {
				if !strings.Contains(y, tt.mut[i]) {
					t.Fatalf("mutation %q not found in base", tt.mut[i])
				}
				y = strings.Replace(y, tt.mut[i], tt.mut[i+1], 1)
			}
			_, err := Parse([]byte(y), "ids.yaml")
			var ce *Error
			if !errors.As(err, &ce) {
				t.Fatalf("err = %v (%T), want *Error", err, err)
			}
			if tt.line > 0 && ce.Line != tt.line {
				t.Errorf("line = %d, want %d (%v)", ce.Line, tt.line, ce)
			}
			if ce.Path != tt.path {
				t.Errorf("path = %q, want %q (%v)", ce.Path, tt.path, ce)
			}
			if !strings.Contains(ce.Msg, tt.msg) {
				t.Errorf("msg = %q, want substring %q", ce.Msg, tt.msg)
			}
			for _, secret := range []string{h64a, strings.ToUpper(h64a), "abc123", "abcdefgh"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error echoes %q: %v", secret, err)
				}
			}
		})
	}
}

func TestTokenEnv(t *testing.T) {
	const val = "super-secret-env-token-value"
	y := strings.Replace(base, "match: {jwt: {sub: bob}}", "match: {token_env: AUTHZCOV_TEST_TOK}", 1)
	t.Run("set", func(t *testing.T) {
		t.Setenv("AUTHZCOV_TEST_TOK", val)
		f, err := Parse([]byte(y), "x.yaml")
		if err != nil {
			t.Fatal(err)
		}
		if got := f.Identities[1].TokenFP; got != redact.Fingerprint(val) {
			t.Errorf("TokenFP = %q", got)
		}
		if out := fmt.Sprintf("%+v %#v", *f, *f); strings.Contains(out, val) {
			t.Errorf("env value leaked: %s", out)
		}
	})
	for name, set := range map[string]bool{"unset": false, "empty": true} {
		t.Run(name, func(t *testing.T) {
			if set {
				t.Setenv("AUTHZCOV_TEST_TOK", "")
			}
			_, err := Parse([]byte(y), "x.yaml")
			var ce *Error
			if !errors.As(err, &ce) {
				t.Fatalf("err = %v", err)
			}
			if ce.Path != "identities[1].match.token_env" || ce.Line != 5 ||
				!strings.Contains(ce.Msg, "env var AUTHZCOV_TEST_TOK is empty or unset") {
				t.Errorf("got %+v", ce)
			}
		})
	}
}

func TestWarnings(t *testing.T) {
	mk := func(ids ...string) *File {
		f := &File{}
		for _, s := range ids {
			r, tn, _ := strings.Cut(s, "/")
			f.Identities = append(f.Identities, Identity{Name: s, Role: r, Tenant: tn})
		}
		return f
	}
	w := func(r, t string) string {
		return fmt.Sprintf("role %q has fewer than two identities in tenant %q: same_role_other_user cannot be covered", r, t)
	}
	tests := []struct {
		name string
		f    *File
		want []string
	}{
		{"none", mk("user", "user"), nil},
		{"empty", mk(), nil},
		{"single", mk("user"), []string{w("user", "")}},
		{"per tenant", mk("user/a", "user/a", "user/b", "admin/a"), []string{w("admin", "a"), w("user", "b")}},
		{"sorted", mk("zed/b", "zed/a", "alpha/z", "alpha/a"), []string{w("alpha", "a"), w("alpha", "z"), w("zed", "a"), w("zed", "b")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.f.Warnings()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q want %q", got, tt.want)
			}
			if !reflect.DeepEqual(tt.f.Warnings(), got) {
				t.Error("not deterministic")
			}
		})
	}
}

func TestTopLevelKeys(t *testing.T) {
	got := TopLevelKeys()
	if !sort.StringsAreSorted(got) || len(got) != 10 {
		t.Fatalf("TopLevelKeys() = %v", got)
	}
	// Every listed key must be accepted by the parser (error must not be "unknown key").
	for _, k := range got {
		_, err := Parse([]byte(k+": {}\n"), "x.yaml")
		if err != nil && strings.Contains(err.Error(), "unknown key") {
			t.Errorf("key %q rejected as unknown: %v", k, err)
		}
	}
	if _, err := Parse([]byte("bogus: 1\n"), "x.yaml"); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Errorf("bogus key not rejected: %v", err)
	}
}
