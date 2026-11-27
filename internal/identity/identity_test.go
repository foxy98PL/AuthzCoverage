package identity

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"authzcov/internal/model"
	"authzcov/internal/redact"
)

func hdr(kv ...string) func(string) []string {
	m := map[string][]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		k := strings.ToLower(kv[i])
		m[k] = append(m[k], kv[i+1])
	}
	return func(name string) []string { return m[strings.ToLower(name)] }
}

func mkJWT(t testing.TB, claims jwt.MapClaims) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func sigOf(tok string) string { return tok[strings.LastIndex(tok, ".")+1:] }

func TestExtract(t *testing.T) {
	alice := mkJWT(t, jwt.MapClaims{"sub": "alice"})
	tests := []struct {
		name     string
		h        func(string) []string
		kind     string
		fp       string
		sub      string
		noClaims bool
	}{
		{"bearer jwt", hdr("Authorization", "Bearer "+alice), KindBearer, redact.Fingerprint(alice), "alice", false},
		{"lowercase scheme", hdr("authorization", "bearer "+alice), KindBearer, redact.Fingerprint(alice), "alice", false},
		{"opaque bearer", hdr("Authorization", "Bearer opaque-secret-123"), KindBearer, redact.Fingerprint("opaque-secret-123"), "", true},
		{"basic", hdr("Authorization", "Basic dXNlcjpwYXNz"), KindAuthorization, redact.Fingerprint("Basic dXNlcjpwYXNz"), "", true},
		{"token scheme", hdr("Authorization", "Token x"), KindAuthorization, redact.Fingerprint("Token x"), "", true},
		{"empty bearer", hdr("Authorization", "Bearer "), KindBearer, redact.Fingerprint(""), "", true},
		{"cookie", hdr("Cookie", "sid=abc"), KindCookie, redact.Fingerprint("sid=abc"), "", true},
		{"multi cookie", hdr("Cookie", "a=1", "Cookie", "b=2"), KindCookie, redact.Fingerprint("a=1; b=2"), "", true},
		{"api key", hdr("X-API-Key", "k123"), KindAPIKey, redact.Fingerprint("k123"), "", true},
		{"x-auth-token", hdr("X-Auth-Token", "t1"), KindAPIKey, redact.Fingerprint("t1"), "", true},
		{"auth beats cookie", hdr("Cookie", "sid=abc", "Authorization", "Basic x"), KindAuthorization, redact.Fingerprint("Basic x"), "", true},
		{"cookie beats apikey", hdr("Cookie", "sid=abc", "X-API-Key", "k"), KindCookie, redact.Fingerprint("sid=abc"), "", true},
		{"none", hdr(), KindNone, "", "", true},
		{"empty cookie", hdr("Cookie", ""), KindNone, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Extract(tt.h)
			if c.Kind != tt.kind || c.Fingerprint != tt.fp {
				t.Fatalf("got kind=%q fp=%q, want %q %q", c.Kind, c.Fingerprint, tt.kind, tt.fp)
			}
			if tt.kind != KindNone && len(c.Fingerprint) != 12 {
				t.Errorf("fingerprint length %d", len(c.Fingerprint))
			}
			if tt.noClaims {
				if c.Claims != nil {
					t.Errorf("claims = %v, want nil", c.Claims)
				}
			} else if c.Claims["sub"] != tt.sub {
				t.Errorf("sub = %v, want %q", c.Claims["sub"], tt.sub)
			}
		})
	}
}

func TestNoRawSecretAnywhere(t *testing.T) {
	jwtTok := mkJWT(t, jwt.MapClaims{"sub": "alice"})
	tests := []struct {
		name, header, value string
		secrets             []string
	}{
		{"bearer jwt", "Authorization", "Bearer " + jwtTok, []string{jwtTok, sigOf(jwtTok)}},
		{"bearer opaque", "Authorization", "Bearer sup3r-s3cret-token", []string{"sup3r-s3cret-token"}},
		{"basic", "Authorization", "Basic c2VjcmV0cGFzcw==", []string{"c2VjcmV0cGFzcw=="}},
		{"cookie", "Cookie", "session=cookie-secret-value", []string{"cookie-secret-value"}},
		{"apikey", "X-API-Key", "api-key-secret-value", []string{"api-key-secret-value"}},
	}
	r := NewResolver([]Rule{{Identity: model.Identity{Name: "alice"}, JWT: map[string]string{"sub": "alice"}}}, "sub")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Extract(hdr(tt.header, tt.value))
			id, _ := r.Resolve(c)
			out := fmt.Sprintf("%+v|%+v", c, *id)
			for _, s := range tt.secrets {
				if strings.Contains(out, s) {
					t.Errorf("output leaks %q", s)
				}
			}
		})
	}
}

func TestDecodeClaims(t *testing.T) {
	big := mkJWT(t, jwt.MapClaims{"sub": "alice", "pad": strings.Repeat("x", MaxJWT)})
	if _, err := DecodeClaims(big); err == nil {
		t.Fatal("oversized token accepted")
	} else if strings.Contains(err.Error(), big[:40]) {
		t.Error("error leaks token")
	}
	if c := Extract(hdr("Authorization", "Bearer "+big)); c.Claims != nil || c.Kind != KindBearer {
		t.Errorf("oversized: kind=%q claims=%v", c.Kind, c.Claims)
	}
	if id, conf := NewResolver(nil, "sub").Resolve(Extract(hdr("Authorization", "Bearer "+big))); id.Anonymous || conf != model.ConfUnknown {
		t.Errorf("oversized resolved to %+v %v", id, conf)
	}

	if _, err := DecodeClaims("not-a-jwt"); err == nil {
		t.Error("garbage accepted")
	}

	// Unverified by design: alg none and wrong-key tokens still decode.
	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "mallory"}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	other, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "eve"}).SignedString([]byte("other-key"))
	if err != nil {
		t.Fatal(err)
	}
	for tok, want := range map[string]string{none: "mallory", other: "eve"} {
		cl, err := DecodeClaims(tok)
		if err != nil || cl["sub"] != want {
			t.Errorf("DecodeClaims = %v, %v; want sub %q", cl, err, want)
		}
	}
}

func TestResolve(t *testing.T) {
	alice := mkJWT(t, jwt.MapClaims{"sub": "alice", "tier": "gold", "n": 42})
	aliceFP8 := redact.Fingerprint(alice)[:8]
	ra := Rule{Identity: model.Identity{Name: "alice", Role: "user", Rank: 10}, JWT: map[string]string{"sub": "alice"}}
	tests := []struct {
		name  string
		rules []Rule
		h     func(string) []string
		want  string
		conf  model.Confidence
		anon  bool
		role  string
		rank  int
		subj  string
	}{
		{"match", []Rule{ra}, hdr("Authorization", "Bearer "+alice), "alice", model.ConfDeclared, false, "user", 10, "alice"},
		{"and both", []Rule{{Identity: model.Identity{Name: "g"}, JWT: map[string]string{"sub": "alice", "tier": "gold"}}}, hdr("Authorization", "Bearer "+alice), "g", model.ConfDeclared, false, "", 0, "alice"},
		{"and one mismatch", []Rule{{Identity: model.Identity{Name: "g"}, JWT: map[string]string{"sub": "alice", "tier": "silver"}}}, hdr("Authorization", "Bearer "+alice), "unknown-" + aliceFP8, model.ConfUnknown, false, "", 0, ""},
		{"two match", []Rule{ra, {Identity: model.Identity{Name: "alice2"}, JWT: map[string]string{"tier": "gold"}}}, hdr("Authorization", "Bearer "+alice), "unknown-" + aliceFP8, model.ConfUnknown, false, "", 0, ""},
		{"no rule", nil, hdr("Authorization", "Bearer "+alice), "unknown-" + aliceFP8, model.ConfUnknown, false, "", 0, ""},
		{"numeric claim", []Rule{{Identity: model.Identity{Name: "n"}, JWT: map[string]string{"n": "42"}}}, hdr("Authorization", "Bearer "+alice), "n", model.ConfDeclared, false, "", 0, "alice"},
		{"opaque", []Rule{ra}, hdr("Authorization", "Bearer opaque"), "unknown-" + redact.Fingerprint("opaque")[:8], model.ConfUnknown, false, "", 0, ""},
		{"basic", []Rule{ra}, hdr("Authorization", "Basic abc"), "unknown-" + redact.Fingerprint("Basic abc")[:8], model.ConfUnknown, false, "", 0, ""},
		{"cookie", []Rule{ra}, hdr("Cookie", "a=b"), "unknown-" + redact.Fingerprint("a=b")[:8], model.ConfUnknown, false, "", 0, ""},
		{"apikey", []Rule{ra}, hdr("X-API-Key", "k"), "unknown-" + redact.Fingerprint("k")[:8], model.ConfUnknown, false, "", 0, ""},
		{"empty bearer", []Rule{ra}, hdr("Authorization", "Bearer "), "unknown-" + redact.Fingerprint("")[:8], model.ConfUnknown, false, "", 0, ""},
		{"anonymous", []Rule{ra}, hdr(), "anonymous", model.ConfDeclared, true, "", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, conf := NewResolver(tt.rules, "sub").Resolve(Extract(tt.h))
			if id.Name != tt.want || conf != tt.conf || id.Anonymous != tt.anon ||
				id.Role != tt.role || id.Rank != tt.rank || id.Subject != tt.subj {
				t.Errorf("got %+v %v", *id, conf)
			}
		})
	}
	t.Run("short fingerprint", func(t *testing.T) {
		id, conf := NewResolver(nil, "sub").Resolve(model.Credential{Kind: KindCookie, Fingerprint: "ab"})
		if id.Name != "unknown-ab" || conf != model.ConfUnknown {
			t.Errorf("got %+v", *id)
		}
	})
	t.Run("distinct pointers", func(t *testing.T) {
		r := NewResolver([]Rule{ra}, "sub")
		c := Extract(hdr("Authorization", "Bearer "+alice))
		a, _ := r.Resolve(c)
		a.Role = "mutated"
		b, _ := r.Resolve(c)
		if a == b || b.Role != "user" {
			t.Errorf("shared state: %+v", *b)
		}
	})
}

func TestClaimMatches(t *testing.T) {
	big := json.Number("12345678901234567890")
	claims := map[string]any{
		"sub":   "alice",
		"realm": map[string]any{"roles": []any{"admin", json.Number("7")}, "name": "r1"},
		"n":     json.Number("42"),
		"f":     1.5,
		"i":     int64(9),
		"big":   big,
		"b":     true,
		"nil":   nil,
		"m":     map[string]any{"x": "y"},
	}
	tests := []struct {
		name, path, want string
		ok               bool
	}{
		{"top string", "sub", "alice", true},
		{"top string mismatch", "sub", "bob", false},
		{"nested", "realm.name", "r1", true},
		{"nested array string", "realm.roles", "admin", true},
		{"nested array number", "realm.roles", "7", true},
		{"nested array miss", "realm.roles", "user", false},
		{"json number", "n", "42", true},
		{"json number mismatch", "n", "43", false},
		{"float", "f", "1.5", true},
		{"int", "i", "9", true},
		{"big int exact", "big", "12345678901234567890", true},
		{"big int off", "big", "12345678901234567891", false},
		{"missing", "nope", "x", false},
		{"missing nested", "realm.nope", "x", false},
		{"through non-map", "sub.x", "alice", false},
		{"bool", "b", "true", false},
		{"nil", "nil", "", false},
		{"map leaf", "m", "x", false},
		{"empty path", "", "alice", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClaimMatches(claims, tt.path, tt.want); got != tt.ok {
				t.Errorf("ClaimMatches(%q,%q) = %v", tt.path, tt.want, got)
			}
		})
	}
	if ClaimMatches(nil, "sub", "x") {
		t.Error("nil claims matched")
	}
}

func FuzzExtract(f *testing.F) {
	f.Add("Bearer abcdefghijkl", "a=b", "k")
	f.Add("Basic dXNlcjpwYXNz", "", "")
	f.Add("Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.sig", "", "")
	f.Fuzz(func(t *testing.T, auth, cookie, key string) {
		c := Extract(hdr("Authorization", auth, "Cookie", cookie, "X-API-Key", key))
		out := fmt.Sprintf("%+v", c)
		if len(auth) >= 8 && strings.Contains(out, auth) {
			t.Fatalf("authorization value leaked into %q", out)
		}
		id, _ := NewResolver(nil, "sub").Resolve(c)
		if c.Kind != KindNone && id.Anonymous {
			t.Fatal("credentialed request resolved anonymous")
		}
	})
}
