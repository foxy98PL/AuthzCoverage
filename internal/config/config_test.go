package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const base = `version: 1
roles: {user: 10, admin: 100}
identities:
  - {name: alice, role: user, match: {jwt: {sub: alice}}}
  - {name: bob, role: user, tenant: acme, match: {jwt: {sub: bob}}}
resources: {book_title: books, username: users}
ownership:
  self_params: {username: subject}
  learn_from_create:
    - match: {method: POST, path: /books/v1}
      resource: books
      id_from: {request_json: book_title}
`

const jwtLike = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2IifQ.c2lnbmF0dXJl"

func TestParseValid(t *testing.T) {
	f, err := Parse([]byte(base), "identities.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := &File{
		Path:    "identities.yaml",
		Version: 1,
		Roles:   map[string]int{"user": 10, "admin": 100},
		Identities: []Identity{
			{Name: "alice", Role: "user", JWT: map[string]string{"sub": "alice"}, Line: 4},
			{Name: "bob", Role: "user", Tenant: "acme", JWT: map[string]string{"sub": "bob"}, Line: 5},
		},
		Resources:   map[string]string{"book_title": "books", "username": "users"},
		Credentials: defaultCredentials(),
		JWTSubject:  "sub",
		Ownership: Ownership{
			SelfParams: map[string]string{"username": "subject"},
			LearnFromCreate: []CreateRule{
				{Method: "POST", Path: "/books/v1", Resource: "books", IDFromRequestJSON: "book_title", Line: 10},
			},
		},
	}
	if !reflect.DeepEqual(f, want) {
		t.Errorf("got  %+v\nwant %+v", f, want)
	}
	if !f.HasTenants() {
		t.Error("HasTenants = false, want true")
	}
}

func TestMinimalAndNumericClaim(t *testing.T) {
	y := "version: 1\nroles: {user: 1}\nidentities:\n  - name: a\n    role: user\n    match: {jwt: {sub: 42}}\n"
	f, err := Parse([]byte(y), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if f.Identities[0].JWT["sub"] != "42" {
		t.Errorf("jwt = %v", f.Identities[0].JWT)
	}
	if f.HasTenants() {
		t.Error("HasTenants = true, want false")
	}
}

func TestParseErrors(t *testing.T) {
	// mut is old/new pairs applied to base; line numbers refer to the mutated text.
	tests := []struct {
		name string
		mut  []string
		line int // -1: do not check
		path string
		msg  string
	}{
		{"wrong version", []string{"version: 1", "version: 2"}, 1, "version", "unsupported version"},
		{"duplicate key", []string{"version: 1", "version: 1\nversion: 1"}, 2, "version", "duplicate key"},
		{"unknown top key", []string{"resources:", "resorces:"}, 6, "", `unknown key "resorces"`},
		{"unknown identity key", []string{"tenant: acme", "tenent: acme"}, 5, "identities[1]", `unknown key "tenent"`},
		{"anonymous rank", []string{"admin: 100", "anonymous: 5"}, 2, "roles.anonymous", "rank 0"},
		{"rank too big", []string{"admin: 100", "admin: 2000"}, 2, "roles.admin", "between 0 and 1000"},
		{"rank not int", []string{"admin: 100", "admin: high"}, 2, "roles.admin", "integer"},
		{"bad name", []string{"name: alice", "name: Alice"}, 4, "identities[0].name", "must match"},
		{"reserved anonymous", []string{"name: bob", "name: anonymous"}, 5, "identities[1].name", "reserved"},
		{"reserved unknown-", []string{"name: bob", "name: unknown-x"}, 5, "identities[1].name", "reserved"},
		{"duplicate name", []string{"name: bob", "name: alice"}, 5, "identities[1].name", "duplicate identity name"},
		{"unknown role", []string{"role: user, tenant", "role: ghost, tenant"}, 5, "identities[1].role", "known roles: admin, user"},
		{"empty jwt", []string{"jwt: {sub: bob}", "jwt: {}"}, 5, "identities[1].match.jwt", "at least one claim"},
		{"missing match", []string{", match: {jwt: {sub: bob}}", ""}, 5, "identities[1].match", "required"},
		{"bad resource", []string{"book_title: books", "book_title: ''"}, 6, "resources.book_title", "empty"},
		{"self_params value", []string{"username: subject}", "username: owner}"}, 8, "ownership.self_params.username", "subject"},
		{"bad method", []string{"method: POST", "method: post"}, 10, "ownership.learn_from_create[0].match.method", "upper-case"},
		{"bad path", []string{"path: /books/v1}", "path: books}"}, 10, "ownership.learn_from_create[0].match.path", `start with "/"`},
		{"missing resource", []string{"      resource: books\n", ""}, 10, "ownership.learn_from_create[0].resource", "required"},
		{"empty id_from", []string{"request_json: book_title", "request_json: ''"}, 12, "ownership.learn_from_create[0].id_from.request_json", "empty"},
		{"anchor", []string{"name: alice", "name: &a alice"}, 4, "", "anchors and aliases"},
		{"alias", []string{"name: alice", "name: &a alice", "tenant: acme", "tenant: *a"}, 4, "", "anchors and aliases"},
		{"secret key", []string{"sub: bob", "token: abc123"}, 5, "identities[1].match.jwt", "raw credentials"},
		{"secret key case", []string{"sub: bob", "Authorization: abc123"}, 5, "identities[1].match.jwt", "raw credentials"},
		{"secret top-level key", []string{"resources:", "password: hunter2\nresources:"}, 6, "", "raw credentials"},
		{"jwt value", []string{"sub: bob", "sub: " + jwtLike}, 5, "identities[1].match.jwt.sub", "raw credentials"},
		{"multiple documents", []string{"admin: 100}\n", "admin: 100}\n---\nversion: 1\n"}, -1, "", "multiple yaml documents"},
		{"empty", []string{base, ""}, 0, "", "empty"},
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
			if tt.line >= 0 && ce.Line != tt.line {
				t.Errorf("line = %d, want %d (%v)", ce.Line, tt.line, ce)
			}
			if ce.Path != tt.path {
				t.Errorf("path = %q, want %q", ce.Path, tt.path)
			}
			if !strings.Contains(ce.Msg, tt.msg) {
				t.Errorf("msg = %q, want substring %q", ce.Msg, tt.msg)
			}
			for _, secret := range []string{jwtLike, "abc123", "hunter2"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error echoes secret %q: %v", secret, err)
				}
			}
		})
	}
}

func TestErrorFormat(t *testing.T) {
	tests := []struct {
		e    Error
		want string
	}{
		{Error{File: "f.yaml", Line: 3, Path: "roles.x", Msg: "bad"}, "f.yaml:3: roles.x: bad"},
		{Error{File: "f.yaml", Path: "roles.x", Msg: "bad"}, "f.yaml: roles.x: bad"},
		{Error{File: "f.yaml", Line: 3, Msg: "bad"}, "f.yaml:3: bad"},
	}
	for _, tt := range tests {
		if got := tt.e.Error(); got != tt.want {
			t.Errorf("got %q, want %q", got, tt.want)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "ok.yaml")
	if err := os.WriteFile(ok, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(ok)
	if err != nil || f.Path != ok || len(f.Identities) != 2 {
		t.Fatalf("Load = %+v, %v", f, err)
	}

	missing := filepath.Join(dir, "nope.yaml")
	if _, err := Load(missing); err == nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("missing file err = %v", err)
	}

	big := filepath.Join(dir, "big.yaml")
	data := []byte("# " + strings.Repeat("x", MaxSize) + "\n" + base)
	if err := os.WriteFile(big, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized err = %v", err)
	}
}
