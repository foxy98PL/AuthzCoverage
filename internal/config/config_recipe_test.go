package config

import (
	"authzcov/internal/redact"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const recipeOK = `
    login_recipe:
      method: POST
      path: /auth/login
      content_type: json
      fields: {username: "${RCP_USER}", password: "${RCP_PASS}", tenant: acme}
      token_from: {json: /access_token}
      apply: bearer
`

// withRecipe puts rec on bob (identities[1], last identity line of the block).
func withRecipe(rec string) string {
	return strings.Replace(base,
		"  - {name: bob, role: user, tenant: acme, match: {jwt: {sub: bob}}}\n",
		"  - name: bob\n    role: user\n    tenant: acme\n    match: {jwt: {sub: bob}}"+rec, 1)
}

func TestLoginRecipeParses(t *testing.T) {
	t.Setenv("RCP_USER", "bob")
	t.Setenv("RCP_PASS", "pw-canary-123")
	f, err := Parse([]byte(withRecipe(recipeOK)), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := f.Identities[1].LoginRecipe
	if r == nil || r.Method != "POST" || r.Path != "/auth/login" || r.ContentType != "json" ||
		r.TokenFrom.Kind != "json" || r.TokenFrom.Name != "/access_token" || r.Apply.Kind != "bearer" ||
		r.Fields["password"] != "${RCP_PASS}" || r.Fields["tenant"] != "acme" {
		t.Fatalf("recipe = %+v", r)
	}
	if f.Identities[0].LoginRecipe != nil {
		t.Fatal("alice should have no recipe")
	}
	if out := fmt.Sprintf("%+v %#v", *f, *f); strings.Contains(out, "pw-canary-123") {
		t.Fatalf("env value leaked: %s", out)
	}
}

func TestLoginRecipeDefaultsAndForms(t *testing.T) {
	t.Setenv("RCP_USER", "bob")
	t.Setenv("RCP_PASS", "x")
	rec := strings.Replace(recipeOK, "      apply: bearer\n", "", 1)
	f, err := Parse([]byte(withRecipe(rec)), "x.yaml")
	if err != nil || f.Identities[1].LoginRecipe.Apply.Kind != "bearer" {
		t.Fatalf("default apply: %v", err)
	}
	rec = strings.Replace(recipeOK, "{json: /access_token}", "{cookie: sid}", 1)
	rec = strings.Replace(rec, "apply: bearer", "apply: cookie:sid", 1)
	f, err = Parse([]byte(withRecipe(rec)), "x.yaml")
	if err != nil || f.Identities[1].LoginRecipe.Apply.Name != "sid" || f.Identities[1].LoginRecipe.TokenFrom.Kind != "cookie" {
		t.Fatalf("cookie recipe: %v", err)
	}
}

func TestLoginRecipeErrors(t *testing.T) {
	t.Setenv("RCP_USER", "bob")
	t.Setenv("RCP_PASS", "x")
	rep := func(old, new string) string { return strings.Replace(recipeOK, old, new, 1) }
	cases := []struct {
		name, rec, path, msg string
	}{
		{"method GET", rep("method: POST", "method: GET"), "identities[1].login_recipe.method", "POST or PUT"},
		{"path abs", rep("path: /auth/login", "path: http://evil.example.com/x"), "identities[1].login_recipe.path", "must start with /"},
		{"path dotdot", rep("path: /auth/login", "path: /a/../b"), "identities[1].login_recipe.path", ".."},
		{"content type", rep("content_type: json", "content_type: xml"), "identities[1].login_recipe.content_type", "json or form"},
		{"concat secret key", rep(`"${RCP_PASS}"`, `"x${RCP_PASS}"`), "identities[1].login_recipe.fields.password", "raw credentials"},
		{"concat", rep(`"${RCP_USER}"`, `"x${RCP_USER}"`), "identities[1].login_recipe.fields.username", "whole-value"},
		{"bad env name", rep("${RCP_PASS}", "${rcp}"), "identities[1].login_recipe.fields.password", "must match"},
		{"denied env", rep("${RCP_PASS}", "${PATH}"), "identities[1].login_recipe.fields.password", "system variable"},
		{"token_from two", rep("{json: /access_token}", "{json: /a, cookie: b}"), "identities[1].login_recipe.token_from", "exactly one"},
		{"token_from bad", rep("{json: /access_token}", "{body: x}"), "identities[1].login_recipe.token_from", "unknown key"},
		{"token_from set-cookie hdr", rep("{json: /access_token}", "{header: Set-Cookie}"), "identities[1].login_recipe.token_from", "Set-Cookie"},
		{"apply bad", rep("apply: bearer", "apply: query:t"), "identities[1].login_recipe.apply", "bearer"},
		{"apply Host", rep("apply: bearer", "apply: header:Host"), "identities[1].login_recipe.apply", "cannot be set"},
		{"unknown key", rep("path:", "headers: {X: y}\n      path:"), "identities[1].login_recipe", `unknown key "headers"`},
		{"missing method", rep("      method: POST\n", ""), "identities[1].login_recipe.method", "required"},
		{"missing token_from", rep("      token_from: {json: /access_token}\n", ""), "identities[1].login_recipe.token_from", "required"},
		{"missing fields", rep(`      fields: {username: "${RCP_USER}", password: "${RCP_PASS}", tenant: acme}`+"\n", ""), "identities[1].login_recipe.fields", "required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(withRecipe(c.rec)), "x.yaml")
			var ce *Error
			if !errors.As(err, &ce) {
				t.Fatalf("err = %v", err)
			}
			if ce.Path != c.path || !strings.Contains(ce.Msg, c.msg) {
				t.Fatalf("got path=%q msg=%q; want %q / %q", ce.Path, ce.Msg, c.path, c.msg)
			}
			if strings.Contains(ce.Error(), "pw-") {
				t.Fatal("leak")
			}
		})
	}
}

// F2: Parse never reads the recipe env vars (coverage/report run without them).
func TestLoginRecipeParseDoesNotNeedEnv(t *testing.T) {
	t.Setenv("RCP_USER", "")
	t.Setenv("RCP_PASS", "")
	if _, err := Parse([]byte(withRecipe(recipeOK)), "x.yaml"); err != nil {
		t.Fatalf("parse must not require env: %v", err)
	}
}

// F1: secret-named recipe fields take only a whole-value ${NAME}.
func TestLoginRecipeSecretFieldsPlaceholderOnly(t *testing.T) {
	for _, key := range []string{"password", "token", "secret", "api_key", "Password"} {
		for _, val := range []string{"hunter2", `"x${RCP_PASS}"`, `"$RCP_PASS"`, `""`} {
			rec := strings.Replace(recipeOK, `password: "${RCP_PASS}"`, key+": "+val, 1)
			_, err := Parse([]byte(withRecipe(rec)), "x.yaml")
			var ce *Error
			if !errors.As(err, &ce) || !strings.Contains(ce.Msg, "raw credentials") || strings.Contains(ce.Error(), "hunter2") {
				t.Errorf("%s: %s -> %v", key, val, err)
			}
		}
	}
	rec := strings.Replace(recipeOK, `password: "${RCP_PASS}"`, `token: "${RCP_PASS}"`, 1)
	if _, err := Parse([]byte(withRecipe(rec)), "x.yaml"); err != nil {
		t.Fatalf("placeholder under secret key: %v", err)
	}
}

// F7: the exemption is anchored to identities[N].login_recipe.
func TestRecipeFieldsExemptionAnchored(t *testing.T) {
	bad := strings.Replace(base, "match: {jwt: {sub: bob}}", "match: {jwt: {sub: bob}, login_recipe: {fields: {password: hunter2}}}", 1)
	if _, err := Parse([]byte(bad), "x.yaml"); err == nil || !strings.Contains(err.Error(), "raw credentials") {
		t.Fatalf("got %v", err)
	}
	for path, want := range map[string]bool{
		"identities[0].login_recipe.fields":          true,
		"identities[12].login_recipe.token_from":     true,
		"identities[0].match.login_recipe.fields":    false,
		"x.identities[0].login_recipe.fields":        false,
		"identities[0].login_recipe.fields.password": false,
		"identities[a].login_recipe.fields":          false,
	} {
		if isRecipeFields(path) != want {
			t.Errorf("isRecipeFields(%q) != %v", path, want)
		}
	}
}

// F3: token_sha256 on a recipe identity becomes the provider's expected fingerprint.
func TestProbeRecipesExpectFP(t *testing.T) {
	sum := sha256.Sum256([]byte("tokB"))
	h := hex.EncodeToString(sum[:])
	rec := strings.Replace(withRecipe(recipeOK), "match: {jwt: {sub: bob}}", "match: {token_sha256: "+h+"}", 1)
	f, err := Parse([]byte(rec), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	recipes, fps := f.ProbeRecipes()
	if len(recipes) != 1 || recipes["bob"].Path != "/auth/login" {
		t.Fatalf("recipes = %v", recipes)
	}
	if fps["bob"] != redact.Fingerprint("tokB") {
		t.Fatalf("fps = %v", fps)
	}
	if _, ok := fps["alice"]; ok {
		t.Fatal("alice has no recipe")
	}
}

// The identity-name matcher key stays `login` under match; a recipe is a
// separate key and a raw secret key elsewhere is still rejected.
func TestLoginRecipeKeyIsNotLoginAndPasswordElsewhereRejected(t *testing.T) {
	bad := strings.Replace(base, "match: {jwt: {sub: bob}}", "match: {jwt: {sub: bob}}, login: x", 1)
	if _, err := Parse([]byte(bad), "x.yaml"); err == nil {
		t.Fatal("login: at identity level must be rejected")
	}
	pw := strings.Replace(base, "match: {jwt: {sub: bob}}", "match: {jwt: {sub: bob}}, password: hunter2", 1)
	if _, err := Parse([]byte(pw), "x.yaml"); err == nil || !strings.Contains(err.Error(), "raw credentials") {
		t.Fatalf("password key must be rejected: %v", err)
	}
}

func TestLoginRecipeWithTokenEnvRejected(t *testing.T) {
	t.Setenv("RCP_USER", "bob")
	t.Setenv("RCP_PASS", "x")
	t.Setenv("RCP_TOK", "tok")
	y := strings.Replace(withRecipe(recipeOK), "match: {jwt: {sub: bob}}", "match: {token_env: RCP_TOK}", 1)
	_, err := Parse([]byte(y), "x.yaml")
	if err == nil || !strings.Contains(err.Error(), "login_recipe and match.token_env") {
		t.Fatalf("err = %v", err)
	}
}

// KAN-39 F3: token_env names reach the probe by NAME only.
func TestProbeTokenEnvs(t *testing.T) {
	const val = "super-secret-env-token-value"
	t.Setenv("AUTHZCOV_TEST_TOK", val)
	y := strings.Replace(base, "match: {jwt: {sub: bob}}", "match: {token_env: AUTHZCOV_TEST_TOK}", 1)
	f, err := Parse([]byte(y), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	envs := f.ProbeTokenEnvs()
	if len(envs) != 1 || envs["bob"] != "AUTHZCOV_TEST_TOK" {
		t.Fatalf("envs = %v", envs)
	}
	if strings.Contains(fmt.Sprintf("%+v", *f), val) {
		t.Fatal("value leaked")
	}
}

// KAN-39b F1: the ambiguity error wins even when the env var is unset.
func TestLoginRecipeWithTokenEnvUnsetStillAmbiguous(t *testing.T) {
	t.Setenv("RCP_USER", "bob")
	t.Setenv("RCP_PASS", "x")
	y := strings.Replace(withRecipe(recipeOK), "match: {jwt: {sub: bob}}", "match: {token_env: RCP_TOK_UNSET_F1}", 1)
	_, err := Parse([]byte(y), "x.yaml")
	if err == nil || !strings.Contains(err.Error(), "login_recipe and match.token_env") {
		t.Fatalf("err = %v", err)
	}
}

// KAN-39b F2: alias and merge-key forms of match must not bypass the check.
func TestLoginRecipeWithTokenEnvViaAliasOrMerge(t *testing.T) {
	t.Setenv("RCP_USER", "bob")
	t.Setenv("RCP_PASS", "x")
	t.Setenv("RCP_TOK", "tok")
	for name, bobMatch := range map[string]string{
		"alias":      "match: *m",
		"merge":      "match: {<<: *m}",
		"merge-list": "match: {<<: [*m]}",
	} {
		y := strings.Replace(withRecipe(recipeOK), "match: {jwt: {sub: bob}}", bobMatch, 1)
		y = strings.Replace(y, "match: {jwt: {sub: alice}}", "match: &m {token_env: RCP_TOK}", 1)
		// Parse rejects anchors/aliases outright, so this must fail either way
		// (defence in depth: hasKey is also tested directly below).
		if _, err := Parse([]byte(y), "x.yaml"); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

func TestHasKeyFollowsAliasAndMerge(t *testing.T) {
	var doc yaml.Node
	src := "a: &m {token_env: X}\nb: *m\nc: {<<: *m}\nd: {<<: [*m]}\ne: {jwt: 1}\n"
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	m := doc.Content[0]
	get := func(k string) *yaml.Node {
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value == k {
				return m.Content[i+1]
			}
		}
		return nil
	}
	for k, want := range map[string]bool{"a": true, "b": true, "c": true, "d": true, "e": false} {
		if got := hasKey(get(k), "token_env"); got != want {
			t.Errorf("%s: hasKey = %v want %v", k, got, want)
		}
	}
}

// KAN-39b F3: a canary env value must appear in no exposed field.
func TestProbeTokenEnvsCanaryNotExposed(t *testing.T) {
	const val = "canary-env-value-9f3a"
	t.Setenv("AUTHZCOV_TEST_TOK", val)
	y := strings.Replace(base, "match: {jwt: {sub: bob}}", "match: {token_env: AUTHZCOV_TEST_TOK}", 1)
	f, err := Parse([]byte(y), "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprintf("%+v", *f), fmt.Sprintf("%#v", *f), fmt.Sprintf("%#v", f.ProbeTokenEnvs()), fmt.Sprintf("%#v", f.Identities)} {
		if strings.Contains(s, val) {
			t.Fatalf("env value leaked: %.80s", s)
		}
	}
	if envs := f.ProbeTokenEnvs(); envs["bob"] != "AUTHZCOV_TEST_TOK" {
		t.Fatalf("envs = %v", envs)
	}
}
