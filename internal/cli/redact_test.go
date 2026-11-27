package cli

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"authzcov/internal/testutil/hartest"
)

const tenantshopSpec = "../../e2e/apps/tenantshop/shop/openapi.yaml"
const tenantshopIDs = "../../e2e/apps/tenantshop/identities.yaml"
const tenantshopRaw = "../../testdata/raw/tenantshop.har"

func redactTo(t *testing.T, in string, extra ...string) (string, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "fixture.har")
	args := append([]string{"redact", "--pseudonymize", "--in", in, "--out", out}, extra...)
	code, _, errs := runCLI(t, args...)
	if code != ExitOK {
		t.Fatalf("redact exit = %d; stderr=%s", code, errs)
	}
	return out, errs
}

func TestRedactUsageErrors(t *testing.T) {
	dir := t.TempDir()
	in := hartest.WriteHAR(t, dir, "in.har", hartest.Entry{Method: "GET", URL: base + "/me", Status: 200})
	existing := writeFile(t, "exists.har", "{}")
	short := writeFile(t, "short.key", "too-short")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no pseudonymize", []string{"redact", "--in", in, "--out", filepath.Join(dir, "o.har")}, "only --pseudonymize is supported"},
		{"missing in", []string{"redact", "--pseudonymize", "--out", filepath.Join(dir, "o.har")}, "--in"},
		{"missing out", []string{"redact", "--pseudonymize", "--in", in}, "--out"},
		{"out equals in", []string{"redact", "--pseudonymize", "--in", in, "--out", in}, "same file"},
		{"out equals in via dot", []string{"redact", "--pseudonymize", "--in", in, "--out", filepath.Join(dir, ".", "in.har")}, "same file"},
		{"out exists", []string{"redact", "--pseudonymize", "--in", in, "--out", existing}, "--force"},
		{"short key", []string{"redact", "--pseudonymize", "--in", in, "--out", filepath.Join(dir, "o.har"), "--key-file", short}, "at least 32"},
		{"missing key file", []string{"redact", "--pseudonymize", "--in", in, "--out", filepath.Join(dir, "o.har"), "--key-file", filepath.Join(dir, "nope")}, "--key-file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errs := runCLI(t, tc.args...)
			if code != ExitUsage || !strings.Contains(errs, tc.want) {
				t.Errorf("exit %d, stderr %q; want %d containing %q", code, errs, ExitUsage, tc.want)
			}
		})
	}
	b, _ := os.ReadFile(in) //nolint:gosec // test path
	if !strings.Contains(string(b), "hartest") {
		t.Error("input modified")
	}
	b, _ = os.ReadFile(existing) //nolint:gosec // test path
	if string(b) != "{}" {
		t.Error("existing --out overwritten without --force")
	}
}

func TestRedactInputErrors(t *testing.T) {
	dir := t.TempDir()
	bad := writeFile(t, "bad.har", "not json")
	out := filepath.Join(dir, "o.har")
	for _, in := range []string{filepath.Join(dir, "missing.har"), bad} {
		code, _, errs := runCLI(t, "redact", "--pseudonymize", "--in", in, "--out", out)
		if code != ExitInput {
			t.Errorf("%s: exit %d, stderr %s", in, code, errs)
		}
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("--out created despite failure")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("temp files left behind: %v", ents)
	}
}

func TestRedactWritesAtomically0600AndForce(t *testing.T) {
	dir := t.TempDir()
	in := hartest.WriteHAR(t, dir, "in.har", hartest.Entry{Method: "GET", URL: base + "/me", Status: 200, Headers: hartest.Bearer(hartest.JWT(t, "alice", nil))})
	out := filepath.Join(dir, "o.har")
	for i, force := range []bool{false, true} {
		args := []string{"redact", "--pseudonymize", "--in", in, "--out", out}
		if force {
			args = append(args, "--force")
		}
		code, _, errs := runCLI(t, args...)
		if code != ExitOK {
			t.Fatalf("run %d: exit %d %s", i, code, errs)
		}
		fi, err := os.Stat(out)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("out mode = %v, err %v", fi, err)
		}
		for _, w := range []string{"1 entries", "re-signed 1", "hosts mapped 1"} {
			if !strings.Contains(errs, w) {
				t.Errorf("summary lacks %q: %s", w, errs)
			}
		}
		if i == 0 {
			// second run without --force must refuse
			if code, _, _ := runCLI(t, "redact", "--pseudonymize", "--in", in, "--out", out); code != ExitUsage {
				t.Fatalf("overwrite without --force: exit %d", code)
			}
		}
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 {
		t.Errorf("unexpected files: %v", ents)
	}
}

// Rule 10.
func TestRedactDeterministicWithKeyFile(t *testing.T) {
	dir := t.TempDir()
	es, _ := entries(t)
	in := hartest.WriteHAR(t, dir, "in.har", es...)
	key := writeFile(t, "k", strings.Repeat("k", 40))
	read := func(n string, extra ...string) string {
		out := filepath.Join(dir, n)
		args := append([]string{"redact", "--pseudonymize", "--in", in, "--out", out, "--key-file", key}, extra...)
		if code, _, errs := runCLI(t, args...); code != ExitOK {
			t.Fatalf("exit %d %s", code, errs)
		}
		b, _ := os.ReadFile(out) //nolint:gosec // test path
		return string(b)
	}
	a, b := read("a.har"), read("b.har")
	if a != b {
		t.Error("same input and key gave different bytes")
	}
	// Without --key-file the opaque tokens differ between runs.
	opaque := hartest.WriteHAR(t, dir, "op.har", hartest.Entry{Method: "GET", URL: base + "/me", Status: 200, Headers: hartest.Bearer("opaque-token-123")})
	r1, _ := redactTo(t, opaque)
	r2, _ := redactTo(t, opaque)
	b1, _ := os.ReadFile(r1) //nolint:gosec // test path
	b2, _ := os.ReadFile(r2) //nolint:gosec // test path
	if bytes.Equal(b1, b2) {
		t.Error("random run key produced identical output twice")
	}
}

// Rule 9 through the CLI: raw secrets never reach the file or stderr.
func TestRedactNoSecretInOutputOrStderr(t *testing.T) {
	secrets := []string{"alice.realname@acme-corp.example", "acme-corp", "OPAQUE-BEARER-SECRET-1", "AKIAREALKEY99999", "SESSIONCOOKIE-ABCDEF", "Sup3rS3cretPw", "8443"}
	jwtRaw := hartest.JWT(t, "alice", map[string]any{"email": "alice.realname@acme-corp.example", "exp": 1893456000})
	secrets = append(secrets, strings.Split(jwtRaw, ".")[2])
	dir := t.TempDir()
	in := hartest.WriteHAR(t, dir, "in.har",
		hartest.Entry{Method: "POST", URL: "https://api.acme-corp.example:8443/books/v1?token=QQQ", Status: 200,
			Headers: map[string]string{"Authorization": "Bearer " + jwtRaw, "X-API-Key": "AKIAREALKEY99999", "Cookie": "sid=SESSIONCOOKIE-ABCDEF"},
			ReqJSON: `{"book_title":"a1","password":"Sup3rS3cretPw","owner":"alice.realname@acme-corp.example"}`},
		hartest.Entry{Method: "GET", URL: "https://api.acme-corp.example:8443/me", Status: 200, Headers: hartest.Bearer("OPAQUE-BEARER-SECRET-1")},
	)
	out, errs := redactTo(t, in)
	b, _ := os.ReadFile(out) //nolint:gosec // test path
	for _, s := range append(secrets, "QQQ") {
		if strings.Contains(string(b), s) || strings.Contains(errs, s) {
			t.Errorf("secret %q leaked", s)
		}
	}
}

func coverageTable(t *testing.T, spec, ids, har string) string {
	t.Helper()
	code, out, errs := runCLI(t, "coverage", "--spec", spec, "--har", har, "--identities", ids)
	if code != ExitOK {
		t.Fatalf("coverage exit %d: %s", code, errs)
	}
	return out
}

// Rule 8 (hartest-built fixtures; no real traffic).
func TestRedactCoverageInvariance(t *testing.T) {
	vampiEs, _ := entries(t)
	tenantsSpecFile := writeFile(t, "tenants.yml", tenantsSpec)
	tenantsIDsFile := writeFile(t, "ids.yaml", tenantsIDs)
	listsIDsFile := writeFile(t, "ids.yaml", listsIDs)
	tests := []struct {
		name      string
		spec, ids string
		es        []hartest.Entry
	}{
		{"vampi", vampi, idsFx, vampiEs},
		{"vampi-lists", vampi, listsIDsFile, listsEntries(t)},
		{"tenants", tenantsSpecFile, tenantsIDsFile, tenantsEntries(t)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := hartest.WriteHAR(t, t.TempDir(), "raw.har", tc.es...)
			red, _ := redactTo(t, raw)
			want := coverageTable(t, tc.spec, tc.ids, raw)
			if got := coverageTable(t, tc.spec, tc.ids, red); got != want {
				t.Errorf("table differs after redact:\n%s\nvs original:\n%s", got, want)
			}
			b, _ := os.ReadFile(red) //nolint:gosec // test path
			if strings.Contains(string(b), "localhost") {
				t.Error("real host survived")
			}
		})
	}
}

// Rule 8 on the real tenantshop recording (git-ignored; skipped when absent).
func TestRedactCoverageInvarianceTenantshop(t *testing.T) {
	if _, err := os.Stat(tenantshopRaw); err != nil {
		t.Skip("testdata/raw/tenantshop.har not recorded (e2e/recorders/tenantshop.sh)")
	}
	red, _ := redactTo(t, tenantshopRaw, "--keep-claims", "sub,org_id")
	want := coverageTable(t, tenantshopSpec, tenantshopIDs, tenantshopRaw)
	if got := coverageTable(t, tenantshopSpec, tenantshopIDs, red); got != want {
		t.Errorf("table differs after redact:\n%s\nvs original:\n%s", got, want)
	}
	b, _ := os.ReadFile(red) //nolint:gosec // test path
	for _, m := range regexp.MustCompile(`eyJ[\w-]+\.(eyJ[\w-]+)\.[\w-]+`).FindAllStringSubmatch(string(b), -1) {
		if !strings.Contains(decodeSeg(t, m[1]), `"iss":"authzcov-test"`) {
			t.Errorf("token not re-signed: %s", m[0])
		}
	}
}

func decodeSeg(t *testing.T, seg string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Fix 2 through the CLI: coverage invariance with an e-mail subject.
func TestRedactCoverageInvarianceEmailSubject(t *testing.T) {
	pseudoSub := func(email string) string {
		m := hmac.New(sha256.New, []byte(strings.Repeat("k", 40)))
		m.Write([]byte(email))
		return "user_" + hex.EncodeToString(m.Sum(nil))[:8] + "@example.test"
	}
	a := hartest.Bearer(hartest.JWT(t, "alice@corp.com", nil))
	b := hartest.Bearer(hartest.JWT(t, "bob@corp.com", nil))
	es := []hartest.Entry{
		{Method: "GET", URL: base + "/books/v1", Status: 200, Headers: a, RespJSON: `{"Books":[{"book_title":"a1"}]}`},
		{Method: "GET", URL: base + "/books/v1", Status: 200, Headers: b, RespJSON: `{"Books":[{"book_title":"b1"}]}`},
		{Method: "GET", URL: base + "/books/v1/a1", Status: 200, Headers: a},
		{Method: "GET", URL: base + "/books/v1/a1", Status: 200, Headers: b},
	}
	idsFor := func(sa, sb string) string {
		return strings.Replace(strings.Replace(listsIDs, "{sub: alice}", "{sub: \""+sa+"\"}", 1), "{sub: bob}", "{sub: \""+sb+"\"}", 1)
	}
	raw := hartest.WriteHAR(t, t.TempDir(), "raw.har", es...)
	red, _ := redactTo(t, raw, "--key-file", writeFile(t, "k", strings.Repeat("k", 40)))
	if rb, _ := os.ReadFile(red); strings.Contains(string(rb), "corp.com") { //nolint:gosec // test path
		t.Fatal("raw email survived")
	}
	want := coverageTable(t, vampi, writeFile(t, "ids.yaml", idsFor("alice@corp.com", "bob@corp.com")), raw)
	got := coverageTable(t, vampi, writeFile(t, "ids.yaml", idsFor(pseudoSub("alice@corp.com"), pseudoSub("bob@corp.com"))), red)
	if got != want {
		t.Errorf("table differs:\n%s\nvs\n%s", got, want)
	}
}
