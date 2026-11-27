package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"authzcov/internal/config"
	"authzcov/internal/testutil/hartest"
)

const learnFx = "../../testdata/identities/vampi-learn.yaml"

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Execute(args, &out, &errb)
	return code, out.String(), errb.String()
}

// cells parses the coverage table into row-prefix -> column -> cell.
func cells(t *testing.T, out, prefix string) map[string]string {
	t.Helper()
	lines := strings.Split(out, "\n")
	cols := regexp.MustCompile(`\s{2,}`)
	header := cols.Split(strings.TrimSpace(lines[0]), -1)
	for _, l := range lines[1:] {
		if strings.HasPrefix(l, prefix) {
			f := cols.Split(strings.TrimSpace(strings.TrimPrefix(l, prefix)), -1)
			m := map[string]string{}
			for i, h := range header[1:] {
				if i < len(f) {
					m[h] = f[i]
				}
			}
			return m
		}
	}
	t.Fatalf("no row %q in:\n%s", prefix, out)
	return nil
}

func runWith(t *testing.T, ids string, es []hartest.Entry) (int, string, string) {
	t.Helper()
	har := hartest.WriteHAR(t, t.TempDir(), "t.har", es...)
	return runCLI(t, "coverage", "--spec", vampi, "--har", har, "--identities", ids)
}

func reverse(es []hartest.Entry) []hartest.Entry {
	rev := make([]hartest.Entry, len(es))
	for i, e := range es {
		rev[len(es)-1-i] = e
	}
	return rev
}

func TestLearnTokensEndToEnd(t *testing.T) {
	const ta, tb = "opaque-alice-token-0123456789", "opaque-bob-token-9876543210"
	a, b := hartest.Bearer(ta), hartest.Bearer(tb)
	es := []hartest.Entry{
		{Method: "POST", URL: base + "/users/v1/login", Status: 200, ReqJSON: `{"username":"alice","password":"pw-a"}`, RespJSON: `{"auth_token":"` + ta + `"}`},
		{Method: "POST", URL: base + "/users/v1/login", Status: 200, ReqJSON: `{"username":"bob","password":"pw-b"}`, RespJSON: `{"auth_token":"` + tb + `"}`},
		{Method: "POST", URL: base + "/books/v1", Status: 200, Headers: a, ReqJSON: `{"book_title":"a1","secret":"x"}`},
		{Method: "GET", URL: base + "/books/v1/a1", Status: 200, Headers: a},
		{Method: "GET", URL: base + "/books/v1/a1", Status: 200, Headers: b},
		{Method: "GET", URL: base + "/books/v1/a1", Status: 401},
	}
	code, out, errs := runWith(t, learnFx, es)
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, errs)
	}
	book := cells(t, out, "GET     /books/v1/{book_title}")
	for col, want := range map[string]string{"OWNER": "ok", "SAME_ROLE": "ok", "ANON": "ok 401"} {
		if book[col] != want {
			t.Errorf("books %s = %q, want %q\n%s", col, book[col], want, out)
		}
	}
	for _, tok := range []string{ta, tb, "pw-a", "pw-b"} {
		if strings.Contains(out+errs, tok) {
			t.Errorf("output leaks %q", tok)
		}
	}
	// HAR order must not matter: logins after their uses still learn.
	if _, got, _ := runWith(t, learnFx, reverse(es)); got != out {
		t.Errorf("reversed output differs:\n%s\nwant:\n%s", got, out)
	}
}

func shaHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestMixedCredentials(t *testing.T) {
	const cookie = "sess-value-for-alice-123"
	ids := filepath.Join(t.TempDir(), "identities.yaml")
	y := "version: 1\nroles: {user: 10}\ncredentials:\n  - {type: cookie, name: SESSION}\n  - {type: bearer}\nidentities:\n" +
		"  - {name: alice, role: user, match: {token_sha256: \"" + shaHex(cookie) + "\"}}\n" +
		"  - {name: bob, role: user, match: {jwt: {sub: bob}}}\n"
	if err := os.WriteFile(ids, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	es := []hartest.Entry{
		{Method: "GET", URL: base + "/me", Status: 200, Headers: map[string]string{"Cookie": "a=1; SESSION=" + cookie}},
		{Method: "GET", URL: base + "/users/v1", Status: 401, Headers: map[string]string{"Cookie": "SESSION=who-knows"}},
		{Method: "GET", URL: base + "/books/v1", Status: 401},
	}
	code, out, errs := runWith(t, ids, es)
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, errs)
	}
	if me := cells(t, out, "GET     /me"); me["OWNER"] != "ok" {
		t.Errorf("cookie-resolved alice: /me OWNER = %q, want ok\n%s", me["OWNER"], out)
	}
	if u := cells(t, out, "GET     /users/v1  "); u["ANON"] != "GAP" {
		t.Errorf("unknown cookie must not count as anonymous: ANON = %q\n%s", u["ANON"], out)
	}
	if b := cells(t, out, "GET     /books/v1  "); b["ANON"] != "ok 401" {
		t.Errorf("true anonymous: ANON = %q\n%s", b["ANON"], out)
	}
	if strings.Contains(out+errs, cookie) || strings.Contains(out+errs, "who-knows") {
		t.Error("output leaks cookie value")
	}
}

func TestConfigWarnings(t *testing.T) {
	ids := filepath.Join(t.TempDir(), "identities.yaml")
	y := "version: 1\nroles: {user: 10, admin: 100}\nidentities:\n  - {name: root, role: admin, match: {jwt: {sub: root}}}\n"
	if err := os.WriteFile(ids, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	es := []hartest.Entry{{Method: "GET", URL: base + "/me", Status: 200, Headers: hartest.Bearer(hartest.JWT(t, "root", nil))}}
	code, _, errs := runWith(t, ids, es)
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, errs)
	}
	if !strings.Contains(errs, `warning: role "admin" has fewer than two identities`) {
		t.Errorf("missing warning in stderr:\n%s", errs)
	}
}

func TestInvalidIdentitiesLocation(t *testing.T) {
	ids := filepath.Join(t.TempDir(), "identities.yaml")
	y := "version: 1\nroles: {user: 10}\nidentities:\n  - {name: alice, role: ghost, match: {login: alice}}\n"
	if err := os.WriteFile(ids, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	es := []hartest.Entry{{Method: "GET", URL: base + "/me", Status: 200}}
	code, _, errs := runWith(t, ids, es)
	if code != ExitUsage {
		t.Fatalf("exit = %d, want 2; stderr=%s", code, errs)
	}
	if !strings.Contains(errs, "identities.yaml:4") || !strings.Contains(errs, "identities[0].role") {
		t.Errorf("stderr lacks file:line and key path: %s", errs)
	}
}

func discoverEntries(t *testing.T) ([]hartest.Entry, []string) {
	t.Helper()
	ta := hartest.JWT(t, "alice", map[string]any{"role": "user"})
	tb := hartest.JWT(t, "bob", map[string]any{"role": "user"})
	opaque := "opaque-token-abcdef-1234567890"
	es := []hartest.Entry{
		{Method: "GET", URL: base + "/me", Status: 200, Headers: hartest.Bearer(ta)},
		{Method: "GET", URL: base + "/me", Status: 200, Headers: hartest.Bearer(ta)},
		{Method: "GET", URL: base + "/me", Status: 200, Headers: hartest.Bearer(tb)},
		{Method: "GET", URL: base + "/me", Status: 200, Headers: hartest.Bearer(opaque)},
		{Method: "GET", URL: base + "/me", Status: 401},
	}
	return es, []string{ta, tb, opaque, ta[strings.LastIndex(ta, ".")+1:]}
}

func TestDiscover(t *testing.T) {
	es, secrets := discoverEntries(t)
	dir := t.TempDir()
	har := hartest.WriteHAR(t, dir, "d.har", es...)
	code, out, errs := runCLI(t, "discover", "--har", har)
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, errs)
	}
	t.Logf("stdout:\n%s\nstderr:\n%s", out, errs)
	cfg, err := config.Parse([]byte(out), "discover.yaml")
	if err != nil {
		t.Fatalf("output does not parse: %v\n%s", err, out)
	}
	var names []string
	for _, id := range cfg.Identities {
		names = append(names, id.Name)
	}
	if strings.Join(names, ",") != "alice,bob" {
		t.Errorf("names = %v", names)
	}
	if !strings.Contains(out, "# opaque") && !strings.Contains(out, "bearer credential, fingerprint ") {
		t.Errorf("no commented principal with fingerprint:\n%s", out)
	}
	if !strings.Contains(errs, "discover: 3 principals from 5 requests") {
		t.Errorf("summary missing: %q", errs)
	}
	for _, s := range secrets {
		if strings.Contains(out+errs, s) {
			t.Errorf("output leaks %q", s)
		}
	}

	// Order independence.
	rng := rand.New(rand.NewSource(7)) //nolint:gosec // fixed seed for a reproducible test shuffle
	for i := 0; i < 5; i++ {
		shuf := append([]hartest.Entry(nil), es...)
		rng.Shuffle(len(shuf), func(a, b int) { shuf[a], shuf[b] = shuf[b], shuf[a] })
		h2 := hartest.WriteHAR(t, dir, "s.har", shuf...)
		if _, got, _ := runCLI(t, "discover", "--har", h2); got != out {
			t.Errorf("shuffled output differs:\n%s", got)
		}
	}

	// --write refuses to overwrite without --force.
	target := filepath.Join(dir, "out.yaml")
	if code, o, e := runCLI(t, "discover", "--har", har, "--write", target); code != ExitOK || o != "" {
		t.Fatalf("write: exit=%d stdout=%q stderr=%s", code, o, e)
	}
	if b, err := os.ReadFile(filepath.Clean(target)); err != nil || string(b) != out {
		t.Errorf("written file differs (err %v)", err)
	}
	if st, err := os.Stat(target); err != nil || st.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, %v", st, err)
	}
	code, _, e := runCLI(t, "discover", "--har", har, "--write", target)
	if code != ExitUsage || !strings.Contains(e, "file exists; pass --force") {
		t.Errorf("second write: exit=%d stderr=%s", code, e)
	}
	if code, _, e := runCLI(t, "discover", "--har", har, "--write", target, "--force"); code != ExitOK {
		t.Errorf("force write: exit=%d stderr=%s", code, e)
	}
}

func TestDiscoverBasicAndPlaceholder(t *testing.T) {
	dir := t.TempDir()
	basic := hartest.WriteHAR(t, dir, "b.har",
		hartest.Entry{Method: "GET", URL: base + "/me", Status: 200, Headers: map[string]string{"Authorization": "Basic dXNlcjE6cHc="}})
	code, out, errs := runCLI(t, "discover", "--har", basic)
	if code != ExitOK {
		t.Fatalf("exit = %d; %s", code, errs)
	}
	if !strings.Contains(out, `match: {basic_user: "user1"}`) || strings.Contains(out, "dXNlcjE6cHc=") {
		t.Errorf("basic output:\n%s", out)
	}
	if _, err := config.Parse([]byte(out), "x.yaml"); err != nil {
		t.Errorf("parse: %v", err)
	}

	anon := hartest.WriteHAR(t, dir, "a.har", hartest.Entry{Method: "GET", URL: base + "/me", Status: 401},
		hartest.Entry{Method: "GET", URL: base + "/me", Status: 200, Headers: map[string]string{"X-API-Key": "key-123456789"}})
	code, out, errs = runCLI(t, "discover", "--har", anon)
	if code != ExitOK {
		t.Fatalf("exit = %d; %s", code, errs)
	}
	if _, err := config.Parse([]byte(out), "x.yaml"); err != nil || !strings.Contains(out, "change-me") || strings.Contains(out, "key-123456789") {
		t.Errorf("placeholder output (err %v):\n%s", err, out)
	}
	if code, _, _ := runCLI(t, "discover"); code != ExitUsage {
		t.Errorf("no --har: exit %d", code)
	}
}

func TestSchemaMatchesConfig(t *testing.T) {
	b, err := os.ReadFile("../../schema/identities.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Props map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	var got []string
	for k := range doc.Props {
		got = append(got, k)
	}
	sortStrings(got)
	want := config.TopLevelKeys()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("schema top-level keys %v != config %v", got, want)
	}
}

func sortStrings(s []string) { sort.Strings(s) }
