package cli

import (
	"encoding/base64"
	"strings"
	"testing"

	"authzcov/internal/config"
	"authzcov/internal/identity"
	"authzcov/internal/ingest/har"
	"authzcov/internal/model"
	"authzcov/internal/redact"
	"authzcov/internal/spec"
	"authzcov/internal/testutil/hartest"
)

func TestDiscoverShowsJWTClaims(t *testing.T) {
	ja := hartest.JWT(t, "alice", map[string]any{"role": "user"})
	jb := hartest.JWT(t, "bob", map[string]any{"role": "user"})
	es := []hartest.Entry{
		{Method: "GET", URL: base + "/books/v1", Status: 200, Headers: hartest.Bearer(ja)},
		{Method: "GET", URL: base + "/books/v1", Status: 200, Headers: hartest.Bearer(jb)},
	}
	harFile := hartest.WriteHAR(t, t.TempDir(), "d.har", es...)
	code, out, errs := runCLI(t, "discover", "--har", harFile)
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, errs)
	}
	for _, want := range []string{"# claims:", "sub=alice", "sub=bob", "role=user"} {
		if !strings.Contains(out, want) {
			t.Errorf("discover output missing %q:\n%s", want, out)
		}
	}
}

func TestDiscoverBasicLeaksNothingAboutPassword(t *testing.T) {
	const pw = "hunter2-very-secret"
	b64 := base64.StdEncoding.EncodeToString([]byte("carol:" + pw))
	es := []hartest.Entry{
		{Method: "GET", URL: base + "/books/v1", Status: 200, Headers: map[string]string{"Authorization": "Basic " + b64}},
	}
	harFile := hartest.WriteHAR(t, t.TempDir(), "b.har", es...)
	code, out, errs := runCLI(t, "discover", "--har", harFile)
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, errs)
	}
	all := out + errs
	for _, bad := range []string{redact.Fingerprint(b64), redact.Fingerprint(pw), pw, b64} {
		if strings.Contains(all, bad) {
			t.Errorf("output leaks %q:\n%s", bad, all)
		}
	}
	if !strings.Contains(out, "carol") {
		t.Errorf("expected basic user in output:\n%s", out)
	}
}

func TestLearnTokensYieldsLearnedConfidence(t *testing.T) {
	const ta = "opaque-alice-token-0123456789"
	es := []hartest.Entry{
		{Method: "POST", URL: base + "/users/v1/login", Status: 200, ReqJSON: `{"username":"alice","password":"pw-a"}`, RespJSON: `{"auth_token":"` + ta + `"}`},
		{Method: "GET", URL: base + "/books/v1", Status: 200, Headers: hartest.Bearer(ta)},
	}
	harFile := hartest.WriteHAR(t, t.TempDir(), "l.har", es...)
	cfg, err := config.Load(learnFx)
	if err != nil {
		t.Fatal(err)
	}
	endpoints, err := spec.Load(vampi)
	if err != nil {
		t.Fatal(err)
	}
	trie, byID, err := buildTrie(endpoints, vampi)
	if err != nil {
		t.Fatal(err)
	}
	var hs har.Stats
	xs, err := readHARs([]string{harFile}, identity.NewExtractor(credSpecs(cfg)), &hs)
	if err != nil {
		t.Fatal(err)
	}
	obs, _ := matchExchanges(xs, trie, byID, nil)
	r := newResolver(cfg)
	learnTokens(cfg, r, obs)
	resolveAll(r, obs)
	found := false
	for _, o := range obs {
		if o.X.Cred.Kind == identity.KindBearer {
			found = true
			if o.Identity == nil || o.Identity.Name != "alice" || o.IDConf != model.ConfLearned {
				t.Errorf("token obs: identity=%v conf=%v, want alice/ConfLearned", o.Identity, o.IDConf)
			}
		}
	}
	if !found {
		t.Fatal("no bearer observation found")
	}
}
