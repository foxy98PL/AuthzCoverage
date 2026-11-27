package cli

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authzcov/internal/testutil/hartest"
)

func TestLooksLikeID(t *testing.T) {
	cases := []struct {
		seg  string
		want bool
	}{
		{"ab-Zq9x-Kd7", true},
		{"v1", false},
		{"v2", false},
		{"api", false},
		{"2fa", false},
		{"users", false},
		{"books", false},
		{"123", true},
		{"550e8400-e29b-41d4-a716-446655440000", true},
		{strings.Repeat("ab12", 10), true},
		{"a-very-long-slug-without-digits-here", true},
		{"", false},
	}
	for _, c := range cases {
		if got := looksLikeID(c.seg); got != c.want {
			t.Errorf("looksLikeID(%q) = %v, want %v", c.seg, got, c.want)
		}
	}
}

func TestUnmatchedIDLikeSegmentNotLeaked(t *testing.T) {
	const secret = "ab-Zq9x-Kd7" //nolint:gosec // test fixture
	es := []hartest.Entry{
		{Method: "GET", URL: base + "/nope/" + secret, Status: 404},
		{Method: "GET", URL: base + "/books/v1", Status: 200, Headers: hartest.Bearer(hartest.JWT(t, "alice", map[string]any{"role": "user"}))},
	}
	r := runCoverageIn(t, vampi, idsFx, es)
	for name, s := range map[string]string{"coverage.json": r.json, "stderr": r.stderr, "stdout": r.stdout} {
		if strings.Contains(s, secret) {
			t.Errorf("%s leaks %q", name, secret)
		}
	}
	if !strings.Contains(r.json, "/nope/<id>") {
		t.Errorf("coverage.json lacks shape /nope/<id>:\n%s", r.json)
	}
}

func TestBasicPasswordNeverInOutputs(t *testing.T) {
	const pw = "SuperSecretPw1"
	b64 := base64.StdEncoding.EncodeToString([]byte("carol:" + pw))
	ids := filepath.Join(t.TempDir(), "basic-ids.yaml")
	cfg := "version: 1\ncredentials:\n  - {type: basic}\nroles: {user: 10}\nidentities:\n  - {name: carol, role: user, match: {basic_user: carol}}\n"
	if err := os.WriteFile(ids, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	h := map[string]string{"Authorization": "Basic " + b64}
	es := []hartest.Entry{
		{Method: "GET", URL: base + "/books/v1", Status: 200, Headers: h},
		{Method: "GET", URL: base + "/users/v1", Status: 200, Headers: h},
	}
	r := runCoverageIn(t, vampi, ids, es)
	for name, s := range map[string]string{"coverage.json": r.json, "stderr": r.stderr, "stdout": r.stdout} {
		for _, bad := range []string{pw, b64} {
			if strings.Contains(s, bad) {
				t.Errorf("%s leaks %q", name, bad)
			}
		}
	}
	if !strings.Contains(r.json, "carol") {
		t.Errorf("expected identity carol in coverage.json:\n%s", r.json)
	}
}
