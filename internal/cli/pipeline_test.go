package cli

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"authzcov/internal/testutil/hartest"
)

const (
	base   = "http://localhost:5000"
	secret = "s3cr3t-value"
)

type tokens struct{ alice, bob string }

func entries(t *testing.T) ([]hartest.Entry, tokens) {
	t.Helper()
	tk := tokens{hartest.JWT(t, "alice", nil), hartest.JWT(t, "bob", nil)}
	a, b := hartest.Bearer(tk.alice), hartest.Bearer(tk.bob)
	es := []hartest.Entry{
		{Method: "POST", URL: base + "/books/v1", Status: 200, Headers: a, ReqJSON: `{"book_title":"a1","secret":"` + secret + `"}`},
		{Method: "POST", URL: base + "/books/v1", Status: 200, Headers: b, ReqJSON: `{"book_title":"b1","secret":"s"}`},
		{Method: "GET", URL: base + "/books/v1/a1", Status: 200, Headers: a},
		{Method: "GET", URL: base + "/books/v1/b1", Status: 200, Headers: b},
		{Method: "GET", URL: base + "/books/v1/a1", Status: 401},
		{Method: "GET", URL: base + "/users/v1/alice", Status: 200, Headers: a},
		{Method: "GET", URL: base + "/me", Status: 200, Headers: a},
		{Method: "GET", URL: base + "/me", Status: 200, Headers: b},
	}
	return es, tk
}

func run(t *testing.T, es []hartest.Entry) (int, string, string) {
	t.Helper()
	har := hartest.WriteHAR(t, t.TempDir(), "t.har", es...)
	var out, errb bytes.Buffer
	code := Execute([]string{"coverage", "--spec", vampi, "--har", har, "--identities", idsFx}, &out, &errb)
	return code, out.String(), errb.String()
}

func TestAcceptance(t *testing.T) {
	es, _ := entries(t)
	code, out, errs := run(t, es)
	t.Logf("stdout:\n%s\nstderr:\n%s", out, errs)
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, errs)
	}
	lines := strings.Split(out, "\n")
	cols := regexp.MustCompile(`\s{2,}`)
	header := cols.Split(strings.TrimSpace(lines[0]), -1)
	row := func(prefix string) map[string]string {
		for _, l := range lines[1:] {
			if strings.HasPrefix(l, prefix) {
				// The endpoint cell is "METHOD<pad>/path": consume it, then split the rest.
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
	book := row("GET     /books/v1/{book_title}")
	for col, want := range map[string]string{"OWNER": "ok", "SAME_ROLE": "GAP", "ANON": "ok 401"} {
		if book[col] != want {
			t.Errorf("books %s = %q, want %q (row %v)", col, book[col], want, book)
		}
	}
	if u := row("GET     /users/v1/{username}"); u["OWNER"] != "ok" {
		t.Errorf("users OWNER = %q", u["OWNER"])
	}
	if !strings.Contains(out, "\nrequired ") {
		t.Errorf("missing footer:\n%s", out)
	}
}

func TestNoNetwork(t *testing.T) {
	oldT, oldR := http.DefaultTransport, net.DefaultResolver
	t.Cleanup(func() { http.DefaultTransport, net.DefaultResolver = oldT, oldR })
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Errorf("network access attempted: %s", req.URL)
		return nil, errors.New("network disabled")
	})
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(_ context.Context, network, addr string) (net.Conn, error) {
		t.Errorf("dns access attempted: %s %s", network, addr)
		return nil, errors.New("network disabled")
	}}
	es, _ := entries(t)
	if code, _, errs := run(t, es); code != ExitOK {
		t.Fatalf("exit = %d; stderr=%s", code, errs)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNoRawSecrets(t *testing.T) {
	es, tk := entries(t)
	code, out, errs := run(t, es)
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	all := out + errs
	for _, tok := range []string{tk.alice, tk.bob} {
		sig := tok[strings.LastIndex(tok, ".")+1:]
		for _, s := range []string{tok, sig, secret} {
			if strings.Contains(all, s) {
				t.Errorf("output leaks %q", s)
			}
		}
	}
}

func TestOrderIndependence(t *testing.T) {
	es, _ := entries(t)
	_, want, _ := run(t, es)
	rev := make([]hartest.Entry, len(es))
	for i, e := range es {
		rev[len(es)-1-i] = e
	}
	shuf := append([]hartest.Entry(nil), es...)
	rng := rand.New(rand.NewSource(42)) //nolint:gosec // fixed seed for a reproducible test shuffle
	rng.Shuffle(len(shuf), func(i, j int) { shuf[i], shuf[j] = shuf[j], shuf[i] })
	for name, v := range map[string][]hartest.Entry{"reversed": rev, "shuffled": shuf} {
		if _, got, _ := run(t, v); got != want {
			t.Errorf("%s output differs:\n%s\nwant:\n%s", name, got, want)
		}
	}
}

func TestPipelineExitCodes(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "identities.yaml")
	notJSON := filepath.Join(dir, "x.har")
	for p, c := range map[string]string{bad: "version: 2\n", notJSON: "not json"} {
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	nothing := hartest.WriteHAR(t, dir, "nope.har", hartest.Entry{Method: "GET", URL: base + "/nope", Status: 200})
	tests := []struct {
		name    string
		har, id string
		want    int
		wantErr string
	}{
		{"invalid identities", nothing, bad, ExitUsage, "identities"},
		{"missing har", filepath.Join(dir, "missing.har"), idsFx, ExitInput, "missing.har"},
		{"har not json", notJSON, idsFx, ExitInput, "x.har"},
		{"nothing matches", nothing, idsFx, ExitInput, "no recorded request matched"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			got := Execute([]string{"coverage", "--spec", vampi, "--har", tt.har, "--identities", tt.id}, &out, &errb)
			if got != tt.want || !strings.Contains(errb.String(), tt.wantErr) {
				t.Fatalf("exit = %d, stderr=%q; want %d containing %q", got, errb.String(), tt.want, tt.wantErr)
			}
		})
	}
}
