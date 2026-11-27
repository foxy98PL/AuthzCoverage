package hartest

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWT(t *testing.T) {
	tok := JWT(t, "alice", map[string]any{"role": "admin"})
	var c jwt.MapClaims
	if _, _, err := jwt.NewParser().ParseUnverified(tok, &c); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{"iss": Issuer, "sub": "alice", "role": "admin"} {
		if c[k] != want {
			t.Errorf("claim %s = %v, want %v", k, c[k], want)
		}
	}
}

func TestHAR(t *testing.T) {
	b := HAR(
		Entry{Method: "POST", URL: "http://h/x", Status: 200, Headers: map[string]string{"B": "2", "A": "1"}, ReqJSON: `{"a":1}`, RespJSON: `{"b":2}`},
		Entry{Method: "GET", URL: "http://h/y", Status: 204, RespMIME: "text/plain"},
	)
	var doc struct {
		Log struct {
			Version string
			Entries []struct {
				Request struct {
					Headers  []struct{ Name string }
					PostData *struct{ MimeType, Text string }
				}
				Response struct {
					Status  int
					Content struct{ MimeType string }
				}
			}
		}
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	es := doc.Log.Entries
	if doc.Log.Version != "1.2" || len(es) != 2 {
		t.Fatalf("version %q, %d entries", doc.Log.Version, len(es))
	}
	if h := es[0].Request.Headers; len(h) != 2 || h[0].Name != "A" {
		t.Errorf("headers not sorted: %v", h)
	}
	if p := es[0].Request.PostData; p == nil || p.MimeType != "application/json" || p.Text != `{"a":1}` {
		t.Errorf("postData = %+v", p)
	}
	if es[1].Request.PostData != nil || es[1].Response.Content.MimeType != "text/plain" || es[1].Response.Status != 204 {
		t.Errorf("second entry = %+v", es[1])
	}
}

func TestBearerAndWrite(t *testing.T) {
	if got := Bearer("x")["Authorization"]; got != "Bearer x" {
		t.Errorf("Bearer = %q", got)
	}
	p := WriteHAR(t, t.TempDir(), "a.har", Entry{Method: "GET", URL: "http://h/", Status: 200})
	b, err := os.ReadFile(p) //nolint:gosec // path comes from t.TempDir
	if err != nil || !strings.Contains(string(b), `"entries"`) {
		t.Errorf("read %s: %v", p, err)
	}
}
