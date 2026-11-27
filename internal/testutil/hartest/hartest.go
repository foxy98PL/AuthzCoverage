// Package hartest builds HAR fixtures and JWTs for tests.
package hartest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"authzcov/internal/testkey"
)

// Issuer is the iss claim of fixture JWTs.
const Issuer = testkey.Issuer

// TestKey signs fixture JWTs. It protects nothing; fixtures are generated at test time.
var TestKey = testkey.Key

// JWT returns an HS256 token signed with TestKey with claims iss=Issuer, sub=sub, plus extra.
func JWT(t testing.TB, sub string, extra map[string]any) string {
	t.Helper()
	claims := jwt.MapClaims{}
	for k, v := range extra {
		claims[k] = v
	}
	claims["iss"] = Issuer
	claims["sub"] = sub
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(TestKey)
	if err != nil {
		t.Fatalf("hartest: sign jwt: %v", err)
	}
	return s
}

// Entry describes one recorded request/response.
type Entry struct {
	Method   string
	URL      string // absolute, e.g. "http://localhost:5000/books/v1"
	Status   int
	Headers  map[string]string // request headers (sorted by name on output)
	ReqJSON  string            // "" => no postData
	RespJSON string            // "" => empty content
	RespMIME string            // overrides response mimeType when set
}

// Bearer returns Headers with Authorization: Bearer tok.
func Bearer(tok string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + tok}
}

type kv struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type m = map[string]any

func headers(h map[string]string) []kv {
	out := make([]kv, 0, len(h))
	for k, v := range h {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func entry(e Entry) m {
	req := m{
		"method": e.Method, "url": e.URL, "httpVersion": "HTTP/1.1",
		"headers": headers(e.Headers), "queryString": []any{}, "cookies": []any{},
		"headersSize": -1, "bodySize": -1,
	}
	if e.ReqJSON != "" {
		req["postData"] = m{"mimeType": "application/json", "text": e.ReqJSON}
	}
	mime := "application/json"
	if e.RespMIME != "" {
		mime = e.RespMIME
	}
	content := m{"size": len(e.RespJSON), "mimeType": mime}
	if e.RespJSON != "" {
		content["text"] = e.RespJSON
	}
	resp := m{
		"status": e.Status, "statusText": "", "httpVersion": "HTTP/1.1",
		"headers": []any{}, "cookies": []any{}, "content": content,
		"redirectURL": "", "headersSize": -1, "bodySize": -1,
	}
	return m{
		"startedDateTime": "2026-01-01T00:00:00.000Z", "time": 1,
		"request": req, "response": resp, "cache": m{},
		"timings": m{"send": 0, "wait": 1, "receive": 0},
	}
}

// HAR returns a valid HAR 1.2 document for the entries.
func HAR(entries ...Entry) []byte {
	es := make([]m, 0, len(entries))
	for _, e := range entries {
		es = append(es, entry(e))
	}
	doc := m{"log": m{
		"version": "1.2",
		"creator": m{"name": "hartest", "version": "1"},
		"entries": es,
	}}
	b, err := json.Marshal(doc)
	if err != nil {
		// Unreachable: doc holds only strings, ints and maps. A nil HAR makes the
		// caller's parse fail loudly instead of panicking.
		return nil
	}
	return b
}

// WriteHAR writes HAR(entries...) to dir/name and returns the path.
func WriteHAR(t testing.TB, dir, name string, entries ...Entry) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, HAR(entries...), 0o600); err != nil {
		t.Fatalf("hartest: write har: %v", err)
	}
	return p
}
