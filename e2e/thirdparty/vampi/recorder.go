package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const fakeHost = "http://vampi.test"

// step is the observed outcome of one recorded call, used to confirm the
// ground truth empirically.
type step struct {
	Tag    string `json:"tag,omitempty"`
	Who    string `json:"who"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
}

type recorder struct {
	base    string // real http://127.0.0.1:port
	client  *http.Client
	entries []harEntry
	steps   []step
	tokens  map[string]string
	pw      map[string]string
}

func newRecorder(base string) *recorder {
	return &recorder{
		base:   base,
		client: &http.Client{Timeout: 30 * time.Second},
		tokens: map[string]string{},
		pw:     map[string]string{},
	}
}

// call performs one request as `who` ("" = anonymous) and records it.
func (r *recorder) call(tag, who, method, path string, body any) (int, []byte) {
	var rb []byte
	if body != nil {
		rb, _ = json.Marshal(body)
	}
	req, err := http.NewRequest(method, r.base+path, bytes.NewReader(rb))
	if err != nil {
		panic(err)
	}
	var hdrs []harHeader
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		hdrs = append(hdrs, harHeader{"Content-Type", "application/json"})
	}
	if who != "" {
		tok := r.tokens[who]
		req.Header.Set("Authorization", "Bearer "+tok)
		hdrs = append(hdrs, harHeader{"Authorization", "Bearer " + tok})
	}
	start := time.Now()
	resp, err := r.client.Do(req)
	if err != nil {
		panic(fmt.Sprintf("%s %s: %v", method, path, err))
	}
	defer resp.Body.Close()
	rbody, _ := io.ReadAll(resp.Body)
	ct := resp.Header.Get("Content-Type")

	e := harEntry{
		Started: epoch.Add(time.Duration(len(r.entries)) * time.Second).Format("2006-01-02T15:04:05.000Z"),
		Time:    int(time.Since(start).Milliseconds()),
		Request: harReq{
			Method: method, URL: fakeHost + path, HTTPVersion: "HTTP/1.1",
			Cookies: []string{}, Headers: nonNil(hdrs), QueryString: []string{},
			HeadersSize: -1, BodySize: len(rb),
		},
		Response: harRes{
			Status: resp.StatusCode, StatusText: http.StatusText(resp.StatusCode), HTTPVersion: "HTTP/1.1",
			Cookies: []string{}, Headers: []harHeader{{"Content-Type", ct}},
			Content:     harContent{Size: len(rbody), MimeType: ct, Text: string(rbody)},
			HeadersSize: -1, BodySize: len(rbody),
		},
	}
	e.Time = 1 // deterministic
	if body != nil {
		e.Request.PostData = &harPost{MimeType: "application/json", Text: string(rb)}
	}
	r.entries = append(r.entries, e)
	r.steps = append(r.steps, step{Tag: tag, Who: orAnon(who), Method: method, Path: path, Status: resp.StatusCode})
	return resp.StatusCode, rbody
}

func nonNil(h []harHeader) []harHeader {
	if h == nil {
		return []harHeader{}
	}
	return h
}

func orAnon(s string) string {
	if s == "" {
		return "anonymous"
	}
	return s
}

func (r *recorder) register(name, email string, extra map[string]any) {
	r.pw[name] = "Pw-" + name + "-v1"
	body := map[string]any{"username": name, "password": r.pw[name], "email": email}
	for k, v := range extra {
		body[k] = v
	}
	r.call("", "", "POST", "/users/v1/register", body)
}

func (r *recorder) login(name, password string) {
	if password == "" {
		password = r.pw[name]
	}
	_, b := r.call("", "", "POST", "/users/v1/login", map[string]any{"username": name, "password": password})
	var out struct {
		Token string `json:"auth_token"`
	}
	_ = json.Unmarshal(b, &out)
	if out.Token == "" {
		panic(setupError("login failed for " + name + ": " + strings.TrimSpace(string(b))))
	}
	r.tokens[name] = out.Token
}

// honest: every caller touches only their own objects; admin does admin work.
// setupError is a failed login during a recorded session. VAmPI gives every
// new user a book titled "bookTitle"+randrange(100) with a unique title
// (models/user_model.py register_user, models/books_model.py), so about one
// session in eight loses a user to a title collision. recordSession retries
// such sessions from a fresh /createdb.
type setupError string

// recordSession runs one suite, retrying up to attempts times on setupError.
// Entries of a failed attempt are discarded, so the HAR is one clean session.
func recordSession(base, suite string, attempts int) *recorder {
	var last setupError
	for i := 0; i < attempts; i++ {
		r := newRecorder(base)
		if tryRecord(r, suite, &last) {
			if i > 0 {
				fmt.Printf("%s: recorded on attempt %d (retried: %s)\n", suite, i+1, last)
			}
			return r
		}
	}
	fatal(fmt.Sprintf("%s: setup failed %d times, last: %s", suite, attempts, last))
	return nil
}

func tryRecord(r *recorder, suite string, last *setupError) (ok bool) {
	defer func() {
		if e := recover(); e != nil {
			se, isSetup := e.(setupError)
			if !isSetup {
				panic(e)
			}
			*last, ok = se, false
		}
	}()
	if suite == "honest" {
		r.honest()
	} else {
		r.attack()
	}
	return true
}

func (r *recorder) honest() {
	r.call("", "", "GET", "/createdb", nil)
	r.call("", "", "GET", "/", nil)
	for _, n := range []string{"alice", "bob", "carol"} {
		r.register(n, n+"@example.com", nil)
	}
	for _, n := range []string{"alice", "bob", "carol"} {
		r.login(n, "")
	}
	r.login("admin", "pass1") // seeded by /createdb (models/user_model.py:init_db_users)

	for _, n := range []string{"alice", "bob", "carol"} {
		r.call("", n, "POST", "/books/v1", map[string]any{"book_title": n + "-book", "secret": "secret of " + n})
	}
	for _, n := range []string{"alice", "bob", "carol", "admin"} {
		r.call("", n, "GET", "/me", nil)
	}
	for _, n := range []string{"alice", "bob", "carol"} {
		r.call("", n, "GET", "/books/v1/"+n+"-book", nil)
		r.call("", n, "GET", "/users/v1/"+n, nil)
	}
	r.call("", "alice", "GET", "/books/v1", nil)
	r.call("", "", "GET", "/books/v1", nil) // public listing
	r.call("", "", "GET", "/users/v1", nil) // public listing
	r.call("", "alice", "PUT", "/users/v1/alice/email", map[string]any{"email": "alice.new@example.com"})
	r.call("", "bob", "PUT", "/users/v1/bob/email", map[string]any{"email": "bob2@example.com"})
	r.call("", "alice", "PUT", "/users/v1/alice/password", map[string]any{"password": "Pw-alice-v2"})
	r.call("", "bob", "PUT", "/users/v1/bob/password", map[string]any{"password": "Pw-bob-v2"})
	r.call("", "admin", "DELETE", "/users/v1/carol", nil) // admin work
}

// attack: honest + cross-user, anonymous and lower-role attempts.
func (r *recorder) attack() {
	r.honest()
	r.call("bola_book", "bob", "GET", "/books/v1/alice-book", nil)
	r.call("bola_book", "alice", "GET", "/books/v1/bob-book", nil)
	r.call("book_anon", "", "GET", "/books/v1/alice-book", nil)

	r.call("user_get_other", "bob", "GET", "/users/v1/alice", nil)
	r.call("user_get_other", "alice", "GET", "/users/v1/bob", nil)
	r.call("user_get_anon", "", "GET", "/users/v1/alice", nil)

	r.call("email_other", "bob", "PUT", "/users/v1/alice/email", map[string]any{"email": "evil.bob@example.com"})
	r.call("email_other", "alice", "PUT", "/users/v1/bob/email", map[string]any{"email": "evil.alice@example.com"})
	r.call("email_anon", "", "PUT", "/users/v1/alice/email", map[string]any{"email": "anon@example.com"})

	r.call("delete_other", "bob", "DELETE", "/users/v1/alice", nil)
	r.call("delete_other", "alice", "DELETE", "/users/v1/bob", nil)
	r.call("delete_anon", "", "DELETE", "/users/v1/alice", nil)

	r.call("debug_anon", "", "GET", "/users/v1/_debug", nil)
	r.call("debug_user", "alice", "GET", "/users/v1/_debug", nil)
	r.call("debug_admin", "admin", "GET", "/users/v1/_debug", nil)

	r.register("mallory", "mallory@example.com", map[string]any{"admin": true}) // mass assignment (not authz)
	r.steps[len(r.steps)-1].Tag = "mass_assign"

	// Password attacks last: they change the victims' passwords.
	r.call("pw_anon", "", "PUT", "/users/v1/alice/password", map[string]any{"password": "Pw-anon-set"})
	r.call("pwchange_other", "bob", "PUT", "/users/v1/alice/password", map[string]any{"password": "Pw-bob-set"})
	r.call("pwchange_other", "alice", "PUT", "/users/v1/bob/password", map[string]any{"password": "Pw-alice-set"})
}
