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

// fakeHost replaces the random localhost port in the HAR; the spec's server base path is /api, so recorded
// paths start with /api and match the spec's `servers` entry.
const fakeHost = "http://realworld.test"

// step is the observed outcome of one recorded call, used to confirm the ground truth empirically.
type step struct {
	Tag    string `json:"tag,omitempty"`
	Who    string `json:"who"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
}

// stack is one running RealWorld app: the published (socat-relayed) address of its API.
type stack struct {
	web string
}

type recorder struct {
	st      stack
	client  *http.Client
	entries []harEntry
	steps   []step
	tokens  map[string]string
	users   map[string]*user
}

// user is a synthetic RealWorld account. Everything here is throwaway test data (demo credentials, fresh stack).
type user struct {
	name, email, pass string
	slug              string // the user's main article
	comment           string // id of a comment of the user on their own article
}

func newRecorder(st stack) *recorder {
	return &recorder{
		st:     st,
		client: &http.Client{Timeout: 30 * time.Second},
		tokens: map[string]string{},
		users:  map[string]*user{},
	}
}

func newUser(name string) *user {
	title := strings.ToUpper(name[:1]) + name[1:]
	return &user{name: name, email: name + "@example.test", pass: "Pw-" + title + "-1!x"}
}

// setupError is a failure while preparing users or readiness (as opposed to a probe answering an unexpected
// status, which is data). recordSession retries on a fresh stack.
type setupError string

func setupFail(format string, a ...any) { panic(setupError(fmt.Sprintf(format, a...))) }

// do performs one request. A transport error is a setupError: the app may still be settling.
func (r *recorder) do(req *http.Request) (*http.Response, []byte) {
	resp, err := r.client.Do(req)
	if err != nil {
		setupFail("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

// call performs one JSON request as `who` ("" = anonymous) and records it.
func (r *recorder) call(tag, who, method, path string, body any) (int, []byte) {
	var rb []byte
	ct := ""
	if body != nil {
		rb, _ = json.Marshal(body)
		ct = "application/json"
	}
	return r.send(tag, who, method, path, rb, ct)
}

func (r *recorder) send(tag, who, method, path string, rb []byte, ct string) (int, []byte) {
	req, err := http.NewRequest(method, r.st.web+path, bytes.NewReader(rb))
	if err != nil {
		panic(err)
	}
	var hdrs []harHeader
	if ct != "" {
		req.Header.Set("Content-Type", ct)
		hdrs = append(hdrs, harHeader{"Content-Type", ct})
	}
	if who != "" {
		auth := "Token " + r.tokens[who]
		req.Header.Set("Authorization", auth)
		hdrs = append(hdrs, harHeader{"Authorization", auth})
	}
	resp, rbody := r.do(req)
	rct := resp.Header.Get("Content-Type")
	e := harEntry{
		Started: epoch.Add(time.Duration(len(r.entries)) * time.Second).Format("2006-01-02T15:04:05.000Z"),
		Request: harReq{
			Method: method, URL: fakeHost + path, HTTPVersion: "HTTP/1.1",
			Cookies: []string{}, Headers: nonNil(hdrs), QueryString: []string{},
			HeadersSize: -1, BodySize: len(rb),
		},
		Response: harRes{
			Status: resp.StatusCode, StatusText: http.StatusText(resp.StatusCode), HTTPVersion: "HTTP/1.1",
			Cookies: []string{}, Headers: []harHeader{{"Content-Type", rct}},
			Content:     harContent{Size: len(rbody), MimeType: rct, Text: string(rbody)},
			HeadersSize: -1, BodySize: len(rbody),
		},
	}
	e.Time = 1 // deterministic
	if len(rb) > 0 {
		e.Request.PostData = &harPost{MimeType: ct, Text: string(rb)}
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

// field reads a scalar at a dotted path of a JSON body ("" when absent). Numbers are printed without exponent.
func field(b []byte, path ...string) string {
	var v any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return ""
	}
	for _, p := range path {
		switch m := v.(type) {
		case map[string]any:
			v = m[p]
		case []any:
			if len(m) == 0 {
				return ""
			}
			v = m[0]
			if mm, ok := v.(map[string]any); ok {
				v = mm[p]
			}
		default:
			return ""
		}
	}
	switch s := v.(type) {
	case string:
		return s
	case json.Number:
		return s.String()
	}
	return ""
}

var names = []string{"alice", "bob", "carol"}

// register creates the account (POST /api/users answers 201) and logs in. Accounts are created in the order of
// names: the app's JWT carries the sequential row id (alice=1, bob=2, carol=3), which identities.yaml matches.
func (r *recorder) setup() {
	for _, n := range names {
		u := newUser(n)
		r.users[n] = u
		code, b := r.call("", "", "POST", "/api/users", map[string]any{"user": map[string]any{"username": u.name, "email": u.email, "password": u.pass}})
		if code != http.StatusCreated {
			setupFail("register %s: status %d: %s", n, code, b)
		}
	}
	for _, n := range names {
		u := r.users[n]
		code, b := r.call("", "", "POST", "/api/users/login", map[string]any{"user": map[string]any{"email": u.email, "password": u.pass}})
		tok := field(b, "user", "token")
		if code != http.StatusOK || tok == "" {
			setupFail("login %s: status %d: %s", n, code, b)
		}
		r.tokens[n] = tok
	}
}

func article(title string) map[string]any {
	return map[string]any{"article": map[string]any{"title": title, "description": "about " + title, "body": "text of " + title, "tagList": []string{"demo"}}}
}

// honest: every user touches only their own articles and comments (profile follows name another user, which is
// the point of a follow and not an owned object).
func (r *recorder) honest() {
	r.setup()
	for i, n := range names {
		u := r.users[n]
		next := names[(i+1)%len(names)]
		r.call("", n, "GET", "/api/user", nil)
		r.call("", n, "PUT", "/api/user", map[string]any{"user": map[string]any{"bio": "bio of " + n}})
		r.call("", n, "GET", "/api/profiles/"+n, nil)

		_, b := r.call("", n, "POST", "/api/articles", article("Article of "+n))
		u.slug = field(b, "article", "slug")
		if u.slug == "" {
			setupFail("create article of %s: %s", n, b)
		}
		r.call("", n, "GET", "/api/articles/"+u.slug, nil)
		r.call("", n, "PUT", "/api/articles/"+u.slug, map[string]any{"article": map[string]any{"description": "edited by " + n}})
		r.call("", n, "POST", "/api/articles/"+u.slug+"/favorite", nil)
		r.call("", n, "DELETE", "/api/articles/"+u.slug+"/favorite", nil)

		_, b = r.call("", n, "POST", "/api/articles/"+u.slug+"/comments", map[string]any{"comment": map[string]any{"body": "my first note"}})
		first := field(b, "comment", "id")
		r.call("", n, "GET", "/api/articles/"+u.slug+"/comments", nil)
		r.call("", n, "DELETE", "/api/articles/"+u.slug+"/comments/"+first, nil)
		_, b = r.call("", n, "POST", "/api/articles/"+u.slug+"/comments", map[string]any{"comment": map[string]any{"body": "my kept note"}})
		u.comment = field(b, "comment", "id")
		if u.comment == "" {
			setupFail("create comment of %s: %s", n, b)
		}

		_, b = r.call("", n, "POST", "/api/articles", article("Throwaway of "+n))
		if tw := field(b, "article", "slug"); tw != "" {
			r.call("", n, "DELETE", "/api/articles/"+tw, nil)
		}

		r.call("", n, "POST", "/api/profiles/"+next+"/follow", nil)
		r.call("", n, "GET", "/api/articles/feed", nil)
		r.call("", n, "DELETE", "/api/profiles/"+next+"/follow", nil)
		r.call("", n, "GET", "/api/articles", nil)
		r.call("", n, "GET", "/api/tags", nil)
	}
}

// attack: honest + cross-user and anonymous attempts, each tagged and listed in groundtruth.yaml.
// Destructive attempts (DELETE) come last.
func (r *recorder) attack() {
	r.honest()
	a, b := r.users["alice"], r.users["bob"]
	pair := func(tag, method, pathFmt string, body any, idOf func(*user) string) {
		r.call(tag, "bob", method, fmt.Sprintf(pathFmt, idOf(a)), body)
		r.call(tag, "alice", method, fmt.Sprintf(pathFmt, idOf(b)), body)
	}
	slug := func(u *user) string { return u.slug }
	edit := map[string]any{"article": map[string]any{"description": "edited by someone else"}}
	note := map[string]any{"comment": map[string]any{"body": "note by someone else"}}

	pair("article_get_other", "GET", "/api/articles/%s", nil, slug)
	r.call("article_get_anon", "", "GET", "/api/articles/"+a.slug, nil)
	pair("comments_get_other", "GET", "/api/articles/%s/comments", nil, slug)
	r.call("comments_get_anon", "", "GET", "/api/articles/"+a.slug+"/comments", nil)
	pair("article_put_other", "PUT", "/api/articles/%s", edit, slug)
	r.call("article_put_anon", "", "PUT", "/api/articles/"+a.slug, edit)
	pair("favorite_other", "POST", "/api/articles/%s/favorite", nil, slug)
	pair("unfavorite_other", "DELETE", "/api/articles/%s/favorite", nil, slug)
	r.call("favorite_anon", "", "POST", "/api/articles/"+a.slug+"/favorite", nil)
	pair("comment_post_other", "POST", "/api/articles/%s/comments", note, slug)
	r.call("comment_post_anon", "", "POST", "/api/articles/"+a.slug+"/comments", note)
	r.call("user_get_anon", "", "GET", "/api/user", nil)
	r.call("user_put_anon", "", "PUT", "/api/user", map[string]any{"user": map[string]any{"bio": "anon"}})
	r.call("follow_anon", "", "POST", "/api/profiles/alice/follow", nil)

	// Destructive attempts last: a missing owner check would delete the victim's object.
	r.call("comment_del_other", "bob", "DELETE", "/api/articles/"+a.slug+"/comments/"+a.comment, nil)
	r.call("comment_del_other", "alice", "DELETE", "/api/articles/"+b.slug+"/comments/"+b.comment, nil)
	r.call("comment_del_anon", "", "DELETE", "/api/articles/"+a.slug+"/comments/"+a.comment, nil)
	pair("article_del_other", "DELETE", "/api/articles/%s", nil, slug)
	r.call("article_del_anon", "", "DELETE", "/api/articles/"+a.slug, nil)
}

// recordSession records one suite on a fresh stack, retrying on setupError (a slow service, a lost mail). `open`
// starts a stack and returns it with its teardown; the stack of a failed attempt is torn down before the next
// attempt, and entries of a failed attempt are discarded, so the HAR is one clean session. The returned stack
// is still running; the caller calls its teardown.
func recordSession(open func() (stack, func()), suite string, attempts int) (*recorder, func()) {
	var last setupError
	for i := 0; i < attempts; i++ {
		st, stop := open()
		r := newRecorder(st)
		if tryRecord(r, suite, &last) {
			if i > 0 {
				fmt.Printf("%s: recorded on attempt %d (retried: %s)\n", suite, i+1, last)
			}
			return r, stop
		}
		fmt.Printf("%s: attempt %d failed: %s\n", suite, i+1, last)
		stop()
	}
	fatal(fmt.Sprintf("%s: setup failed %d times, last: %s", suite, attempts, last))
	return nil, nil
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
