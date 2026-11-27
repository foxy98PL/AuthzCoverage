// Package record drives a scripted tenantshop session and returns it as a HAR 1.2 document.
// The output is deterministic against a fresh server: fixed timestamps, fixed JWTs, no timing data.
package record

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const started = "2026-01-01T00:00:00.000Z"

type kv struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type step struct {
	who, method, path, body string
	save                    string // when set, remember the response "id" under this name
	idFrom                  string // when set, {id} in path is replaced by the saved id
}

type recorder struct {
	base, harBase string
	client        *http.Client
	tokens        map[string]string
	ids           map[string]string
	entries       []map[string]any
}

// Record runs the script against baseURL and writes the same URLs into the HAR.
func Record(baseURL string, client *http.Client) ([]byte, error) {
	return RecordAs(baseURL, baseURL, client)
}

// RecordAs sends requests to baseURL but writes harBase into the HAR URLs (so a random test port stays out of it).
func RecordAs(baseURL, harBase string, client *http.Client) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	r := &recorder{base: strings.TrimRight(baseURL, "/"), harBase: strings.TrimRight(harBase, "/"),
		client: client, tokens: map[string]string{}, ids: map[string]string{}}
	users := []string{"ann", "amy", "adminA", "ben", "bob", "adminB"}
	for _, u := range users {
		if err := r.login(u); err != nil {
			return nil, err
		}
	}
	for _, s := range script() {
		if err := r.run(s); err != nil {
			return nil, err
		}
	}
	doc := map[string]any{"log": map[string]any{
		"version": "1.2", "creator": map[string]string{"name": "tenantshop-recorder", "version": "1"},
		"entries": r.entries,
	}}
	return json.MarshalIndent(doc, "", "  ")
}

// script is the session, in order. "{ann}" in a path is the id of the order ann created.
func script() []step {
	const item = `{"item":"%s"}`
	s := []step{}
	for _, u := range []string{"ann", "amy", "adminA", "ben", "bob", "adminB"} {
		org := "OrgA"
		if u == "ben" || u == "bob" || u == "adminB" {
			org = "OrgB"
		}
		s = append(s, step{who: u, method: "GET", path: "/me"}, step{who: u, method: "GET", path: "/orgs/" + org + "/orders"})
		if strings.HasPrefix(u, "admin") {
			s = append(s, step{who: u, method: "GET", path: "/orgs/" + org + "/customers"})
			continue
		}
		s = append(s,
			step{who: u, method: "POST", path: "/orgs/" + org + "/orders", body: `{"item":"gadget"}`, save: u},
			step{who: u, method: "GET", path: "/orgs/" + org + "/orders/{" + u + "}"},
			step{who: u, method: "PUT", path: "/orgs/" + org + "/orders/{" + u + "}", body: fmt.Sprintf(item, "gadget-2")})
	}
	return append(s,
		// same tenant, other user
		step{who: "amy", method: "GET", path: "/orgs/OrgA/orders/{ann}"},
		step{who: "ann", method: "GET", path: "/orgs/OrgA/customers"},
		// cross tenant
		step{who: "ben", method: "GET", path: "/orgs/OrgA/orders/{ann}"},
		step{who: "adminB", method: "GET", path: "/orgs/OrgA/orders/{ann}"}, // 200: the seeded bug
		step{who: "adminB", method: "GET", path: "/orgs/OrgA/orders"},
		step{who: "adminB", method: "PUT", path: "/orgs/OrgA/orders/{ann}", body: fmt.Sprintf(item, "hijack")},
		step{who: "adminB", method: "DELETE", path: "/orgs/OrgA/orders/{ann}"},
		step{who: "ben", method: "GET", path: "/orgs/OrgA/customers"},
		// anonymous
		step{method: "GET", path: "/orgs/OrgA/orders/{ann}"},
		// owners clean up
		step{who: "ann", method: "DELETE", path: "/orgs/OrgA/orders/{ann}"},
		step{who: "ben", method: "DELETE", path: "/orgs/OrgB/orders/{ben}"},
	)
}

func (r *recorder) login(user string) error {
	resp, err := r.do("", "POST", "/login", fmt.Sprintf(`{"username":%q,"password":"demo"}`, user))
	if err != nil {
		return err
	}
	var out struct{ Token string }
	if json.Unmarshal(resp, &out) != nil || out.Token == "" {
		return fmt.Errorf("login %s: no token in %s", user, resp)
	}
	r.tokens[user] = out.Token
	return nil
}

func (r *recorder) run(s step) error {
	path := s.path
	for name, id := range r.ids {
		path = strings.ReplaceAll(path, "{"+name+"}", id)
	}
	resp, err := r.do(s.who, s.method, path, s.body)
	if err != nil {
		return err
	}
	if s.save != "" {
		var o struct{ ID string }
		if json.Unmarshal(resp, &o) != nil || o.ID == "" {
			return fmt.Errorf("%s %s: no id in response %s", s.method, path, resp)
		}
		r.ids[s.save] = o.ID
	}
	return nil
}

// do sends one request, appends a HAR entry, and returns the response body.
func (r *recorder) do(who, method, path, body string) ([]byte, error) {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, r.base+path, rd)
	if err != nil {
		return nil, err
	}
	hdrs := []kv{}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
		hdrs = append(hdrs, kv{"Content-Type", "application/json"})
	}
	if who != "" {
		req.Header.Set("Authorization", "Bearer "+r.tokens[who])
		hdrs = append([]kv{{"Authorization", "Bearer " + r.tokens[who]}}, hdrs...)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	mime := resp.Header.Get("Content-Type")
	rh := []kv{}
	if mime != "" {
		rh = append(rh, kv{"Content-Type", mime})
	}
	reqM := map[string]any{"method": method, "url": r.harBase + path, "httpVersion": "HTTP/1.1",
		"headers": hdrs, "queryString": []any{}, "cookies": []any{}, "headersSize": -1, "bodySize": -1}
	if body != "" {
		reqM["postData"] = map[string]string{"mimeType": "application/json", "text": body}
	}
	content := map[string]any{"size": len(rb), "mimeType": mime}
	if len(bytes.TrimSpace(rb)) > 0 {
		content["text"] = string(rb)
	}
	r.entries = append(r.entries, map[string]any{
		"startedDateTime": started, "time": 1, "request": reqM,
		"response": map[string]any{"status": resp.StatusCode, "statusText": http.StatusText(resp.StatusCode),
			"httpVersion": "HTTP/1.1", "headers": rh, "cookies": []any{}, "content": content,
			"redirectURL": "", "headersSize": -1, "bodySize": len(rb)},
		"cache": map[string]any{}, "timings": map[string]any{"send": 0, "wait": 1, "receive": 0},
	})
	return rb, nil
}
