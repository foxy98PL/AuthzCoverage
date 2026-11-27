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

// Step is one scripted request. Cell is set only on attacker steps ("METHOD /template|relationship").
type Step struct {
	Cell                    string
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
	return RecordScript(baseURL, harBase, client, SeededScript())
}

// RecordScript is RecordAs with an explicit script.
func RecordScript(baseURL, harBase string, client *http.Client, steps []Step) ([]byte, error) {
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
	for _, s := range steps {
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

// SeededScript is the session that exposes the seeded bug, in order. "{ann}" in a path is the id of the order ann created.
func SeededScript() []Step { return script() }

// ownerSteps are every user's own requests: /me, list, create, get and update their own order.
func ownerSteps() []Step {
	const item = `{"item":"%s"}`
	s := []Step{}
	for _, u := range []string{"ann", "amy", "adminA", "ben", "bob", "adminB"} {
		org := "OrgA"
		if u == "ben" || u == "bob" || u == "adminB" {
			org = "OrgB"
		}
		s = append(s, Step{who: u, method: "GET", path: "/me"}, Step{who: u, method: "GET", path: "/orgs/" + org + "/orders"})
		if strings.HasPrefix(u, "admin") {
			s = append(s, Step{who: u, method: "GET", path: "/orgs/" + org + "/customers"})
			continue
		}
		s = append(s,
			Step{who: u, method: "POST", path: "/orgs/" + org + "/orders", body: `{"item":"gadget"}`, save: u},
			Step{who: u, method: "GET", path: "/orgs/" + org + "/orders/{" + u + "}"},
			Step{who: u, method: "PUT", path: "/orgs/" + org + "/orders/{" + u + "}", body: fmt.Sprintf(item, "gadget-2")})
	}
	return s
}

// script is the session, in order. "{ann}" in a path is the id of the order ann created.
func script() []Step {
	const item = `{"item":"%s"}`
	return append(ownerSteps(),
		// same tenant, other user
		Step{who: "amy", method: "GET", path: "/orgs/OrgA/orders/{ann}"},
		Step{who: "ann", method: "GET", path: "/orgs/OrgA/customers"},
		// cross tenant
		Step{who: "ben", method: "GET", path: "/orgs/OrgA/orders/{ann}"},
		Step{who: "adminB", method: "GET", path: "/orgs/OrgA/orders/{ann}"}, // 200: the seeded bug
		Step{who: "adminB", method: "GET", path: "/orgs/OrgA/orders"},
		Step{who: "adminB", method: "PUT", path: "/orgs/OrgA/orders/{ann}", body: fmt.Sprintf(item, "hijack")},
		Step{who: "adminB", method: "DELETE", path: "/orgs/OrgA/orders/{ann}"},
		Step{who: "ben", method: "GET", path: "/orgs/OrgA/customers"},
		// anonymous
		Step{method: "GET", path: "/orgs/OrgA/orders/{ann}"},
		// owners clean up
		Step{who: "ann", method: "DELETE", path: "/orgs/OrgA/orders/{ann}"},
		Step{who: "ben", method: "DELETE", path: "/orgs/OrgB/orders/{ben}"},
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

func (r *recorder) run(s Step) error {
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

// FullScript is the owner session plus exactly one attacker step per object-level cell authzcov
// requires (same_role_other_user, other_tenant, anonymous on every object endpoint). Every
// attack on a write endpoint targets its own victim order, and the destructive attacks run last,
// so a vulnerable variant cannot break a later step. The cell GET /orgs/{orgId}/customers|lower_role
// is probed too although authzcov does not require it (see the eval README).
func FullScript() []Step {
	const (
		order = "/orgs/OrgA/orders/{%s}"
		list  = "/orgs/OrgA/orders"
		cust  = "/orgs/OrgA/customers"
		ot    = "|other_tenant"
		sr    = "|same_role_other_user"
		an    = "|anonymous"
	)
	const tpl = "/orgs/{orgId}/orders/{orderId}"
	s := ownerSteps()
	methods := []string{"GET", "PUT", "DELETE"}
	rels := []struct{ key, rel string }{{"same", sr}, {"tenant", ot}, {"anon", an}}
	// Dedicated victims, all owned by ann (OrgA).
	for _, m := range methods {
		for _, r := range rels {
			s = append(s, Step{who: "ann", method: "POST", path: "/orgs/OrgA/orders", body: `{"item":"victim"}`, save: m + r.key})
		}
	}
	attack := func(m string) []Step {
		body := ""
		if m == "PUT" {
			body = `{"item":"hijack"}`
		}
		return []Step{
			{Cell: m + " " + tpl + sr, who: "amy", method: m, path: fmt.Sprintf(order, m+"same"), body: body},
			{Cell: m + " " + tpl + ot, who: "adminB", method: m, path: fmt.Sprintf(order, m+"tenant"), body: body},
			{Cell: m + " " + tpl + an, method: m, path: fmt.Sprintf(order, m+"anon"), body: body},
		}
	}
	s = append(s, attack("GET")...)
	s = append(s,
		Step{Cell: "GET /orgs/{orgId}/orders" + ot, who: "adminB", method: "GET", path: list},
		Step{Cell: "GET /orgs/{orgId}/orders" + an, method: "GET", path: list},
		Step{Cell: "GET /orgs/{orgId}/customers" + ot, who: "adminB", method: "GET", path: cust},
		Step{Cell: "GET /orgs/{orgId}/customers" + an, method: "GET", path: cust},
		Step{Cell: "GET /orgs/{orgId}/customers|lower_role", who: "ann", method: "GET", path: cust},
		Step{Cell: "POST /orgs/{orgId}/orders" + ot, who: "adminB", method: "POST", path: list, body: `{"item":"intruder"}`},
		Step{Cell: "POST /orgs/{orgId}/orders" + an, method: "POST", path: list, body: `{"item":"intruder"}`},
	)
	s = append(s, attack("PUT")...)
	s = append(s, attack("DELETE")...)
	return append(s,
		// owners clean up
		Step{who: "ann", method: "DELETE", path: "/orgs/OrgA/orders/{ann}"},
		Step{who: "ben", method: "DELETE", path: "/orgs/OrgB/orders/{ben}"},
	)
}
