package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const fakeHost = "http://crapi.test"

// adminEmail/adminPass is crAPI's seeded administrator (services/identity/src/main/java/com/crapi/constant/TestUsers.java,
// published in the crAPI repository). It is not a secret of ours; the stack is thrown away after each run.
const (
	adminEmail = "admin@example.com"
	adminPass  = "Admin!123"
)

// step is the observed outcome of one recorded call, used to confirm the ground truth empirically.
type step struct {
	Tag    string `json:"tag,omitempty"`
	Who    string `json:"who"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
}

// stack is one running crAPI: the web entry point (nginx, all /identity /community /workshop traffic is
// recorded through it) and MailHog's API (not recorded; it only delivers the welcome e-mail with VIN and pin).
type stack struct {
	web, mail string
}

type recorder struct {
	st      stack
	client  *http.Client
	entries []harEntry
	steps   []step
	tokens  map[string]string
	users   map[string]*user
	mailTO  time.Duration
}

// user is a synthetic crAPI customer. Everything here is throwaway test data.
type user struct {
	name, email, pass, number string
	vin, pin                  string
	vehicle                   string // vehicle uuid
	order, video, post        string
	report                    string // mechanic report id
}

func newRecorder(st stack) *recorder {
	return &recorder{
		st:     st,
		client: &http.Client{Timeout: 60 * time.Second},
		tokens: map[string]string{},
		users:  map[string]*user{},
		mailTO: 60 * time.Second,
	}
}

func newUser(name string, n int) *user {
	title := strings.ToUpper(name[:1]) + name[1:]
	return &user{name: name, email: name + "@example.test", pass: "Pw-" + title + "-1!x",
		number: fmt.Sprintf("55501000%02d", n)}
}

// setupError is a failure while preparing users, vehicles or readiness (as opposed to a probe answering an
// unexpected status, which is data). recordSession retries on a fresh stack.
type setupError string

func setupFail(format string, a ...any) { panic(setupError(fmt.Sprintf(format, a...))) }

// do performs one request. A transport error is a setupError: crAPI's JVM services are slow to settle.
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

// upload sends a multipart/form-data file field (the profile video).
func (r *recorder) upload(tag, who, path, field, filename string, content []byte) (int, []byte) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.SetBoundary("authzcovboundary")
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, field, filename))
	h.Set("Content-Type", "video/mp4")
	part, _ := w.CreatePart(h)
	_, _ = part.Write(content)
	_ = w.Close()
	return r.send(tag, who, "POST", path, buf.Bytes(), w.FormDataContentType())
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
		auth := "Bearer " + r.tokens[who]
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
	r.steps = append(r.steps, step{Tag: tag, Who: orAnon(who), Method: method, Path: stablePath(path), Status: resp.StatusCode})
	return resp.StatusCode, rbody
}

var (
	uuidRE   = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	postIDRE = regexp.MustCompile(`/posts/[A-Za-z0-9]{22}`)
)

// stablePath hides ids that crAPI generates at random (vehicle uuids, post ids) so that the probes in the
// result file are identical between runs. The HAR keeps the real paths.
func stablePath(p string) string {
	p = uuidRE.ReplaceAllString(p, "{uuid}")
	return postIDRE.ReplaceAllString(p, "/posts/{id}")
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

var (
	vinRE = regexp.MustCompile(`(?s)VIN:.*?>([A-Z0-9]{17})</font>`)
	pinRE = regexp.MustCompile(`(?s)Pincode:.*?>(\d{4})</font>`)
)

// welcomeMail polls MailHog for the welcome e-mail of crAPI (services/identity: VehicleServiceImpl sends VIN and
// pin code to the new user's address) and returns VIN and pin code.
func (r *recorder) welcomeMail(email string) (vin, pin string) {
	deadline := time.Now().Add(r.mailTO)
	for {
		req, _ := http.NewRequest("GET", r.st.mail+"/api/v2/search?kind=to&query="+url.QueryEscape(email), nil)
		resp, b := r.do(req)
		if resp.StatusCode == 200 {
			var doc struct {
				Items []struct {
					Raw struct{ Data string }
				} `json:"items"`
			}
			if json.Unmarshal(b, &doc) == nil {
				for _, it := range doc.Items {
					dec, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(it.Raw.Data)))
					if err != nil {
						continue
					}
					v, p := vinRE.FindSubmatch(dec), pinRE.FindSubmatch(dec)
					if v != nil && p != nil {
						return string(v[1]), string(p[1])
					}
				}
			}
		}
		if time.Now().After(deadline) {
			setupFail("no welcome mail with VIN and pin for %s within %v", email, r.mailTO)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (r *recorder) signup(u *user) {
	st, b := r.call("", "", "POST", "/identity/api/auth/signup",
		map[string]any{"name": strings.ToUpper(u.name[:1]) + u.name[1:], "email": u.email, "number": u.number, "password": u.pass})
	if st != 200 {
		setupFail("signup %s: %d %s", u.name, st, strings.TrimSpace(string(b)))
	}
}

func (r *recorder) login(who, email, pass string) {
	st, b := r.call("", "", "POST", "/identity/api/auth/login", map[string]any{"email": email, "password": pass})
	tok := field(b, "token")
	if st != 200 || tok == "" {
		setupFail("login %s: %d %s", who, st, strings.TrimSpace(string(b)))
	}
	r.tokens[who] = tok
}

// addVehicle claims the vehicle announced in the welcome mail and learns its uuid from the vehicle list.
func (r *recorder) addVehicle(u *user) {
	u.vin, u.pin = r.welcomeMail(u.email)
	st, b := r.call("", u.name, "POST", "/identity/api/v2/vehicle/add_vehicle", map[string]any{"vin": u.vin, "pincode": u.pin})
	if st != 200 {
		setupFail("add_vehicle %s: %d %s", u.name, st, strings.TrimSpace(string(b)))
	}
	st, b = r.call("", u.name, "GET", "/identity/api/v2/vehicle/vehicles", nil)
	u.vehicle = field(b, "uuid")
	if st != 200 || u.vehicle == "" {
		setupFail("vehicles %s: %d %s", u.name, st, strings.TrimSpace(string(b)))
	}
}

var names = []string{"alice", "bob", "carol"}

// setup creates the three customers (sign up, log in, claim their vehicle) and logs in the seeded admin.
func (r *recorder) setup() {
	for i, n := range names {
		u := newUser(n, i+1)
		r.users[n] = u
		r.signup(u)
	}
	for _, n := range names {
		r.login(n, r.users[n].email, r.users[n].pass)
	}
	r.login("admin", adminEmail, adminPass)
	for _, n := range names {
		r.addVehicle(r.users[n])
	}
}

// honest: every customer touches only their own objects; the admin does admin work.
func (r *recorder) honest() {
	r.setup()
	for _, n := range names {
		u := r.users[n]
		r.call("", n, "GET", "/identity/api/v2/user/dashboard", nil)
		r.call("", n, "GET", "/identity/api/v2/vehicle/"+u.vehicle+"/location", nil)
		r.call("", n, "GET", "/workshop/api/shop/products", nil)

		_, b := r.call("", n, "POST", "/workshop/api/shop/orders", map[string]any{"product_id": 1, "quantity": 1})
		u.order = field(b, "id")
		r.call("", n, "GET", "/workshop/api/shop/orders/"+u.order, nil)
		r.call("", n, "PUT", "/workshop/api/shop/orders/"+u.order, map[string]any{"quantity": 1})
		r.call("", n, "GET", "/workshop/api/shop/orders/all", nil)

		_, b = r.upload("", n, "/identity/api/v2/user/videos", "file", n+".mp4", []byte("video of "+n))
		u.video = field(b, "id")
		r.call("", n, "GET", "/identity/api/v2/user/videos/"+u.video, nil)
		r.call("", n, "PUT", "/identity/api/v2/user/videos/"+u.video, map[string]any{"videoName": n + "-renamed.mp4"})

		_, b = r.call("", n, "POST", "/community/api/v2/community/posts", map[string]any{"title": "post of " + n, "content": "hello from " + n})
		u.post = field(b, "id")
		r.call("", n, "GET", "/community/api/v2/community/posts/"+u.post, nil)
		r.call("", n, "POST", "/community/api/v2/community/posts/"+u.post+"/comment", map[string]any{"content": "my own post"})
		r.call("", n, "GET", "/community/api/v2/community/posts/recent", nil)

		_, b = r.call("", n, "POST", "/workshop/api/merchant/contact_mechanic", map[string]any{
			"mechanic_code": "TRAC_JHN", "problem_details": "service request of " + n, "vin": u.vin,
			"mechanic_api":             "http://crapi-workshop:8000/workshop/api/mechanic/receive_report",
			"repeat_request_if_failed": false, "number_of_repeats": 1})
		u.report = reportID(field(b, "response_from_mechanic_api", "report_link"))
		r.call("", n, "GET", "/workshop/api/mechanic/mechanic_report?report_id="+u.report, nil)
	}
	r.call("", "admin", "GET", "/workshop/api/management/users/all", nil)
	r.call("", "admin", "DELETE", "/identity/api/v2/admin/videos/"+r.users["carol"].video, nil) // admin work
}

func reportID(link string) string {
	if i := strings.LastIndex(link, "report_id="); i >= 0 {
		return link[i+len("report_id="):]
	}
	return ""
}

// attack: honest + cross-user, anonymous and lower-role attempts. Destructive attacks come last.
func (r *recorder) attack() {
	r.honest()
	a, b := r.users["alice"], r.users["bob"]

	r.call("bola_vehicle", "bob", "GET", "/identity/api/v2/vehicle/"+a.vehicle+"/location", nil)
	r.call("bola_vehicle", "alice", "GET", "/identity/api/v2/vehicle/"+b.vehicle+"/location", nil)
	r.call("vehicle_anon", "", "GET", "/identity/api/v2/vehicle/"+a.vehicle+"/location", nil)

	r.call("bola_order", "bob", "GET", "/workshop/api/shop/orders/"+a.order, nil)
	r.call("bola_order", "alice", "GET", "/workshop/api/shop/orders/"+b.order, nil)
	r.call("order_anon", "", "GET", "/workshop/api/shop/orders/"+a.order, nil)
	r.call("order_put_other", "bob", "PUT", "/workshop/api/shop/orders/"+a.order, map[string]any{"quantity": 2})
	r.call("order_put_other", "alice", "PUT", "/workshop/api/shop/orders/"+b.order, map[string]any{"quantity": 2})
	r.call("order_put_anon", "", "PUT", "/workshop/api/shop/orders/"+a.order, map[string]any{"quantity": 2})

	r.call("video_get_other", "bob", "GET", "/identity/api/v2/user/videos/"+a.video, nil)
	r.call("video_get_other", "alice", "GET", "/identity/api/v2/user/videos/"+b.video, nil)
	r.call("video_get_anon", "", "GET", "/identity/api/v2/user/videos/"+a.video, nil)
	r.call("video_put_other", "bob", "PUT", "/identity/api/v2/user/videos/"+a.video, map[string]any{"videoName": "bob-was-here.mp4"})
	r.call("video_put_other", "alice", "PUT", "/identity/api/v2/user/videos/"+b.video, map[string]any{"videoName": "alice-was-here.mp4"})
	r.call("video_delete_user", "bob", "DELETE", "/identity/api/v2/user/videos/"+a.video, nil)
	r.call("video_delete_user", "alice", "DELETE", "/identity/api/v2/user/videos/"+b.video, nil)
	r.call("admin_video_anon", "", "DELETE", "/identity/api/v2/admin/videos/"+a.video, nil)

	r.call("post_other", "bob", "GET", "/community/api/v2/community/posts/"+a.post, nil)
	r.call("post_other", "alice", "GET", "/community/api/v2/community/posts/"+b.post, nil)
	r.call("post_anon", "", "GET", "/community/api/v2/community/posts/"+a.post, nil)

	r.call("report_other", "bob", "GET", "/workshop/api/mechanic/mechanic_report?report_id="+a.report, nil)
	r.call("report_other", "alice", "GET", "/workshop/api/mechanic/mechanic_report?report_id="+b.report, nil)
	r.call("report_anon", "", "GET", "/workshop/api/mechanic/mechanic_report?report_id="+a.report, nil)
	r.call("users_all_user", "alice", "GET", "/workshop/api/management/users/all", nil)
	r.call("users_all_anon", "", "GET", "/workshop/api/management/users/all", nil)

	// Mass assignment on the caller's own objects (challenges 8 and 10: not cross-user, not authz for authzcov).
	r.call("mass_assign_order", "bob", "PUT", "/workshop/api/shop/orders/"+b.order, map[string]any{"status": "returned"})
	r.call("mass_assign_video", "bob", "PUT", "/identity/api/v2/user/videos/"+b.video, map[string]any{"videoName": "b.mp4", "conversion_params": "-v codec h264"})

	// Destructive: BFLA, any customer can call the admin delete endpoint on another customer's video.
	r.call("bfla_video", "bob", "DELETE", "/identity/api/v2/admin/videos/"+a.video, nil)
	r.call("bfla_video", "alice", "DELETE", "/identity/api/v2/admin/videos/"+b.video, nil)
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
