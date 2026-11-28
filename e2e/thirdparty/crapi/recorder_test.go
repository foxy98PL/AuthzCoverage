package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCrapi answers the calls of the recorder. The first failLogins logins fail (like a service that is not
// settled yet); mailAfter is the number of MailHog polls that return an empty list before the welcome mail appears.
type fakeCrapi struct {
	web, mail                  *httptest.Server
	failLogins, mailAfter      int32
	logins, polls, signups, up atomic.Int32
}

func newFake(t *testing.T, failLogins, mailAfter int32) *fakeCrapi {
	t.Helper()
	f := &fakeCrapi{failLogins: failLogins, mailAfter: mailAfter}
	f.web = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/auth/signup"):
			f.signups.Add(1)
			io.WriteString(w, `{"message":"ok","status":200}`)
		case strings.HasSuffix(p, "/auth/login"):
			if f.logins.Add(1) <= f.failLogins {
				w.WriteHeader(500)
				io.WriteString(w, `{"message":"boom"}`)
				return
			}
			io.WriteString(w, `{"token":"x.y.z","type":"Bearer"}`)
		case strings.HasSuffix(p, "/vehicle/vehicles"):
			io.WriteString(w, `[{"uuid":"00000000-0000-0000-0000-000000000001"}]`)
		case strings.HasSuffix(p, "/shop/orders"), strings.HasSuffix(p, "/user/videos"), strings.HasSuffix(p, "/community/posts"):
			io.WriteString(w, `{"id":7}`)
		case strings.HasSuffix(p, "/contact_mechanic"):
			io.WriteString(w, `{"response_from_mechanic_api":{"report_link":"http://x/mechanic_report?report_id=9"},"status":200}`)
		default:
			io.WriteString(w, `{}`)
		}
	}))
	f.mail = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if f.polls.Add(1) <= f.mailAfter {
			io.WriteString(w, `{"items":[]}`)
			return
		}
		// quoted-printable body as MailHog stores it ("=3D" for "=", soft line break)
		io.WriteString(w, `{"items":[{"Raw":{"Data":"Subject: Welcome\r\n\r\n<b>VIN: </font><font color=3D'#0000ff'>A7544235W8W93020E</font></b> and <b>Pincode: <font color=3D'#0000ff'>3393</font></b>"}}]}`)
	}))
	t.Cleanup(func() { f.web.Close(); f.mail.Close() })
	return f
}

func (f *fakeCrapi) open() (stack, func()) {
	f.up.Add(1)
	return stack{web: f.web.URL, mail: f.mail.URL}, func() {}
}

func TestWelcomeMailParsesVINAndPin(t *testing.T) {
	f := newFake(t, 0, 2) // two empty polls before the mail arrives
	r := newRecorder(stack{web: f.web.URL, mail: f.mail.URL})
	vin, pin := r.welcomeMail("alice@example.test")
	if vin != "A7544235W8W93020E" || pin != "3393" {
		t.Errorf("got vin=%q pin=%q", vin, pin)
	}
	if got := f.polls.Load(); got != 3 {
		t.Errorf("polled %d times, want 3", got)
	}
}

func TestRecordSessionRetriesSetupError(t *testing.T) {
	clean := newFake(t, 0, 0)
	r, _ := recordSession(clean.open, "honest", 1)
	want := len(r.entries)
	if want == 0 || clean.up.Load() != 1 {
		t.Fatalf("clean session: %d entries, %d stacks", want, clean.up.Load())
	}

	flaky := newFake(t, 2, 0) // the first two logins fail
	r, _ = recordSession(flaky.open, "honest", 5)
	if got := flaky.up.Load(); got != 3 {
		t.Errorf("%d stacks started, want 3 (two failed attempts, then a clean one)", got)
	}
	if len(r.entries) != want {
		t.Errorf("HAR has %d entries, want %d: failed attempts must be discarded", len(r.entries), want)
	}
	if !strings.HasSuffix(r.entries[0].Request.URL, "/auth/signup") {
		t.Errorf("first entry %s, want the clean attempt's signup", r.entries[0].Request.URL)
	}
}

func TestRecordSessionMissingMailIsSetupError(t *testing.T) {
	f := newFake(t, 0, 1<<30) // the mail never arrives
	r := newRecorder(stack{web: f.web.URL, mail: f.mail.URL})
	r.mailTO = 600 * time.Millisecond
	var last setupError
	if tryRecord(r, "honest", &last) {
		t.Fatal("session succeeded without a welcome mail")
	}
	if !strings.Contains(string(last), "no welcome mail") {
		t.Errorf("setup error %q does not mention the mail", last)
	}
}

func TestAttackSessionRecordsProbes(t *testing.T) {
	f := newFake(t, 0, 0)
	r, _ := recordSession(f.open, "attack", 1)
	tags := map[string]bool{}
	for _, s := range r.steps {
		if s.Tag != "" {
			tags[s.Tag] = true
		}
	}
	for _, want := range []string{"bola_vehicle", "bola_order", "order_anon", "bfla_video", "report_other", "users_all_user"} {
		if !tags[want] {
			t.Errorf("attack suite has no step tagged %s", want)
		}
	}
}

func TestTryRecordRepanicsOtherErrors(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("non-setup panic was swallowed")
		}
	}()
	var last setupError
	tryRecord(&recorder{}, "honest", &last) // nil maps/client: a plain runtime panic, not a setupError
}

func TestGroundTruthParses(t *testing.T) {
	gt, err := loadGroundTruth("groundtruth.yaml")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, g := range gt {
		if g.ID == "" || g.Category == "" || g.Source == "" || g.Expect == "" {
			t.Errorf("incomplete ground-truth item %+v", g)
		}
		if seen[g.ID] {
			t.Errorf("duplicate id %s", g.ID)
		}
		seen[g.ID] = true
	}
	if len(gt) < 20 {
		t.Errorf("only %d ground-truth items", len(gt))
	}
}

func TestStablePath(t *testing.T) {
	for in, want := range map[string]string{
		"/identity/api/v2/vehicle/0184f8d8-90a5-49b0-9270-86a8dbd18fbd/location": "/identity/api/v2/vehicle/{uuid}/location",
		"/community/api/v2/community/posts/BxzjTcG5ecuNaekq7dWe9L/comment":       "/community/api/v2/community/posts/{id}/comment",
		"/community/api/v2/community/posts/recent":                               "/community/api/v2/community/posts/recent",
		"/workshop/api/shop/orders/6":                                            "/workshop/api/shop/orders/6",
	} {
		if got := stablePath(in); got != want {
			t.Errorf("stablePath(%q) = %q, want %q", in, got, want)
		}
	}
}
