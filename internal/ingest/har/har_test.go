package har_test

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"

	"authzcov/internal/ingest/har"
	"authzcov/internal/model"
	"authzcov/internal/redact"
	"authzcov/internal/testutil/hartest"
)

func bearerExtract(lookup func(string) []string) model.Credential {
	v := lookup("authorization")
	if len(v) == 0 {
		return model.Credential{Kind: "none"}
	}
	return model.Credential{Kind: "bearer", Fingerprint: redact.Fingerprint(v[0])}
}

func opt() har.Options { return har.Options{Source: "t.har", Extract: bearerExtract} }

func collect(t *testing.T, r io.Reader, st *har.Stats) ([]*model.Exchange, error) {
	t.Helper()
	var out []*model.Exchange
	for x, err := range har.Exchanges(r, opt(), st) {
		if err != nil {
			return out, err
		}
		out = append(out, x)
	}
	return out, nil
}

func ingest(t *testing.T, b []byte) ([]*model.Exchange, *har.Stats) {
	t.Helper()
	st := &har.Stats{}
	xs, err := collect(t, strings.NewReader(string(b)), st)
	if err != nil {
		t.Fatal(err)
	}
	return xs, st
}

func TestParseThreeEntries(t *testing.T) {
	b := hartest.HAR(
		hartest.Entry{Method: "post", URL: "http://localhost:5000/users/v1/login", Status: 200,
			ReqJSON: `{"username":"a","password":"hunter2"}`, RespJSON: `{"status":"success","auth_token":"abc"}`},
		hartest.Entry{Method: "OPTIONS", URL: "http://localhost:5000/x", Status: 200},
		hartest.Entry{Method: "Get", URL: "https://api.example.com:8443/books/v1/b1", Status: 404},
		hartest.Entry{Method: "DELETE", URL: "http://h", Status: 204},
	)
	xs, st := ingest(t, b)
	if len(xs) != 3 {
		t.Fatalf("got %d exchanges", len(xs))
	}
	tests := []struct {
		i                       int
		src, method, host, path string
		status                  int
		reqJSON, respJSON       string
	}{
		{0, "t.har#0", "POST", "localhost:5000", "/users/v1/login", 200,
			`{"password":"[redacted]","username":"a"}`,
			`{"auth_token":"[redacted:` + redact.Fingerprint("abc") + `]","status":"success"}`},
		{1, "t.har#2", "GET", "api.example.com:8443", "/books/v1/b1", 404, "", `null`},
		{2, "t.har#3", "DELETE", "h", "/", 204, "", ""},
	}
	for _, tc := range tests {
		x := xs[tc.i]
		if x.Source != tc.src || x.Method != tc.method || x.Host != tc.host || x.Path != tc.path || x.Status != tc.status {
			t.Errorf("exchange %d = %+v", tc.i, *x)
		}
		if string(x.ReqJSON) != tc.reqJSON {
			t.Errorf("exchange %d ReqJSON = %s, want %s", tc.i, x.ReqJSON, tc.reqJSON)
		}
	}
	if string(xs[0].RespJSON) != tests[0].respJSON {
		t.Errorf("RespJSON = %s", xs[0].RespJSON)
	}
	if st.Entries != 4 || st.Kept != 3 || st.Options != 1 {
		t.Errorf("stats = %+v", *st)
	}
}

func TestPathAndSecretsDropped(t *testing.T) {
	tests := []struct {
		name, url, path, host, secret string
	}{
		{"query", "http://h/a?token=SECRET", "/a", "h", "SECRET"},
		{"fragment", "http://h/a#SECRET", "/a", "h", "SECRET"},
		{"encoded slash", "http://h/a%2Fb/c", "/a%2Fb/c", "h", ""},
		{"userinfo", "http://u:pw@h/x", "/x", "h", "pw"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			xs, _ := ingest(t, hartest.HAR(hartest.Entry{Method: "GET", URL: tc.url, Status: 200}))
			if len(xs) != 1 {
				t.Fatalf("got %d exchanges", len(xs))
			}
			x := xs[0]
			if x.Path != tc.path || x.Host != tc.host {
				t.Errorf("host/path = %q %q", x.Host, x.Path)
			}
			if tc.secret != "" && strings.Contains(fmt.Sprintf("%+v", *x), tc.secret) {
				t.Errorf("secret leaked: %+v", *x)
			}
		})
	}
}

func TestDropReasons(t *testing.T) {
	es := []hartest.Entry{
		{Method: "GET", URL: "http://h/app.JS", Status: 200},
		{Method: "GET", URL: "http://h/a/logo.png", Status: 200},
		{Method: "GET", URL: "http://h/data", Status: 200, RespMIME: "Text/CSS; charset=utf-8", RespJSON: "x"},
		{Method: "GET", URL: "http://h/img", Status: 200, RespMIME: "image/webp", RespJSON: "x"},
		{Method: "GET", URL: "http://h/f", Status: 200, RespMIME: "application/font-woff", RespJSON: "x"},
		{Method: "OPTIONS", URL: "http://h/a", Status: 204},
		{Method: "GET", URL: "http://h/a", Status: 0},
		{Method: "GET", URL: "/relative", Status: 200},
		{Method: "GET", URL: "http://[bad", Status: 200},
		{Method: "GET", URL: "http://h/ok", Status: 200},
		{Method: "GET", URL: "http://h/v1.2/ok", Status: 200},
	}
	xs, st := ingest(t, hartest.HAR(es...))
	want := har.Stats{Entries: 11, Kept: 2, Static: 5, Options: 1, Status0: 1, BadURL: 2}
	if *st != want {
		t.Errorf("stats = %+v, want %+v", *st, want)
	}
	if len(xs) != 2 || xs[0].Source != "t.har#9" {
		t.Errorf("exchanges = %v", xs)
	}
}

func TestTolerantStructure(t *testing.T) {
	e := `{"request":{"method":"GET","url":"http://h/a","headers":[]},"response":{"status":200,"content":{}}}`
	tests := []struct {
		name, doc string
		want      int
		wantErr   bool
	}{
		{"keys around entries", `{"x":[1,{"a":[]}],"log":{"pages":[{"id":1}],"entries":[` + e + `],"comment":{"z":1}},"y":null}`, 1, false},
		{"no entries", `{"log":{"version":"1.2"}}`, 0, false},
		{"no log", `{"other":1}`, 0, false},
		{"log not object", `{"log":[1,[2]],"z":1}`, 0, false},
		{"entries null", `{"log":{"entries":null}}`, 0, false},
		{"unknown fields in entry", `{"log":{"entries":[{"foo":1,"request":{"method":"GET","url":"http://h/","bar":{}},"response":{"status":200}}]}}`, 1, false},
		{"top-level array", `[1,2]`, 0, true},
		{"empty", ``, 0, true},
		{"scalar", `3`, 0, true},
		{"wrong entry type", `{"log":{"entries":[1]}}`, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			xs, err := collect(t, strings.NewReader(tc.doc), nil)
			if (err != nil) != tc.wantErr || len(xs) != tc.want {
				t.Errorf("got %d exchanges, err %v", len(xs), err)
			}
		})
	}
}

func TestTruncated(t *testing.T) {
	b := string(hartest.HAR(
		hartest.Entry{Method: "GET", URL: "http://h/a", Status: 200},
		hartest.Entry{Method: "GET", URL: "http://h/b", Status: 200},
	))
	cut := b[:len(b)-60]
	xs, err := collect(t, strings.NewReader(cut), nil)
	if err == nil {
		t.Fatal("want error")
	}
	if len(xs) != 1 {
		t.Errorf("yielded %d before error, want 1", len(xs))
	}
	if msg := err.Error(); !strings.Contains(msg, "t.har") || !strings.Contains(msg, "entry 1") {
		t.Errorf("error = %q", msg)
	}
}

type countReader struct {
	r io.Reader
	n int
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestStreaming(t *testing.T) {
	es := make([]hartest.Entry, 2000)
	for i := range es {
		es[i] = hartest.Entry{Method: "GET", URL: fmt.Sprintf("http://h/items/%d", i), Status: 200, RespJSON: `{"k":"vvvvvvvvvvvvvvvvvvvvvvvv"}`}
	}
	b := hartest.HAR(es...)
	cr := &countReader{r: strings.NewReader(string(b))}
	for x, err := range har.Exchanges(cr, opt(), nil) {
		if err != nil || x == nil {
			t.Fatalf("x=%v err=%v", x, err)
		}
		if cr.n >= len(b) {
			t.Fatalf("read %d of %d bytes before first exchange", cr.n, len(b))
		}
		break
	}
}

func TestBodies(t *testing.T) {
	big := `{"a":"` + strings.Repeat("x", har.MaxBody) + `"}`
	b64 := base64.StdEncoding.EncodeToString([]byte(`{"password":"p4ss"}`))
	bigB64 := base64.StdEncoding.EncodeToString([]byte(big))
	tests := []struct {
		name         string
		e            hartest.Entry
		wantReq      bool
		wantResp     bool
		wantTooLarge int
	}{
		{"big req", hartest.Entry{Method: "POST", URL: "http://h/a", Status: 200, ReqJSON: big}, false, false, 1},
		{"big resp", hartest.Entry{Method: "GET", URL: "http://h/a", Status: 200, RespJSON: big}, false, false, 1},
		{"big base64 resp", hartest.Entry{Method: "GET", URL: "http://h/a", Status: 200, RespJSON: bigB64}, false, false, 1},
		{"non-json mime", hartest.Entry{Method: "GET", URL: "http://h/a", Status: 200, RespMIME: "text/html", RespJSON: `{"a":1}`}, false, false, 0},
		{"invalid json", hartest.Entry{Method: "POST", URL: "http://h/a", Status: 200, ReqJSON: `{nope`, RespJSON: `[1]`}, false, true, 0},
		{"json+ mime", hartest.Entry{Method: "GET", URL: "http://h/a", Status: 200, RespMIME: "Application/VND.API+JSON", RespJSON: `{"a":1}`}, false, true, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			xs, st := ingest(t, hartest.HAR(tc.e))
			if len(xs) != 1 {
				t.Fatalf("got %d exchanges", len(xs))
			}
			if (xs[0].ReqJSON != nil) != tc.wantReq || (xs[0].RespJSON != nil) != tc.wantResp || st.BodyTooLarge != tc.wantTooLarge {
				t.Errorf("req=%v resp=%v tooLarge=%d", xs[0].ReqJSON != nil, xs[0].RespJSON != nil, st.BodyTooLarge)
			}
		})
	}
	t.Run("base64 decoded", func(t *testing.T) {
		doc := fmt.Sprintf(`{"log":{"entries":[{"request":{"method":"GET","url":"http://h/a"},"response":{"status":200,"content":{"mimeType":"application/json","encoding":"base64","text":%q}}}]}}`, b64)
		xs, err := collect(t, strings.NewReader(doc), nil)
		if err != nil || len(xs) != 1 {
			t.Fatalf("%v %d", err, len(xs))
		}
		if want := `{"password":"[redacted]"}`; string(xs[0].RespJSON) != want {
			t.Errorf("RespJSON = %s", xs[0].RespJSON)
		}
		bad := strings.Replace(doc, b64, "!!notbase64", 1)
		xs, _ = collect(t, strings.NewReader(bad), nil)
		if len(xs) != 1 || xs[0].RespJSON != nil {
			t.Errorf("bad base64 should give nil RespJSON")
		}
	})
}

func TestExtractLookupAndNil(t *testing.T) {
	var got, none []string
	o := har.Options{Source: "t", Extract: func(l func(string) []string) model.Credential {
		got = l("authorization")
		none = l("x-missing")
		return model.Credential{Kind: "k"}
	}}
	e := hartest.Entry{Method: "GET", URL: "http://h/a", Status: 200, Headers: hartest.Bearer("tok")}
	for _, err := range har.Exchanges(strings.NewReader(string(hartest.HAR(e))), o, nil) {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(got) != 1 || got[0] != "Bearer tok" || len(none) != 0 {
		t.Errorf("lookup = %v, %v", got, none)
	}

	n := 0
	for x, err := range har.Exchanges(strings.NewReader("{}"), har.Options{Source: "t"}, nil) {
		n++
		if x != nil || err == nil {
			t.Errorf("x=%v err=%v", x, err)
		}
	}
	if n != 1 {
		t.Errorf("yielded %d times", n)
	}
}

func TestNoRawSecret(t *testing.T) {
	const tok, cookie, key, pw, rt = "TOKENVALUE123", "COOKIEVALUE456", "APIKEYVALUE789", "PASSWORDVALUE0", "RESPTOKENVALUE1"
	e := hartest.Entry{
		Method: "POST", URL: "http://h/login?k=" + key, Status: 200,
		Headers: map[string]string{"Authorization": "Bearer " + tok, "Cookie": "sid=" + cookie, "X-API-Key": key},
		ReqJSON: `{"password":"` + pw + `"}`, RespJSON: `{"auth_token":"` + rt + `"}`,
	}
	xs, _ := ingest(t, hartest.HAR(e))
	x := xs[0]
	out := fmt.Sprintf("%+v", *x) + string(x.ReqJSON) + string(x.RespJSON)
	for _, s := range []string{tok, cookie, key, pw, rt} {
		if strings.Contains(out, s) {
			t.Errorf("raw secret %q leaked: %s", s, out)
		}
	}
	if x.Cred.Fingerprint != redact.Fingerprint("Bearer "+tok) {
		t.Errorf("cred = %+v", x.Cred)
	}
}

func FuzzExchanges(f *testing.F) {
	f.Add(hartest.HAR(hartest.Entry{Method: "GET", URL: "http://h/a", Status: 200, RespJSON: `{"a":1}`}))
	f.Add([]byte(`{"log":{"entries":[{}]}}`))
	f.Add([]byte(`[`))
	f.Fuzz(func(_ *testing.T, b []byte) {
		for x, err := range har.Exchanges(strings.NewReader(string(b)), opt(), &har.Stats{}) {
			_, _ = x, err
		}
	})
}
