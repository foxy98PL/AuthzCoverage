package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"authzcov/internal/testkey"
)

var testRunKey = bytes.Repeat([]byte{7}, 32)

func newPseudo(t testing.TB, keep ...string) *Pseudonymizer {
	t.Helper()
	p, err := NewPseudonymizer(PseudoOptions{Key: testRunKey, KeepClaims: keep})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func signRaw(t testing.TB, claims jwt.MapClaims, key string) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func harOf(entries ...map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"log": map[string]any{
		"version": "1.2", "creator": map[string]any{"name": "x", "version": "1"}, "entries": entries}})
	return b
}

func hdrs(h ...string) []any {
	var out []any
	for i := 0; i+1 < len(h); i += 2 {
		out = append(out, map[string]any{"name": h[i], "value": h[i+1]})
	}
	return out
}

func mkEntry(method, url string, reqH []any, reqBody string, status int, respH []any, respBody string) map[string]any {
	req := map[string]any{"method": method, "url": url, "httpVersion": "HTTP/1.1", "headers": reqH,
		"queryString": []any{}, "cookies": []any{map[string]any{"name": "sid", "value": "RAWCOOKIEVALUE"}}, "headersSize": -1, "bodySize": -1}
	if reqBody != "" {
		req["postData"] = map[string]any{"mimeType": "application/json", "text": reqBody}
	}
	resp := map[string]any{"status": status, "statusText": "OK", "httpVersion": "HTTP/1.1", "headers": respH,
		"cookies": []any{}, "content": map[string]any{"size": len(respBody), "mimeType": "application/json", "text": respBody},
		"redirectURL": "", "headersSize": -1, "bodySize": -1}
	return map[string]any{"startedDateTime": "2026-01-01T00:00:00.000Z", "time": 5, "request": req, "response": resp,
		"serverIPAddress": "10.9.8.7", "connection": "4242", "_initiator": map[string]any{"url": "http://secret.corp.example/x"},
		"timings": map[string]any{"send": 1, "wait": 2, "receive": 3, "blocked": 9, "dns": 8}}
}

func pseudoize(t testing.TB, p *Pseudonymizer, in []byte) (string, map[string]any) {
	t.Helper()
	var out bytes.Buffer
	if err := p.HAR(bytes.NewReader(in), &out); err != nil {
		t.Fatalf("HAR: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	return out.String(), doc
}

func entriesOf(doc map[string]any) []map[string]any {
	var out []map[string]any
	for _, e := range doc["log"].(map[string]any)["entries"].([]any) {
		out = append(out, e.(map[string]any))
	}
	return out
}

func reqHeader(e map[string]any, name string) string {
	for _, h := range e["request"].(map[string]any)["headers"].([]any) {
		m := h.(map[string]any)
		if strings.EqualFold(m["name"].(string), name) {
			return m["value"].(string)
		}
	}
	return ""
}

func verifyTestJWT(t *testing.T, tok string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, err := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}), jwt.WithoutClaimsValidation()).
		ParseWithClaims(tok, claims, func(*jwt.Token) (any, error) { return testkey.Key, nil })
	if err != nil {
		t.Fatalf("token %q not signed with the test key: %v", tok, err)
	}
	return claims
}

// Rule 1.
func TestPseudoJWTResignKeepsOnlyListedClaims(t *testing.T) {
	raw := signRaw(t, jwt.MapClaims{"sub": "alice", "org_id": "OrgA", "email": "alice@corp.example",
		"exp": 1999999999, "iat": 1700000000, "aud": "prod-api", "iss": "https://idp.corp.example"}, "REAL-PROD-SIGNING-SECRET")
	in := harOf(mkEntry("GET", "http://api.corp.example/x", hdrs("Authorization", "Bearer "+raw), "", 200, nil, ""))

	for _, tc := range []struct {
		keep []string
		want map[string]any
	}{
		{nil, map[string]any{"sub": "alice", "iss": testkey.Issuer}},
		{[]string{"sub", "org_id"}, map[string]any{"sub": "alice", "org_id": "OrgA", "iss": testkey.Issuer}},
		{[]string{"org_id"}, map[string]any{"org_id": "OrgA", "iss": testkey.Issuer}},
	} {
		_, doc := pseudoize(t, newPseudo(t, tc.keep...), in)
		h := reqHeader(entriesOf(doc)[0], "Authorization")
		tok, ok := strings.CutPrefix(h, "Bearer ")
		if !ok || !LooksLikeJWT(tok) {
			t.Fatalf("keep=%v: Authorization = %q", tc.keep, h)
		}
		got := verifyTestJWT(t, tok)
		if len(got) != len(tc.want) {
			t.Errorf("keep=%v: claims = %v, want %v", tc.keep, got, tc.want)
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("keep=%v: claim %s = %v, want %v", tc.keep, k, got[k], v)
			}
		}
	}
}

func TestPseudoJWTStableAndDistinct(t *testing.T) {
	a := signRaw(t, jwt.MapClaims{"sub": "alice", "exp": 1}, "k1")
	a2 := signRaw(t, jwt.MapClaims{"sub": "alice", "exp": 2}, "k1") // different token, same subject
	b := signRaw(t, jwt.MapClaims{"sub": "bob"}, "k1")
	in := harOf(
		mkEntry("GET", "http://h/x", hdrs("Authorization", "Bearer "+a), "", 200, nil, ""),
		mkEntry("GET", "http://h/y", hdrs("Authorization", "Bearer "+a), "", 200, nil, ""),
		mkEntry("GET", "http://h/z", hdrs("Authorization", "Bearer "+b), "", 200, nil, ""),
		mkEntry("GET", "http://h/w", hdrs("Authorization", "Bearer "+a2), "", 200, nil, ""),
	)
	p := newPseudo(t)
	_, doc := pseudoize(t, p, in)
	es := entriesOf(doc)
	h := func(i int) string { return reqHeader(es[i], "Authorization") }
	if h(0) != h(1) {
		t.Error("same input token must map to the same output token")
	}
	if h(0) == h(2) {
		t.Error("different subjects collapsed")
	}
	if verifyTestJWT(t, strings.TrimPrefix(h(3), "Bearer "))["sub"] != "alice" {
		t.Error("sub lost")
	}
	if st := p.Stats(); st.TokensResigned != 3 || st.Entries != 4 {
		t.Errorf("stats = %+v", st)
	}
}

func TestPseudoJWTShapedEverywhere(t *testing.T) {
	jwtRaw := signRaw(t, jwt.MapClaims{"sub": "carol", "email": "c@corp.example"}, "k")
	e := mkEntry("GET", "http://h/x?t="+jwtRaw, hdrs("User-Agent", "pre "+jwtRaw+" post", "Cookie", "sid="+jwtRaw+"; other=plain"),
		`{"note":"`+jwtRaw+`","nested":{"list":["`+jwtRaw+`"]}}`, 200, nil, `{"echo":"`+jwtRaw+`"}`)
	out, doc := pseudoize(t, newPseudo(t), harOf(e))
	if strings.Contains(out, jwtRaw) || strings.Contains(out, "c@corp.example") {
		t.Fatalf("raw JWT survived:\n%s", out)
	}
	if !strings.Contains(reqHeader(entriesOf(doc)[0], "Cookie"), "other=tok_") {
		t.Errorf("cookie = %q", reqHeader(entriesOf(doc)[0], "Cookie"))
	}
	re := regexp.MustCompile(`eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+`)
	toks := re.FindAllString(out, -1)
	if len(toks) < 5 {
		t.Fatalf("expected re-signed tokens in header, cookie, body, response; got %d", len(toks))
	}
	for _, tok := range toks {
		if c := verifyTestJWT(t, tok); c["iss"] != testkey.Issuer || c["sub"] != "carol" || len(c) != 2 {
			t.Errorf("claims = %v", c)
		}
	}
}

func TestPseudoUndecodableJWTIsOpaque(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString
	bad := b64([]byte(`{"alg":"HS256"}`)) + "." + b64([]byte(`{"notjson`)) + "." + b64([]byte("sig")) // payload is not valid JSON
	in := harOf(mkEntry("GET", "http://h/x", hdrs("Authorization", "Bearer "+bad), "", 200, nil, ""))
	out, doc := pseudoize(t, newPseudo(t), in)
	if strings.Contains(out, bad) {
		t.Fatal("undecodable token survived")
	}
	if !regexp.MustCompile(`^Bearer tok_[0-9a-f]{8}$`).MatchString(reqHeader(entriesOf(doc)[0], "Authorization")) {
		t.Errorf("got %q", reqHeader(entriesOf(doc)[0], "Authorization"))
	}
}

// Rule 2.
func TestPseudoOpaqueCredentials(t *testing.T) {
	in := harOf(
		mkEntry("GET", "http://h/a", hdrs("Authorization", "Bearer opaque-bearer-AAAA", "X-API-Key", "key-BBBB", "Cookie", "session=sess-CCCC; theme=dark"), "", 200,
			hdrs("Set-Cookie", "session=sess-DDDD; Path=/; Domain=corp.example; HttpOnly"), ""),
		mkEntry("GET", "http://h/b", hdrs("Authorization", "Bearer opaque-bearer-AAAA", "Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("zed:hunter2"))), "", 200, nil, ""),
		mkEntry("GET", "http://h/c", hdrs("Authorization", "Bearer opaque-bearer-EEEE"), "", 200, nil, ""),
	)
	p := newPseudo(t)
	out, doc := pseudoize(t, p, in)
	for _, s := range []string{"opaque-bearer-AAAA", "opaque-bearer-EEEE", "key-BBBB", "sess-CCCC", "sess-DDDD", "hunter2", "corp.example", "RAWCOOKIEVALUE", "zed:"} {
		if strings.Contains(out, s) {
			t.Errorf("%q survived", s)
		}
	}
	es := entriesOf(doc)
	tokRe := regexp.MustCompile(`^Bearer tok_[0-9a-f]{8}$`)
	a0, a1, a2 := reqHeader(es[0], "Authorization"), reqHeader(es[1], "Authorization"), reqHeader(es[2], "Authorization")
	if !tokRe.MatchString(a0) || a0 != a1 || a0 == a2 {
		t.Errorf("bearer mapping: %q %q %q", a0, a1, a2)
	}
	if !regexp.MustCompile(`^tok_[0-9a-f]{8}$`).MatchString(reqHeader(es[0], "X-API-Key")) {
		t.Errorf("api key = %q", reqHeader(es[0], "X-API-Key"))
	}
	if c := reqHeader(es[0], "Cookie"); !regexp.MustCompile(`^session=tok_[0-9a-f]{8}; theme=tok_[0-9a-f]{8}$`).MatchString(c) {
		t.Errorf("cookie = %q", c)
	}
	pa := reqHeader(es[1], "Proxy-Authorization")
	b64, ok := strings.CutPrefix(pa, "Basic ")
	raw, err := base64.StdEncoding.DecodeString(b64)
	if !ok || err != nil || !regexp.MustCompile(`^user_[0-9a-f]{8}:$`).Match(raw) {
		t.Errorf("basic = %q (%q)", pa, raw)
	}
	// Different run key => different replacement; the key is the only input.
	p2, _ := NewPseudonymizer(PseudoOptions{Key: bytes.Repeat([]byte{9}, 32)})
	_, doc2 := pseudoize(t, p2, in)
	if reqHeader(entriesOf(doc2)[0], "Authorization") == a0 {
		t.Error("run key does not influence tok_ hash")
	}
	// HMAC-SHA256(key, raw)[:8], not a bare hash.
	if want := hmacHex(testRunKey, "opaque-bearer-AAAA")[:8]; a0 != "Bearer tok_"+want {
		t.Errorf("a0 = %q, want tok_%s", a0, want)
	}
}

func TestNewPseudonymizerKeyLength(t *testing.T) {
	if _, err := NewPseudonymizer(PseudoOptions{Key: make([]byte, 31)}); err == nil {
		t.Error("31-byte key accepted")
	}
	if _, err := NewPseudonymizer(PseudoOptions{}); err == nil {
		t.Error("nil key accepted")
	}
	if _, err := NewPseudonymizer(PseudoOptions{Key: make([]byte, 32), KeepClaims: []string{""}}); err == nil {
		t.Error("empty claim name accepted")
	}
}

// Rule 3.
func TestPseudoBodiesAndEmails(t *testing.T) {
	in := harOf(
		mkEntry("POST", "http://h/users/ann@corp.example/x", hdrs("User-Agent", "boss@corp.example", "Content-Type", "application/json"),
			`{"username":"ann","password":"hunter2","email":"Ann@Corp.Example","api_key":"AKIAXXXX","nested":[{"client_secret":"zzz-secret","n":5}],"count":3}`,
			200, nil, `{"token":"opaque-resp-token","note":"mail ann@corp.example now","id":"o-1","refresh_token":12345}`),
	)
	p := newPseudo(t)
	out, doc := pseudoize(t, p, in)
	for _, s := range []string{"hunter2", "corp.example", "AKIAXXXX", "zzz-secret", "opaque-resp-token", "12345"} {
		if strings.Contains(out, s) {
			t.Errorf("%q survived:\n%s", s, out)
		}
	}
	e := entriesOf(doc)[0]
	reqBody := e["request"].(map[string]any)["postData"].(map[string]any)["text"].(string)
	var rb map[string]any
	if err := json.Unmarshal([]byte(reqBody), &rb); err != nil {
		t.Fatal(err)
	}
	if rb["username"] != "ann" || rb["count"] != json.Number("3") && rb["count"] != float64(3) {
		t.Errorf("benign fields changed: %v", rb)
	}
	if rb["password"] != "[redacted]" {
		t.Errorf("password = %v", rb["password"])
	}
	if !regexp.MustCompile(`^user_[0-9a-f]{8}@example\.test$`).MatchString(rb["email"].(string)) {
		t.Errorf("email = %v", rb["email"])
	}
	// Email case-insensitive: the same mailbox maps to the same pseudonym.
	respBody := e["response"].(map[string]any)["content"].(map[string]any)["text"].(string)
	if !regexp.MustCompile(`mail user_[0-9a-f]{8}@example\.test now`).MatchString(respBody) {
		t.Errorf("resp = %s", respBody)
	}
	if !regexp.MustCompile(`user_[0-9a-f]{8}@example\.test`).MatchString(e["request"].(map[string]any)["url"].(string)) {
		t.Errorf("url = %v", e["request"].(map[string]any)["url"])
	}
	if got := reqHeader(e, "User-Agent"); !strings.HasSuffix(got, "@example.test") {
		t.Errorf("User-Agent = %q", got)
	}
	if p.Stats().BodyFields < 4 {
		t.Errorf("body fields = %d", p.Stats().BodyFields)
	}
}

func TestPseudoFormBodies(t *testing.T) {
	e := mkEntry("POST", "http://h/login", nil, "", 200, nil, "")
	e["request"].(map[string]any)["postData"] = map[string]any{"mimeType": "application/x-www-form-urlencoded; charset=utf-8",
		"text": "username=ann&password=hunter2&client_secret=cs-1234&mail=ann%40corp.example&plain=ok"}
	out, doc := pseudoize(t, newPseudo(t), harOf(e))
	for _, s := range []string{"hunter2", "cs-1234", "corp.example", "corp%2Eexample"} {
		if strings.Contains(out, s) {
			t.Errorf("%q survived", s)
		}
	}
	txt := entriesOf(doc)[0]["request"].(map[string]any)["postData"].(map[string]any)["text"].(string)
	if !strings.Contains(txt, "username=ann") || !strings.Contains(txt, "plain=ok") {
		t.Errorf("benign form fields lost: %s", txt)
	}
}

func TestPseudoNonJSONBodyDropped(t *testing.T) {
	e := mkEntry("GET", "http://h/page", nil, "", 200, nil, "")
	e["response"].(map[string]any)["content"] = map[string]any{"size": 20, "mimeType": "text/html", "text": "<p>token=SECRETHTML</p>"}
	out, _ := pseudoize(t, newPseudo(t), harOf(e))
	if strings.Contains(out, "SECRETHTML") {
		t.Error("non-JSON body kept")
	}
}

func TestPseudoOversizeBodyDropped(t *testing.T) {
	big := `{"a":"` + strings.Repeat("x", 70<<10) + `"}`
	out, _ := pseudoize(t, newPseudo(t), harOf(mkEntry("GET", "http://h/x", nil, "", 200, nil, big)))
	if strings.Contains(out, "xxxxxxxxxxxx") {
		t.Error("oversize body kept")
	}
}

func TestPseudoBase64Body(t *testing.T) {
	e := mkEntry("GET", "http://h/x", nil, "", 200, nil, "")
	e["response"].(map[string]any)["content"] = map[string]any{"size": 1, "mimeType": "application/json", "encoding": "base64",
		"text": base64.StdEncoding.EncodeToString([]byte(`{"password":"b64-secret","id":"k1"}`))}
	out, doc := pseudoize(t, newPseudo(t), harOf(e))
	if strings.Contains(out, "b64-secret") || strings.Contains(out, "YjY0") {
		t.Errorf("base64 body leaked: %s", out)
	}
	txt := entriesOf(doc)[0]["response"].(map[string]any)["content"].(map[string]any)["text"].(string)
	if !strings.Contains(txt, `"id":"k1"`) {
		t.Errorf("body = %s", txt)
	}
}

// Rule 4.
func TestPseudoHosts(t *testing.T) {
	in := harOf(
		mkEntry("GET", "https://api.corp.example:8443/a", hdrs("Host", "api.corp.example:8443", "Origin", "https://app.corp.example", "Referer", "https://app.corp.example/page?q=1#frag"),
			"", 302, hdrs("Location", "https://api.corp.example:8443/b", "Access-Control-Allow-Origin", "https://app.corp.example"),
			`{"self":"https://api.corp.example:8443/orders/9","other":"see http://evil.corp.example/x?y=1 ok"}`),
		mkEntry("GET", "http://API.corp.example:8443/c", nil, "", 200, hdrs("Location", "/relative?x=SECRETQ"), ""),
		mkEntry("GET", "http://third.example/d", nil, "", 200, nil, ""),
	)
	p := newPseudo(t)
	out, doc := pseudoize(t, p, in)
	if strings.Contains(out, "corp.example") || strings.Contains(out, "third.example") || strings.Contains(out, "8443") || strings.Contains(out, "SECRETQ") {
		t.Fatalf("host leaked:\n%s", out)
	}
	es := entriesOf(doc)
	u0 := es[0]["request"].(map[string]any)["url"]
	if u0 != "https://h1.test/a" {
		t.Errorf("url0 = %v", u0)
	}
	if es[1]["request"].(map[string]any)["url"] != "http://h1.test/c" {
		t.Errorf("host mapping not case-insensitive/stable: %v", es[1]["request"].(map[string]any)["url"])
	}
	if es[2]["request"].(map[string]any)["url"] != "http://h4.test/d" {
		t.Errorf("url2 = %v", es[2]["request"].(map[string]any)["url"])
	}
	if reqHeader(es[0], "Host") != "h1.test" || reqHeader(es[0], "Origin") != "https://h2.test" {
		t.Errorf("headers: %q %q", reqHeader(es[0], "Host"), reqHeader(es[0], "Origin"))
	}
	if ref := reqHeader(es[0], "Referer"); ref != "https://h2.test/page?q=x" {
		t.Errorf("referer = %q", ref)
	}
	body := es[0]["response"].(map[string]any)["content"].(map[string]any)["text"].(string)
	if !strings.Contains(body, "https://h1.test/orders/9") || !strings.Contains(body, "http://h3.test/x?y=x") {
		t.Errorf("body = %s", body)
	}
	if p.Stats().HostsMapped != 4 {
		t.Errorf("hosts = %d", p.Stats().HostsMapped)
	}
}

// Rules 5, 7.
func TestPseudoQueryAndPath(t *testing.T) {
	e := mkEntry("GET", "http://h/orders/o-17/items/42?apikey=QSECRET&page=2&flag#frag", nil, "", 200, nil, "")
	e["request"].(map[string]any)["queryString"] = []any{map[string]any{"name": "apikey", "value": "QSECRET"}}
	jwtRaw := signRaw(t, jwt.MapClaims{"sub": "dan", "x": "PAYLOADSECRET"}, "k")
	e2 := mkEntry("GET", "http://h/tok/"+jwtRaw, nil, "", 200, nil, "")
	out, doc := pseudoize(t, newPseudo(t), harOf(e, e2))
	if strings.Contains(out, "QSECRET") || strings.Contains(out, "frag") || strings.Contains(out, jwtRaw) {
		t.Fatalf("leak:\n%s", out)
	}
	es := entriesOf(doc)
	if got := es[0]["request"].(map[string]any)["url"]; got != "http://h1.test/orders/o-17/items/42?apikey=x&page=x&flag" {
		t.Errorf("url = %v", got)
	}
	qs := es[0]["request"].(map[string]any)["queryString"].([]any)
	if len(qs) != 3 || qs[0].(map[string]any)["name"] != "apikey" || qs[0].(map[string]any)["value"] != "x" {
		t.Errorf("queryString = %v", qs)
	}
	if u := es[1]["request"].(map[string]any)["url"].(string); !strings.HasPrefix(u, "http://h1.test/tok/eyJ") {
		t.Errorf("jwt path segment url = %s", u)
	}
}

// Rule 6.
func TestPseudoDrops(t *testing.T) {
	e := mkEntry("GET", "http://h/x", hdrs("Connection", "keep-alive", "X-Forwarded-For", "203.0.113.9", "Authorization", "Bearer zzz", "X-CSRF-Token", "csrf-val", "Accept", "application/json"), "", 200,
		hdrs("Set-Cookie", "a=b-secret; Secure", "Server", "nginx", "Connection", "close"), `{"ok":true}`)
	out, doc := pseudoize(t, newPseudo(t), harOf(e))
	for _, s := range []string{"RAWCOOKIEVALUE", "10.9.8.7", "serverIPAddress", "_initiator", "secret.corp.example", "203.0.113.9", "b-secret", "csrf-val", "keep-alive", "\"dns\"", "\"blocked\""} {
		if strings.Contains(out, s) {
			t.Errorf("%q survived", s)
		}
	}
	en := entriesOf(doc)[0]
	for _, side := range []string{"request", "response"} {
		if c := en[side].(map[string]any)["cookies"].([]any); len(c) != 0 {
			t.Errorf("%s cookies = %v", side, c)
		}
	}
	if reqHeader(en, "Accept") != "application/json" {
		t.Error("benign header lost")
	}
	for _, k := range []string{"send", "wait", "receive"} {
		if _, ok := en["timings"].(map[string]any)[k]; !ok {
			t.Errorf("timings.%s missing (required by HAR 1.2)", k)
		}
	}
}

// Rule 9.
func TestPseudoNoSecretSurvives(t *testing.T) {
	jwtA := signRaw(t, jwt.MapClaims{"sub": "alice", "email": "alice.realname@acme-corp.example", "exp": 1893456000, "aud": "acme-prod-api", "iss": "https://sso.acme-corp.example/realms/main", "name": "Alice Realname"}, "ACME-PROD-HS256-SIGNING-SECRET")
	jwtB := signRaw(t, jwt.MapClaims{"email": "bob.realname@acme-corp.example", "tenant_name": "Acme Holdings", "iss": "https://sso.acme-corp.example/realms/main"}, "ACME-PROD-HS256-SIGNING-SECRET")
	in := harOf(
		mkEntry("POST", "https://api.acme-corp.example:9443/v2/accounts/acct-77?session_token=QSESSIONSECRET",
			hdrs("Authorization", "Bearer "+jwtA, "X-Api-Key", "AKIAREALLOOKINGKEY123", "Cookie", "JSESSIONID=ABCDEF0123456789SESSION", "Host", "api.acme-corp.example:9443",
				"Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice.realname:Sup3rS3cretPw!")), "Origin", "https://portal.acme-corp.example"),
			`{"email":"alice.realname@acme-corp.example","password":"Sup3rS3cretPw!","profile":{"home":"https://api.acme-corp.example:9443/u/1"}}`,
			200, hdrs("Set-Cookie", "JSESSIONID=NEWSESSION0123456789; Domain=acme-corp.example; Path=/", "Location", "https://sso.acme-corp.example/login"),
			`{"access_token":"`+jwtB+`","owner":"bob.realname@acme-corp.example","secret":"topsecretvalue99"}`),
		mkEntry("GET", "https://api.acme-corp.example:9443/v2/accounts/acct-77", hdrs("Authorization", "Bearer "+jwtB, "Authorization-Extra", "x"), "", 200, nil, ""),
	)
	out, _ := pseudoize(t, newPseudo(t), in)
	for _, s := range []string{"alice.realname", "bob.realname", "acme-corp", "Acme Holdings", "Alice Realname", "AKIAREALLOOKINGKEY123", "ABCDEF0123456789SESSION",
		"NEWSESSION0123456789", "Sup3rS3cretPw", "topsecretvalue99", "QSESSIONSECRET", "ACME-PROD", "acme-prod-api", jwtA, jwtB, "9443"} {
		if strings.Contains(out, s) {
			t.Errorf("secret %q survived", s)
		}
	}
	// No 8-char window of either JWT's signature may appear; jwtB's payload (all dropped claims) neither.
	partsA, partsB := strings.Split(jwtA, "."), strings.Split(jwtB, ".")
	for _, part := range []string{partsA[2], partsB[2], partsB[1]} {
		for i := 0; i+8 <= len(part); i++ {
			if strings.Contains(out, part[i:i+8]) {
				t.Fatalf("8-char window %q of a JWT part survived", part[i:i+8])
			}
		}
	}
	// jwtA's payload: decoded dropped-claim strings must be gone (checked above); header window check.
	for i := 0; i+8 <= len(partsA[1]); i++ {
		w := partsA[1][i : i+8]
		if strings.Contains(out, w) && !strings.Contains(sharedWithKept(t), w) {
			t.Fatalf("payload window %q survived", w)
		}
	}
}

// sharedWithKept is the base64 payload of the only legal overlap: the re-signed
// claims {"iss":"authzcov-test","sub":"alice"}.
func sharedWithKept(t *testing.T) string {
	t.Helper()
	s := signRaw(t, jwt.MapClaims{"iss": testkey.Issuer, "sub": "alice"}, string(testkey.Key))
	return strings.Split(s, ".")[1]
}

// Rule 10.
func TestPseudoDeterministicWithKey(t *testing.T) {
	jwtA := signRaw(t, jwt.MapClaims{"sub": "alice", "exp": 5}, "k")
	in := harOf(
		mkEntry("GET", "http://a.example/x/1?q=2", hdrs("Authorization", "Bearer "+jwtA, "X-API-Key", "kkk", "Cookie", "s=1"), `{"a":1,"password":"p","e":"x@y.example"}`, 200, hdrs("Set-Cookie", "z=1"), `{"b":[1,2]}`),
		mkEntry("GET", "http://b.example/", nil, "", 404, nil, ""),
	)
	var outs [3]string
	for i := range outs {
		p, _ := NewPseudonymizer(PseudoOptions{Key: testRunKey})
		outs[i], _ = pseudoize(t, p, in)
	}
	if outs[0] != outs[1] || outs[1] != outs[2] {
		t.Error("output not byte-identical for the same key")
	}
}

func TestPseudoValidHAR12(t *testing.T) {
	_, doc := pseudoize(t, newPseudo(t), harOf(mkEntry("GET", "http://h/x", nil, "", 200, nil, `{"a":1}`)))
	log := doc["log"].(map[string]any)
	if log["version"] != "1.2" || log["creator"].(map[string]any)["name"] == nil {
		t.Errorf("log = %v", log)
	}
	e := entriesOf(doc)[0]
	for _, k := range []string{"startedDateTime", "time", "request", "response", "cache", "timings"} {
		if _, ok := e[k]; !ok {
			t.Errorf("entry.%s missing", k)
		}
	}
	for _, k := range []string{"method", "url", "httpVersion", "cookies", "headers", "queryString", "headersSize", "bodySize"} {
		if _, ok := e["request"].(map[string]any)[k]; !ok {
			t.Errorf("request.%s missing", k)
		}
	}
	for _, k := range []string{"status", "statusText", "httpVersion", "cookies", "headers", "content", "redirectURL", "headersSize", "bodySize"} {
		if _, ok := e["response"].(map[string]any)[k]; !ok {
			t.Errorf("response.%s missing", k)
		}
	}
}

func TestPseudoRejectsNonHAR(t *testing.T) {
	for _, in := range []string{``, `[]`, `{}`, `{"log":{}}`, `{"log":`, `not json`} {
		var out bytes.Buffer
		if err := newPseudo(t).HAR(strings.NewReader(in), &out); err == nil {
			t.Errorf("input %q accepted", in)
		}
	}
}

func FuzzPseudonymize(f *testing.F) {
	jwtRaw, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "a"}).SignedString([]byte("k"))
	f.Add(harOf(mkEntry("GET", "http://h/x?q=1", hdrs("Authorization", "Bearer "+jwtRaw, "Cookie", "a=b"), `{"password":"p"}`, 200, hdrs("Set-Cookie", "a=b"), `{"t":"`+jwtRaw+`"}`)))
	f.Add([]byte(`{"log":{"entries":[{"request":{"url":"::","headers":[{"name":"Authorization","value":"Basic !!!"}]},"response":{"content":{"text":"x","encoding":"base64"}}},1,null,"s"]}}`))
	f.Add([]byte(`{"log":{"entries":[{"request":{"url":"http://[::1]:80/a%zz@x.com","postData":{"mimeType":"application/x-www-form-urlencoded","text":"a=%zz&b&&=c"}}}]}}`))
	f.Add([]byte(`{"log":{"entries":[]}}`))
	f.Add([]byte(`{"log":{"entries":[{"request":{"url":"ws://u:p@h:1//x","headers":[{"name":"Cookie","value":"a;b=;=c"},{"name":"Location","value":"//a%40b.cc/x"}]},"response":{"content":{"mimeType":"application/json","text":"{\"password\":{\"a\":[1]},\"m\":\"token: abcdefghij a.b.c.d.e\"}"}}}]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := NewPseudonymizer(PseudoOptions{Key: testRunKey, KeepClaims: []string{"sub", "x"}})
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := p.HAR(bytes.NewReader(data), &out); err != nil {
			return
		}
		if !json.Valid(out.Bytes()) {
			t.Fatalf("invalid JSON output: %q", out.String())
		}
	})
}

// Fix 1: headers are default-deny.
func TestPseudoCustomHeadersDefaultDeny(t *testing.T) {
	custom := map[string]string{ //nolint:gosec // fake test values
		"X-Session-Token": "sess-tok-AAAA1111", "X-Refresh-Token": "refresh-BBBB2222", "X-Goog-Api-Key": "goog-CCCC3333",
		"Ocp-Apim-Subscription-Key": "apim-DDDD4444", "X-Tenant-Secret": "tsecret-EEEE5555", "X-Custom-Auth": "custom-FFFF6666",
		"X-Amz-Date-Signature": "sig-GGGG7777",
	}
	var h []any
	for k, v := range custom {
		h = append(h, map[string]any{"name": k, "value": v})
	}
	h = append(h, hdrs("Accept", "application/json", "Content-Type", "application/json", "User-Agent", "curl/8.0", "Cache-Control", "no-cache")...)
	e := mkEntry("GET", "http://h/x", h, "", 200, h, "")
	out, doc := pseudoize(t, newPseudo(t), harOf(e))
	for k, v := range custom {
		if strings.Contains(out, v) {
			t.Errorf("value of %s survived", k)
		}
	}
	en := entriesOf(doc)[0]
	for _, k := range []string{"X-Session-Token", "X-Goog-Api-Key"} {
		if !regexp.MustCompile(`^tok_[0-9a-f]{8}$`).MatchString(reqHeader(en, k)) {
			t.Errorf("%s = %q", k, reqHeader(en, k))
		}
	}
	if reqHeader(en, "Accept") != "application/json" || reqHeader(en, "User-Agent") != "curl/8.0" || reqHeader(en, "Cache-Control") != "no-cache" {
		t.Error("benign headers lost their value")
	}
	// Same value, different header: same replacement (identities stay distinguishable).
	e2 := mkEntry("GET", "http://h/x", hdrs("X-Foo", "same", "X-Bar", "same", "X-Baz", "other"), "", 200, nil, "")
	_, doc2 := pseudoize(t, newPseudo(t), harOf(e2))
	en2 := entriesOf(doc2)[0]
	if reqHeader(en2, "X-Foo") != reqHeader(en2, "X-Bar") || reqHeader(en2, "X-Foo") == reqHeader(en2, "X-Baz") {
		t.Error("tok mapping not stable/distinct")
	}
}

func TestPseudoCustomHeaderJWTResigned(t *testing.T) {
	raw := signRaw(t, jwt.MapClaims{"sub": "eve", "x": "DROPPED-CLAIM"}, "k")
	out, doc := pseudoize(t, newPseudo(t), harOf(mkEntry("GET", "http://h/x", hdrs("X-Session-Token", raw), "", 200, nil, "")))
	if strings.Contains(out, raw) || strings.Contains(out, "DROPPED-CLAIM") {
		t.Fatal("leak")
	}
	if verifyTestJWT(t, reqHeader(entriesOf(doc)[0], "X-Session-Token"))["sub"] != "eve" {
		t.Error("custom-header JWT not re-signed")
	}
}

// Fix 2: kept claims that hold e-mail addresses are pseudonymised.
func TestPseudoKeptEmailClaim(t *testing.T) {
	raw := signRaw(t, jwt.MapClaims{"sub": "alice@corp.com", "org": "Acme", "name": "Alice"}, "k")
	in := harOf(mkEntry("GET", "http://h/x", hdrs("Authorization", "Bearer "+raw), `{"owner":"alice@corp.com"}`, 200, nil, ""))
	out, doc := pseudoize(t, newPseudo(t, "sub", "org"), in)
	if strings.Contains(out, "alice@corp.com") {
		t.Fatal("raw email survived")
	}
	c := verifyTestJWT(t, strings.TrimPrefix(reqHeader(entriesOf(doc)[0], "Authorization"), "Bearer "))
	want := "user_" + hmacHex(testRunKey, "alice@corp.com")[:8] + "@example.test"
	if c["sub"] != want || c["org"] != "Acme" {
		t.Errorf("claims = %v, want sub %s", c, want)
	}
	if !strings.Contains(out, want) {
		t.Error("body email not mapped consistently with the claim")
	}
}

// Fix 3: payload not starting with eyJ.
func TestPseudoJWTWithSpacedPayload(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString
	spaced := b64([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + b64([]byte(`{ "sub": "zoe", "secretclaim": "SPACEDPAYLOAD" }`)) + "." + b64([]byte("signature-bytes-XYZ"))
	if strings.HasPrefix(strings.Split(spaced, ".")[1], "eyJ") {
		t.Fatal("test token payload must not start with eyJ")
	}
	e := mkEntry("GET", "http://h/x", hdrs("Authorization", "Bearer "+spaced, "User-Agent", "ua "+spaced), `{"t":"`+spaced+`"}`, 200, nil, `{"echo":"x `+spaced+` y"}`)
	out, _ := pseudoize(t, newPseudo(t), harOf(e))
	for _, s := range []string{spaced, strings.Split(spaced, ".")[1], strings.Split(spaced, ".")[2], "SPACEDPAYLOAD"} {
		if strings.Contains(out, s) {
			t.Errorf("%q survived", s)
		}
	}
}

// ---- adversarial-review regressions ----

func respText(e map[string]any) string {
	return e["response"].(map[string]any)["content"].(map[string]any)["text"].(string)
}

func respBodyOf(t *testing.T, body string) (string, string) {
	t.Helper()
	out, doc := pseudoize(t, newPseudo(t), harOf(mkEntry("GET", "http://h/x", nil, "", 200, nil, body)))
	return out, respText(entriesOf(doc)[0])
}

// 1. JWT header with leading whitespace / unusual prefix is still a JWT.
func TestPseudoJWTOddHeaderDetected(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString
	odd := b64([]byte(` {"alg":"HS256","typ":"JWT"}`)) + "." + b64([]byte(`{"sub":"zoe","hidden":"ODDCLAIMVALUE"}`)) + "." + b64([]byte("odd-signature-bytes"))
	parts := strings.Split(odd, ".")
	e := mkEntry("POST", "http://h/x?q="+odd, nil, "", 200, nil, `{"note":"jwt: `+odd+` end","other":"host.example.`+odd+`"}`)
	e["request"].(map[string]any)["postData"] = map[string]any{"mimeType": "application/x-www-form-urlencoded", "text": "a=" + odd + "&b=ok"}
	out, _ := pseudoize(t, newPseudo(t), harOf(e))
	for _, s := range append(parts, odd, "ODDCLAIMVALUE") {
		if strings.Contains(out, s) {
			t.Errorf("%q survived", s)
		}
	}
	if !strings.Contains(out, "b=ok") {
		t.Error("benign form field lost")
	}
}

// 2. Everything under a sensitive key is masked, whatever its type.
func TestPseudoSensitiveKeySubtree(t *testing.T) {
	body := `{"password":{"value":"CANARY-PW1"},"token":{"raw":"CANARY-TOK2"},"Authorization":{"x":"CANARY-AUTH3"},` +
		`"api_key":["CANARY-LIST4",{"d":"CANARY-LIST5"}],"refresh_token":123456789,"secret":true,"id":"o-1"}`
	out, txt := respBodyOf(t, body)
	for _, s := range []string{"CANARY-", "123456789"} {
		if strings.Contains(out, s) {
			t.Errorf("%q survived: %s", s, txt)
		}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(txt), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"password", "token", "Authorization", "api_key", "refresh_token", "secret"} {
		if _, isStr := m[k].(string); !isStr {
			t.Errorf("%s = %v, want a masked string", k, m[k])
		}
	}
	if m["id"] != "o-1" {
		t.Errorf("id = %v", m["id"])
	}
}

// 3. Sensitive key matching.
func TestPseudoSensitiveKeyMatching(t *testing.T) {
	masked := []string{"x-api-key", "accessKey", "access_key_id", "private_key", "credentials", "SessionId", "auth", "x_auth_header", "signature",
		"Set-Cookie", "otp", "pin", "cvv", "ssn", "passw0rd", "db_pwd", "user.password", "access.token", "clientSecret", "Passwd"}
	lowEntropy := map[string]bool{"otp": true, "pin": true, "cvv": true, "ssn": true, "passw0rd": true, "db_pwd": true, "user.password": true, "Passwd": true}
	kept := []string{"id", "orderId", "userId", "username", "book_title", "name", "email_count", "pinned", "title", "Books", "org_id", "role"}
	obj := map[string]any{}
	for _, k := range masked {
		obj[k] = "VAL-" + k
	}
	for _, k := range kept {
		obj[k] = "VAL-" + k
	}
	raw, _ := json.Marshal(obj)
	_, txt := respBodyOf(t, string(raw))
	var got map[string]any
	if err := json.Unmarshal([]byte(txt), &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range masked {
		v, _ := got[k].(string)
		switch {
		case strings.Contains(v, "VAL-"):
			t.Errorf("key %q not masked: %q", k, v)
		case lowEntropy[k] && v != "[redacted]":
			t.Errorf("low-entropy key %q = %q, want [redacted] without hash", k, v)
		}
	}
	for _, k := range kept {
		if got[k] != "VAL-"+k {
			t.Errorf("key %q wrongly masked: %v", k, got[k])
		}
	}
}

// 4. Scheme-relative URLs.
func TestPseudoSchemeRelativeURLs(t *testing.T) {
	e := mkEntry("GET", "http://h/x", nil, "", 302, hdrs("Location", "//cdn.corp.example/a?x=SECRETQ", "Content-Location", "//cdn.corp.example/b"),
		`{"u":"//cdn.corp.example/x","v":"see //other.corp.example/y here","p":"/files//x","q":"a//b"}`)
	out, doc := pseudoize(t, newPseudo(t), harOf(e))
	if strings.Contains(out, "corp.example") || strings.Contains(out, "SECRETQ") {
		t.Fatalf("leak: %s", out)
	}
	txt := respText(entriesOf(doc)[0])
	for _, w := range []string{`"u":"//h2.test/x"`, `//h3.test/y here`, `"p":"/files//x"`, `"q":"a//b"`} {
		if !strings.Contains(txt, w) {
			t.Errorf("body lacks %s: %s", w, txt)
		}
	}
	var loc string
	for _, h := range entriesOf(doc)[0]["response"].(map[string]any)["headers"].([]any) {
		if m := h.(map[string]any); m["name"] == "Location" {
			loc, _ = m["value"].(string)
		}
	}
	if !strings.HasPrefix(loc, "//h") || !strings.HasSuffix(strings.SplitN(loc, "?", 2)[0], ".test/a") {
		t.Errorf("Location = %q", loc)
	}
}

// 5. Any URL scheme; userinfo dropped.
func TestPseudoAnySchemeURLs(t *testing.T) {
	body := `{"db":"postgres://user:DBPASS@db.real-company.com:5432/x?password=QPASS","a":"ws://live.real-company.com/s","b":"wss://sock.real-company.com:443/s",` +
		`"c":"ftp://files.real-company.com/f","d":"sftp://sf.real-company.com/f","e":"git://git.real-company.com/r.git","f":"redis://:REDISPW@cache.real-company.com:6379/0",` +
		`"g":"mongodb://root:MONGOPW@mongo.real-company.com/db","h":"amqp://guest:AMQPPW@mq.real-company.com:5672/v","i":"jdbc:postgresql://jdb.real-company.com/x"}`
	out, txt := respBodyOf(t, body)
	for _, s := range []string{"real-company", "DBPASS", "QPASS", "REDISPW", "MONGOPW", "AMQPPW", "user:"} {
		if strings.Contains(out, s) {
			t.Errorf("%q survived: %s", s, txt)
		}
	}
	if !regexp.MustCompile(`"db":"postgres://h\d+\.test/x\?password=x"`).MatchString(txt) {
		t.Errorf("db url = %s", txt)
	}
}

// 6. Percent-encoded e-mails.
func TestPseudoPercentEncodedEmails(t *testing.T) {
	e := mkEntry("GET", "http://h/users/bob%40corp.example/x?mail=ann%40corp.example", hdrs("User-Agent", "ua BOB%40CORP.EXAMPLE"), "", 200, nil,
		`{"u":"https://h/x?owner=carl%40corp.example","v":"dave%40corp.example","w":"ERIN%40Corp.Example"}`)
	out, _ := pseudoize(t, newPseudo(t), harOf(e))
	if strings.Contains(strings.ToLower(out), "corp.example") || strings.Contains(strings.ToLower(out), "%40") {
		t.Errorf("percent-encoded email survived: %s", out)
	}
}

// 7. Cookie parts without "=".
func TestPseudoCookieWithoutEquals(t *testing.T) {
	e := mkEntry("GET", "http://h/x", hdrs("Cookie", "RAWSESSIONVALUE; theme=x"), "", 200, hdrs("Set-Cookie", "RAWSETVALUE; Path=/"), "")
	out, doc := pseudoize(t, newPseudo(t), harOf(e))
	if strings.Contains(out, "RAWSESSIONVALUE") || strings.Contains(out, "RAWSETVALUE") {
		t.Fatalf("bare cookie value survived: %s", out)
	}
	if c := reqHeader(entriesOf(doc)[0], "Cookie"); !regexp.MustCompile(`^tok_[0-9a-f]{8}; theme=tok_[0-9a-f]{8}$`).MatchString(c) {
		t.Errorf("cookie = %q", c)
	}
}

// 8. Free-text credentials.
func TestPseudoFreeTextCredentials(t *testing.T) {
	body := `{"m1":"Authorization: Bearer CANARYBEARER99","m2":"call with apikey=CANARYKEY1234 now","m3":"token: CANARYTOKEN77 ok",` +
		`"m4":"Basic Q0FOQVJZVVNFUjpQVw==","m5":"api-key CANARYAPIKEY5","m6":"token ok","m7":"tokens are great"}`
	out, txt := respBodyOf(t, body)
	if strings.Contains(out, "CANARY") || strings.Contains(out, "Q0FOQVJZ") {
		t.Fatalf("free-text secret survived: %s", txt)
	}
	for _, w := range []string{"Bearer tok_", "apikey=tok_", "token: tok_", "Basic tok_", `"m6":"token ok"`, `"m7":"tokens are great"`} {
		if !strings.Contains(txt, w) {
			t.Errorf("body lacks %q: %s", w, txt)
		}
	}
}
