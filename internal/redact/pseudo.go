package redact

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"authzcov/internal/testkey"
)

const (
	// MinPseudoKey is the shortest accepted run key.
	MinPseudoKey = 32
	// maxPseudoBody mirrors the ingest body cap: larger bodies are dropped.
	maxPseudoBody = 64 << 10
	// maxPseudoJWT mirrors identity.MaxJWT: longer tokens are treated as opaque.
	maxPseudoJWT = 16 << 10
)

// PseudoOptions configure a Pseudonymizer.
type PseudoOptions struct {
	// Key is the HMAC run key (at least MinPseudoKey bytes). It is never written anywhere.
	Key []byte
	// KeepClaims lists the JWT claims copied into re-signed tokens (default: sub).
	// Their values are kept verbatim; every other claim is dropped.
	KeepClaims []string
}

// PseudoStats counts what a run changed. Distinct tokens are counted once.
type PseudoStats struct {
	Entries        int
	TokensResigned int // distinct JWTs re-signed with the test key
	TokensReplaced int // opaque credentials replaced by tok_<hash8>
	HeadersMasked  int // header values masked or dropped
	CookiesMasked  int // cookie values masked plus cookies-array items dropped
	HostsMapped    int // distinct hosts mapped to h<N>.test
	BodyFields     int // sensitive body fields masked
	BodiesDropped  int // bodies not kept (non-JSON/form, too large, undecodable)
	Emails         int // email addresses replaced
}

// Pseudonymizer rewrites a HAR so it is safe to commit while keeping what
// coverage needs: methods, path shapes, status codes, caller identity and
// object ids. State (token and host maps) lives for one run.
type Pseudonymizer struct {
	key   []byte
	keep  []string
	jwts  map[string]string // Fingerprint(raw JWT) -> re-signed token
	hosts map[string]string // lower-case host[:port] -> h<N>.test
	st    PseudoStats
}

// NewPseudonymizer validates o and returns a ready Pseudonymizer.
func NewPseudonymizer(o PseudoOptions) (*Pseudonymizer, error) {
	if len(o.Key) < MinPseudoKey {
		return nil, fmt.Errorf("pseudonymize key must be at least %d bytes", MinPseudoKey)
	}
	keep := o.KeepClaims
	if len(keep) == 0 {
		keep = []string{"sub"}
	}
	for _, k := range keep {
		if strings.TrimSpace(k) == "" {
			return nil, errors.New("empty claim name in keep-claims")
		}
	}
	return &Pseudonymizer{
		key: append([]byte(nil), o.Key...), keep: append([]string(nil), keep...),
		jwts: map[string]string{}, hosts: map[string]string{},
	}, nil
}

// Stats returns the counters so far.
func (p *Pseudonymizer) Stats() PseudoStats {
	s := p.st
	s.HostsMapped = len(p.hosts)
	return s
}

func hmacHex(key []byte, raw string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(raw))
	return hex.EncodeToString(m.Sum(nil))
}

func (p *Pseudonymizer) hash8(raw string) string { return hmacHex(p.key, raw)[:8] }

var (
	runRe   = regexp.MustCompile(`[A-Za-z0-9_.-]{11,}`)
	pctAtRe = regexp.MustCompile(`(?i)%40`)
	pctMail = regexp.MustCompile(`(?i)[A-Za-z0-9._%+'-]+%40[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	freeRe  = regexp.MustCompile(`(?i)\b(bearer|basic|token|apikey|api-key)(\s*[:= ]\s*)([A-Za-z0-9._~+/=-]{8,})`)
	// urlRe matches scheme://... (any scheme) or a scheme-relative //host/... that
	// starts the string or follows whitespace, a quote or one of ( = , ;.
	urlRe    = regexp.MustCompile(`(?i)(?:(^|[^A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]{1,15}:)//|(^|[\s"'(=,;])//)[^\s"'<>\\]*`)
	emailRe  = regexp.MustCompile(`[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	hdrName  = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	schemeRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)
	timeRe   = regexp.MustCompile(`^[0-9T:.+Z-]+$`)
	httpVer  = regexp.MustCompile(`^[A-Za-z0-9/.-]{1,16}$`)
)

// opaque replaces raw by tok_<hash8>.
func (p *Pseudonymizer) opaque(raw string) string {
	p.st.TokensReplaced++
	return "tok_" + p.hash8(raw)
}

// credential returns the replacement for a credential value: a re-signed JWT
// when raw is a decodable JWT, tok_<hash8> otherwise.
func (p *Pseudonymizer) credential(raw string) string {
	if len(raw) <= maxPseudoJWT && isJWT(raw) {
		fp := Fingerprint(raw)
		if out, ok := p.jwts[fp]; ok {
			return out
		}
		if out, err := p.resign(raw); err == nil {
			p.jwts[fp] = out
			p.st.TokensResigned++
			return out
		}
	}
	return p.opaque(raw)
}

func (p *Pseudonymizer) resign(raw string) (string, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser(jwt.WithJSONNumber()).ParseUnverified(raw, claims); err != nil {
		return "", errors.New("jwt is malformed")
	}
	out := jwt.MapClaims{}
	for _, k := range p.keep {
		if v, ok := claims[k]; ok && k != "iss" {
			if sv, isStr := v.(string); isStr {
				v = p.scrub(sv) // e-mail subjects must not survive
			}
			out[k] = v
		}
	}
	out["iss"] = testkey.Issuer
	return jwt.NewWithClaims(jwt.SigningMethodHS256, out).SignedString(testkey.Key)
}

func (p *Pseudonymizer) email(m string) string {
	if strings.HasSuffix(strings.ToLower(m), "@example.test") {
		return m
	}
	p.st.Emails++
	return "user_" + p.hash8(strings.ToLower(m)) + "@example.test"
}

// isJOSEHeader reports whether part base64url-decodes to a JSON object with an
// "alg" key (leading whitespace allowed).
func isJOSEHeader(part string) bool {
	if len(part) < 8 || len(part) > 2048 {
		return false
	}
	dec, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(part, "="))
	if err != nil {
		return false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(dec, &m) != nil {
		return false
	}
	_, ok := m["alg"]
	return ok
}

// isJWT reports a compact JWS: three base64url parts, the first a JOSE header.
func isJWT(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[1] == "" || !isJOSEHeader(parts[0]) {
		return false
	}
	for _, q := range parts {
		for _, r := range q {
			if !isBase64URL(r) {
				return false
			}
		}
	}
	return true
}

// scrubJWT replaces every JWT inside s (linear time: runs of token characters
// are split on dots and scanned for header.payload.signature windows).
func (p *Pseudonymizer) scrubJWT(s string) string {
	return runRe.ReplaceAllStringFunc(s, func(run string) string {
		if strings.Count(run, ".") < 2 {
			return run
		}
		parts := strings.Split(run, ".")
		var b strings.Builder
		for i := 0; i < len(parts); {
			if i+2 < len(parts) && parts[i+1] != "" && isJOSEHeader(parts[i]) {
				b.WriteString(p.credential(parts[i] + "." + parts[i+1] + "." + parts[i+2]))
				i += 3
			} else {
				b.WriteString(parts[i])
				i++
			}
			if i < len(parts) {
				b.WriteByte('.')
			}
		}
		return b.String()
	})
}

func (p *Pseudonymizer) freeText(m string) string {
	sub := freeRe.FindStringSubmatch(m)
	val := sub[3]
	if strings.HasPrefix(val, "tok_") || strings.HasPrefix(val, "user_") || isJWT(val) {
		return m
	}
	return sub[1] + sub[2] + p.opaque(val)
}

// scrub replaces JWTs, e-mail addresses (plain or %40-encoded) and
// "bearer/basic/token/apikey <value>" free-text credentials inside s.
func (p *Pseudonymizer) scrub(s string) string {
	if strings.Count(s, ".") >= 2 {
		s = p.scrubJWT(s)
	}
	if strings.Contains(s, "%") {
		s = pctMail.ReplaceAllStringFunc(s, func(m string) string { return p.email(pctAtRe.ReplaceAllString(m, "@")) })
	}
	if strings.Contains(s, "@") {
		s = emailRe.ReplaceAllStringFunc(s, p.email)
	}
	return freeRe.ReplaceAllStringFunc(s, p.freeText)
}

// text scrubs s and rewrites URLs (any scheme, or scheme-relative) inside it.
func (p *Pseudonymizer) text(s string) string {
	if !strings.Contains(s, "//") {
		return p.scrub(s)
	}
	var b strings.Builder
	last := 0
	for _, loc := range urlRe.FindAllStringSubmatchIndex(s, -1) {
		bs, be := loc[2], loc[3]
		if bs < 0 {
			bs, be = loc[6], loc[7]
		}
		b.WriteString(p.scrub(s[last:loc[0]]))
		b.WriteString(s[bs:be]) // the single boundary character
		b.WriteString(p.rewriteURL(s[be:loc[1]]))
		last = loc[1]
	}
	b.WriteString(p.scrub(s[last:]))
	return b.String()
}

const invalidURL = "http://invalid.test/"

// rewriteURL rewrites "<scheme>://auth/path?query#frag" or "//auth/path...":
// host mapped, userinfo/port/fragment dropped, query values masked, path scrubbed.
func (p *Pseudonymizer) rewriteURL(u string) string {
	i := strings.Index(u, "//")
	prefix, rest := strings.ToLower(u[:i+2]), u[i+2:]
	e := strings.IndexAny(rest, "/?#")
	if e < 0 {
		e = len(rest)
	}
	tail, _, _ := strings.Cut(rest[e:], "#")
	path, query, _ := strings.Cut(tail, "?")
	out := prefix + p.mapHost(rest[:e]) + p.cleanPath(path)
	if q, _ := p.maskQuery(query); q != "" {
		out += "?" + q
	}
	return out
}

// absURL rewrites an absolute URL of any scheme.
func (p *Pseudonymizer) absURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return invalidURL
	}
	return p.rewriteURL(raw)
}

func (p *Pseudonymizer) mapHost(authority string) string {
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		authority = authority[i+1:]
	}
	key := strings.ToLower(strings.TrimSpace(authority))
	if key == "" {
		return ""
	}
	h, ok := p.hosts[key]
	if !ok {
		h = fmt.Sprintf("h%d.test", len(p.hosts)+1)
		p.hosts[key] = h
	}
	return h
}

// cleanPath keeps path segments (object ids) but scrubs any email or JWT.
func (p *Pseudonymizer) cleanPath(escPath string) string {
	segs := strings.Split(escPath, "/")
	for i, seg := range segs {
		dec, err := url.PathUnescape(seg)
		if err != nil {
			segs[i] = url.PathEscape(p.scrub(seg))
			continue
		}
		if n := p.scrub(dec); n != dec {
			segs[i] = url.PathEscape(n)
		}
	}
	return strings.Join(segs, "/")
}

type kvPair struct{ name, value string }

// maskQuery keeps keys and replaces values with "x".
func (p *Pseudonymizer) maskQuery(raw string) (string, []kvPair) {
	var parts []string
	var pairs []kvPair
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, _, hasEq := strings.Cut(part, "=")
		kd, err := url.QueryUnescape(k)
		if err != nil {
			kd = k
		}
		kn := p.scrub(kd)
		ek := k
		if kn != kd || err != nil {
			ek = url.QueryEscape(kn)
		}
		if hasEq {
			parts = append(parts, ek+"=x")
			pairs = append(pairs, kvPair{kn, "x"})
		} else {
			parts = append(parts, ek)
			pairs = append(pairs, kvPair{kn, ""})
		}
	}
	return strings.Join(parts, "&"), pairs
}

// relURL rewrites a URL reference that may be relative (Location).
func (p *Pseudonymizer) relURL(s string) string {
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, "/") && !strings.HasPrefix(t, "//") {
		path, query, _ := strings.Cut(t, "?")
		path, _, _ = strings.Cut(path, "#")
		query, _, _ = strings.Cut(query, "#")
		out := p.cleanPath(path)
		if q, _ := p.maskQuery(query); q != "" {
			out += "?" + q
		}
		return out
	}
	return p.text(t)
}

// ---- JSON / form bodies ----

// keyClass classifies a body key: password (low entropy, no hash), token
// (credential-like) or plain. Keys are normalised (lower-case, '-', '_', '.' and
// spaces dropped); matching is by substring, so e.g. "author" is masked too.
func keyClass(k string) mode {
	n := strings.NewReplacer("-", "", "_", "", ".", "", " ", "").Replace(strings.ToLower(k))
	switch {
	case strings.Contains(n, "passw"), strings.Contains(n, "pwd"), n == "pin", n == "cvv", n == "ssn",
		strings.HasPrefix(n, "otp"), strings.HasSuffix(n, "otp"), strings.Contains(n, "totp"), strings.Contains(n, "hotp"):
		return password
	}
	for _, sub := range []string{"secret", "token", "apikey", "accesskey", "privatekey", "credential", "session", "auth", "signature", "cookie"} {
		if strings.Contains(n, sub) {
			return token
		}
	}
	return plain
}

// walk pseudonymises a decoded JSON value. Under a sensitive key the whole
// value is masked whatever its type: strings become a re-signed JWT or
// tok_<hash8> (token keys) or "[redacted]" (password keys); objects, arrays,
// numbers and booleans become the string "[redacted]"; null stays null.
func (p *Pseudonymizer) walk(v any, m mode) any {
	if m != plain && v != nil {
		p.st.BodyFields++
		if t, ok := v.(string); ok && m == token {
			return p.credential(t)
		}
		return "[redacted]"
	}
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[p.scrub(k)] = p.walk(val, keyClass(k))
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = p.walk(val, plain)
		}
		return out
	case string:
		return p.text(t)
	default:
		return v
	}
}

func (p *Pseudonymizer) jsonBody(b []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "", false
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p.walk(v, plain)); err != nil {
		return "", false
	}
	return strings.TrimSuffix(buf.String(), "\n"), true
}

func (p *Pseudonymizer) formBody(s string) string {
	parts := strings.Split(s, "&")
	for i, part := range parts {
		k, v, hasEq := strings.Cut(part, "=")
		kd, err1 := url.QueryUnescape(k)
		vd, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			// Undecodable pair: keep nothing of the value.
			p.st.BodyFields++
			parts[i] = url.QueryEscape(p.scrub(k))
			if hasEq {
				parts[i] += "=x"
			}
			continue
		}
		nk := url.QueryEscape(p.scrub(kd))
		switch {
		case !hasEq:
			parts[i] = nk
		case keyClass(kd) == password:
			p.st.BodyFields++
			parts[i] = nk + "=" + url.QueryEscape("[redacted]")
		case keyClass(kd) == token:
			p.st.BodyFields++
			parts[i] = nk + "=" + url.QueryEscape(p.credential(vd))
		default:
			parts[i] = nk + "=" + url.QueryEscape(p.text(vd))
		}
	}
	return strings.Join(parts, "&")
}

// body returns the pseudonymised body text; ok is false when it is dropped.
func (p *Pseudonymizer) body(mime, text, encoding string) (string, bool) {
	if text == "" {
		return "", false
	}
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(mime, ";", 2)[0]))
	isJSON, isForm := strings.Contains(mt, "json"), mt == "application/x-www-form-urlencoded"
	if !isJSON && !isForm {
		p.st.BodiesDropped++
		return "", false
	}
	raw := []byte(text)
	if strings.EqualFold(encoding, "base64") {
		dec, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			p.st.BodiesDropped++
			return "", false
		}
		raw = dec
	}
	if len(raw) > maxPseudoBody {
		p.st.BodiesDropped++
		return "", false
	}
	if isForm {
		return p.formBody(string(raw)), true
	}
	out, ok := p.jsonBody(raw)
	if !ok {
		p.st.BodiesDropped++
	}
	return out, ok
}

// ---- headers ----

var droppedHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-connection": true,
	"x-forwarded-for": true, "x-real-ip": true, "forwarded": true, "x-client-ip": true,
	"true-client-ip": true, "cf-connecting-ip": true, "x-forwarded-host": true,
	"x-forwarded-server": true, "via": true,
}

// benignHeaders are the only headers whose (scrubbed) value is kept. Every
// other header value is replaced by a re-signed JWT or tok_<hash8>.
var benignHeaders = map[string]bool{
	"accept": true, "accept-encoding": true, "accept-language": true, "content-type": true,
	"content-length": true, "content-encoding": true, "cache-control": true, "pragma": true,
	"user-agent": true, "x-requested-with": true, "origin": true, "referer": true,
	"date": true, "etag": true, "vary": true, "age": true, "expires": true,
	"last-modified": true, "if-none-match": true, "if-modified-since": true,
}

func (p *Pseudonymizer) authValue(v string) string {
	t := strings.TrimSpace(v)
	scheme, rest, found := strings.Cut(t, " ")
	rest = strings.TrimSpace(rest)
	switch {
	case !found || rest == "":
		return p.credential(t)
	case strings.EqualFold(scheme, "basic"):
		raw, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(rest)
		}
		user, _, ok := strings.Cut(string(raw), ":")
		if err != nil || !ok || user == "" {
			return "Basic " + p.opaque(rest)
		}
		p.st.TokensReplaced++
		return "Basic " + base64.StdEncoding.EncodeToString([]byte("user_"+p.hash8(user)+":"))
	case schemeRe.MatchString(scheme):
		return scheme + " " + p.credential(rest)
	}
	return p.opaque(t)
}

// cookieHeader masks every cookie value, keeping names.
func (p *Pseudonymizer) cookieHeader(v string) string {
	parts := strings.Split(v, ";")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, ok := strings.Cut(part, "=")
		if !ok { // a bare value: mask it whole
			p.st.CookiesMasked++
			out = append(out, p.credential(part))
			continue
		}
		name = p.scrub(name)
		if val == "" {
			out = append(out, name+"=")
			continue
		}
		p.st.CookiesMasked++
		out = append(out, name+"="+p.credential(val))
	}
	return strings.Join(out, "; ")
}

// setCookie keeps the cookie name and masks the value; attributes (Domain, Path, ...) are dropped.
func (p *Pseudonymizer) setCookie(v string) string {
	first, _, _ := strings.Cut(v, ";")
	return p.cookieHeader(first)
}

func (p *Pseudonymizer) headerList(v any) []any {
	out := []any{}
	list, _ := v.([]any)
	for _, h := range list {
		m, _ := h.(map[string]any)
		name, _ := m["name"].(string)
		val, _ := m["value"].(string)
		if !hdrName.MatchString(name) {
			continue
		}
		ln := strings.ToLower(name)
		var nv string
		switch {
		case droppedHeaders[ln]:
			p.st.HeadersMasked++
			continue
		case ln == "authorization" || ln == "proxy-authorization":
			p.st.HeadersMasked++
			nv = p.authValue(val)
		case ln == "cookie":
			p.st.HeadersMasked++
			nv = p.cookieHeader(val)
		case ln == "set-cookie":
			p.st.HeadersMasked++
			nv = p.setCookie(val)
		case ln == "host":
			nv = p.mapHost(val)
		case ln == "location" || ln == "content-location":
			nv = p.relURL(val)
		case benignHeaders[ln]:
			nv = p.text(val)
		default: // default-deny: unknown headers may carry any secret
			p.st.HeadersMasked++
			nv = p.credential(strings.TrimSpace(val))
		}
		out = append(out, map[string]any{"name": name, "value": nv})
	}
	return out
}

// ---- entries ----

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func version(s string) string {
	if httpVer.MatchString(s) {
		return s
	}
	return "HTTP/1.1"
}

func (p *Pseudonymizer) countCookies(v any) {
	if l, ok := v.([]any); ok {
		p.st.CookiesMasked += len(l)
	}
}

func (p *Pseudonymizer) content(mime, text, encoding string) map[string]any {
	c := map[string]any{"mimeType": p.text(mime)}
	if out, ok := p.body(mime, text, encoding); ok {
		c["text"] = out
		c["size"] = len(out)
	} else {
		c["size"] = 0
	}
	return c
}

func (p *Pseudonymizer) entry(e map[string]any) map[string]any {
	p.st.Entries++
	rq, rs := asMap(e["request"]), asMap(e["response"])

	method := strings.ToUpper(str(rq, "method"))
	if !hdrName.MatchString(method) {
		method = "GET"
	}
	reqURL, query := invalidURL, []kvPair(nil)
	if u, err := url.Parse(str(rq, "url")); err == nil && u.IsAbs() && u.Host != "" {
		reqURL = p.absURL(str(rq, "url"))
		if _, q, ok := strings.Cut(reqURL, "?"); ok {
			for _, part := range strings.Split(q, "&") {
				k, v, _ := strings.Cut(part, "=")
				if dk, err := url.QueryUnescape(k); err == nil {
					k = dk
				}
				query = append(query, kvPair{k, v})
			}
		}
	}
	qs := make([]any, 0, len(query))
	for _, q := range query {
		qs = append(qs, map[string]any{"name": q.name, "value": q.value})
	}
	p.countCookies(rq["cookies"])
	req := map[string]any{
		"method": method, "url": reqURL, "httpVersion": version(str(rq, "httpVersion")),
		"headers": p.headerList(rq["headers"]), "queryString": qs, "cookies": []any{},
		"headersSize": -1, "bodySize": -1,
	}
	if pd := asMap(rq["postData"]); pd != nil {
		mime := str(pd, "mimeType")
		pdOut := map[string]any{"mimeType": p.text(mime)}
		if out, ok := p.body(mime, str(pd, "text"), ""); ok {
			pdOut["text"] = out
			req["postData"] = pdOut
		}
	}

	status := int64(0)
	if n, ok := rs["status"].(json.Number); ok {
		status, _ = n.Int64()
	}
	statusText := p.text(str(rs, "statusText"))
	if len(statusText) > 64 {
		statusText = statusText[:64]
	}
	cn := asMap(rs["content"])
	p.countCookies(rs["cookies"])
	resp := map[string]any{
		"status": status, "statusText": statusText, "httpVersion": version(str(rs, "httpVersion")),
		"headers": p.headerList(rs["headers"]), "cookies": []any{},
		"content":     p.content(str(cn, "mimeType"), str(cn, "text"), str(cn, "encoding")),
		"redirectURL": p.relURL(str(rs, "redirectURL")),
		"headersSize": -1, "bodySize": -1,
	}
	started := str(e, "startedDateTime")
	if len(started) > 40 || !timeRe.MatchString(started) {
		started = "1970-01-01T00:00:00.000Z"
	}
	return map[string]any{
		"startedDateTime": started, "time": 0, "request": req, "response": resp, "cache": map[string]any{},
		"timings": map[string]any{"send": 0, "wait": 0, "receive": 0},
	}
}

// ---- streaming ----

// HAR reads a HAR from r entry by entry and writes the pseudonymised HAR 1.2
// to w. Only log.entries are read; everything else (pages, creator, comments)
// is dropped. On error the output is incomplete and must be discarded.
func (p *Pseudonymizer) HAR(r io.Reader, w io.Writer) error {
	bw := bufio.NewWriter(w)
	dec := json.NewDecoder(r)
	dec.UseNumber()
	if err := expectDelim(dec, '{'); err != nil {
		return fmt.Errorf("har: top level: %w", err)
	}
	found := false
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return fmt.Errorf("har: %w", err)
		}
		if key != "log" || found {
			if err := skip(dec); err != nil {
				return fmt.Errorf("har: %w", err)
			}
			continue
		}
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("har: %w", err)
		}
		if tok != json.Delim('{') {
			if err := skipFrom(dec, tok); err != nil {
				return fmt.Errorf("har: %w", err)
			}
			continue
		}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return fmt.Errorf("har: %w", err)
			}
			if k != "entries" || found {
				if err := skip(dec); err != nil {
					return fmt.Errorf("har: %w", err)
				}
				continue
			}
			tok, err := dec.Token()
			if err != nil {
				return fmt.Errorf("har: %w", err)
			}
			if tok != json.Delim('[') {
				if err := skipFrom(dec, tok); err != nil {
					return fmt.Errorf("har: %w", err)
				}
				continue
			}
			found = true
			_, _ = bw.WriteString(`{"log":{"version":"1.2","creator":{"name":"authzcov-redact","version":"1"},"entries":[`)
			if err := p.entries(dec, bw); err != nil {
				return err
			}
			_, _ = bw.WriteString("]}}")
		}
		if err := expectDelim(dec, '}'); err != nil {
			return fmt.Errorf("har: log: %w", err)
		}
	}
	if !found {
		return errors.New("har: no log.entries array")
	}
	return bw.Flush()
}

func (p *Pseudonymizer) entries(dec *json.Decoder, bw *bufio.Writer) error {
	first := true
	for dec.More() {
		var v any
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("har: entry %d: %w", p.st.Entries, err)
		}
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(p.entry(m)); err != nil {
			return fmt.Errorf("har: entry %d: %w", p.st.Entries, err)
		}
		if !first {
			_ = bw.WriteByte(',')
		}
		first = false
		_, _ = bw.Write(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	}
	return expectDelim(dec, ']')
}

func expectDelim(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != d {
		return fmt.Errorf("expected %q", rune(d))
	}
	return nil
}

func skip(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	return skipFrom(dec, tok)
}

func skipFrom(dec *json.Decoder, tok json.Token) error {
	d, ok := tok.(json.Delim)
	if !ok || d == '}' || d == ']' {
		return nil
	}
	for depth := 1; depth > 0; {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}
