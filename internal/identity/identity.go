// Package identity extracts redacted credentials from request headers and
// resolves them to configured identities. Raw secrets never leave Extract.
package identity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"authzcov/internal/model"
	"authzcov/internal/redact"
)

// MaxJWT is the longest token DecodeClaims will parse.
const MaxJWT = 16 << 10

// Credential kinds.
const (
	KindNone          = ""
	KindBearer        = "bearer"
	KindAuthorization = "authorization"
	KindCookie        = "cookie"
	KindAPIKey        = "apikey"
)

var apiKeyHeaders = []string{"X-API-Key", "Api-Key", "X-Auth-Token", "X-Access-Token"}

// KindBasic is an HTTP Basic credential recognised by a "basic" CredSpec.
const KindBasic = "basic"

// CredSpec says where to look for a credential. Type is bearer, cookie,
// apikey or basic.
type CredSpec struct {
	Type, Header string
	Schemes      []string
	Name         string
}

var defaultExtract = NewExtractor(nil)

// Extract builds a redacted credential from request headers using the
// default spec (bearer Authorization). lookup is a case-insensitive header
// lookup. Equivalent to NewExtractor(nil).
func Extract(lookup func(name string) []string) model.Credential { return defaultExtract(lookup) }

// NewExtractor tries specs in order (nil/empty means bearer Authorization
// [Bearer]); the first hit wins. After the specs, a fallback still recognises
// any Authorization, Cookie or API-key header so that such a request resolves
// unknown, never anonymous. Raw values never leave the returned function:
// only fingerprints (and JWT claims / the Basic user name) are kept.
func NewExtractor(specs []CredSpec) func(lookup func(name string) []string) model.Credential {
	if len(specs) == 0 {
		specs = []CredSpec{{Type: "bearer", Header: "Authorization", Schemes: []string{"Bearer"}}}
	}
	specs = append([]CredSpec(nil), specs...)
	return func(lookup func(name string) []string) model.Credential {
		for i := range specs {
			if c, ok := applySpec(&specs[i], lookup); ok {
				return c
			}
		}
		return fallbackExtract(lookup)
	}
}

func applySpec(s *CredSpec, lookup func(string) []string) (model.Credential, bool) {
	switch s.Type {
	case "bearer":
		h := s.Header
		if h == "" {
			h = "Authorization"
		}
		schemes := s.Schemes
		if len(schemes) == 0 {
			schemes = []string{"Bearer"}
		}
		for _, v := range lookup(h) {
			scheme, rest, _ := strings.Cut(strings.TrimSpace(v), " ")
			for _, want := range schemes {
				if strings.EqualFold(scheme, want) {
					return bearerCredential(strings.TrimSpace(rest)), true
				}
			}
		}
	case "cookie":
		if s.Name == "" {
			return model.Credential{}, false
		}
		for _, v := range lookup("Cookie") {
			for _, part := range strings.Split(v, ";") {
				name, val, ok := strings.Cut(strings.TrimSpace(part), "=")
				if ok && name == s.Name && val != "" {
					return model.Credential{Kind: KindCookie, Fingerprint: redact.Fingerprint(val)}, true
				}
			}
		}
	case "apikey":
		if s.Header == "" {
			return model.Credential{}, false
		}
		if v := nonEmpty(lookup(s.Header)); len(v) > 0 {
			return model.Credential{Kind: KindAPIKey, Fingerprint: redact.Fingerprint(v[0])}, true
		}
	case "basic":
		for _, v := range lookup("Authorization") {
			scheme, rest, _ := strings.Cut(strings.TrimSpace(v), " ")
			if strings.EqualFold(scheme, "Basic") {
				return basicCredential(strings.TrimSpace(rest)), true
			}
		}
	}
	return model.Credential{}, false
}

func bearerCredential(tok string) model.Credential {
	c := model.Credential{Kind: KindBearer, Fingerprint: redact.Fingerprint(tok)}
	if redact.LooksLikeJWT(tok) {
		if claims, err := DecodeClaims(tok); err == nil {
			c.Claims = claims
		}
	}
	return c
}

// basicCredential keeps only the user name. The fingerprint is derived from
// the user name alone: hashing anything containing the password would let a
// printed fingerprint be used for offline guessing.
func basicCredential(b64 string) model.Credential {
	invalid := model.Credential{Kind: KindBasic, Fingerprint: redact.Fingerprint("basic:invalid")}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(b64)
	}
	if err != nil {
		return invalid
	}
	user, _, ok := strings.Cut(string(raw), ":")
	if !ok || user == "" {
		return invalid
	}
	return model.Credential{
		Kind:        KindBasic,
		Fingerprint: redact.Fingerprint("basic:" + user),
		Claims:      map[string]any{"basic_user": user},
	}
}

// fallbackExtract recognises credentials no spec asked for. Precedence:
// Authorization, Cookie, API keys.
func fallbackExtract(lookup func(name string) []string) model.Credential {
	if v := lookup("Authorization"); len(v) > 0 {
		scheme, rest, _ := strings.Cut(strings.TrimSpace(v[0]), " ")
		if strings.EqualFold(scheme, "Bearer") {
			return bearerCredential(strings.TrimSpace(rest))
		}
		return model.Credential{Kind: KindAuthorization, Fingerprint: redact.Fingerprint(v[0])}
	}
	if v := nonEmpty(lookup("Cookie")); len(v) > 0 {
		return model.Credential{Kind: KindCookie, Fingerprint: redact.Fingerprint(strings.Join(v, "; "))}
	}
	for _, h := range apiKeyHeaders {
		if v := nonEmpty(lookup(h)); len(v) > 0 {
			return model.Credential{Kind: KindAPIKey, Fingerprint: redact.Fingerprint(v[0])}
		}
	}
	return model.Credential{Kind: KindNone}
}

func nonEmpty(vs []string) []string {
	var out []string
	for _, v := range vs {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// DecodeClaims decodes JWT claims without verifying the signature. Claims are
// used only to label recorded traffic (map a caller to a named identity in the
// report); authzcov never grants or denies access based on them. Tokens longer
// than MaxJWT are rejected. Numbers decode as json.Number.
func DecodeClaims(token string) (map[string]any, error) {
	if len(token) > MaxJWT {
		return nil, fmt.Errorf("jwt longer than %d bytes; not decoding", MaxJWT)
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser(jwt.WithJSONNumber()).ParseUnverified(token, claims); err != nil {
		// Do not wrap err: parser errors are safe today, but keep the token out by construction.
		return nil, errors.New("jwt is malformed; cannot decode claims")
	}
	return map[string]any(claims), nil
}

// Rule maps a credential to a configured identity. Every non-empty matcher
// (JWT, TokenFP, BasicUser) must match. Login is used only for token learning.
type Rule struct {
	Identity  model.Identity    // Name, Role, Rank, Tenant filled by caller (from config)
	JWT       map[string]string // claim dot path -> expected value; all must match (AND)
	TokenFP   string            // credential fingerprint (first 12 hex of SHA-256)
	BasicUser string
	Login     string
}

// Resolver maps credentials to identities.
type Resolver struct {
	rules   []Rule
	subject string
	learned map[string]learnedBinding // fingerprint -> binding
}

type learnedBinding struct {
	rule       int // index into rules; -1 = conflicted
	login      string
	conflicted bool
}

// NewResolver builds a resolver; subjectClaim is the dot path for Identity.Subject.
func NewResolver(rules []Rule, subjectClaim string) *Resolver {
	return &Resolver{rules: rules, subject: subjectClaim, learned: map[string]learnedBinding{}}
}

// LearnToken binds credential fingerprint fp to the identity that logged in
// as login: first Rule.Login == login, then the rule's JWT subject
// expectation, then the identity name. A fingerprint bound to two different
// identities becomes conflicted and never resolves. Unmatched logins are
// ignored. Call before Resolve (pass 1).
func (r *Resolver) LearnToken(fp, login string) {
	if fp == "" || login == "" {
		return
	}
	idx := r.findLogin(login)
	if idx < 0 {
		return
	}
	cur, ok := r.learned[fp]
	switch {
	case !ok:
		r.learned[fp] = learnedBinding{rule: idx, login: login}
	case cur.conflicted || cur.rule != idx:
		r.learned[fp] = learnedBinding{rule: -1, conflicted: true}
	}
}

// findLogin returns the single rule matching login at the first tier that
// matches anything, or -1 (none, or ambiguous within the tier).
func (r *Resolver) findLogin(login string) int {
	tiers := []func(*Rule) bool{
		func(x *Rule) bool { return x.Login == login },
		func(x *Rule) bool { return r.subject != "" && x.JWT[r.subject] == login },
		func(x *Rule) bool { return x.Identity.Name == login },
	}
	for _, match := range tiers {
		hit, n := -1, 0
		for i := range r.rules {
			if match(&r.rules[i]) {
				hit = i
				n++
			}
		}
		if n == 1 {
			return hit
		}
		if n > 1 {
			return -1
		}
	}
	return -1
}

// Resolve returns a fresh identity (callers may keep it) and its confidence.
func (r *Resolver) Resolve(c model.Credential) (*model.Identity, model.Confidence) {
	if c.Kind == KindNone {
		return &model.Identity{Name: "anonymous", Anonymous: true}, model.ConfDeclared
	}
	var hit *Rule
	n := 0
	for i := range r.rules {
		if ruleMatches(&r.rules[i], c) {
			hit = &r.rules[i]
			n++
		}
	}
	if n == 1 {
		id := hit.Identity
		switch {
		case c.Kind == KindBearer && c.Claims != nil:
			id.Subject = claimString(c.Claims, r.subject)
		case c.Kind == KindBasic:
			id.Subject, _ = c.Claims["basic_user"].(string)
		}
		return &id, model.ConfDeclared
	}
	if n == 0 && c.Fingerprint != "" {
		if b, ok := r.learned[c.Fingerprint]; ok && !b.conflicted {
			id := r.rules[b.rule].Identity
			id.Subject = b.login
			return &id, model.ConfLearned
		}
	}
	fp := c.Fingerprint
	if len(fp) > 8 {
		fp = fp[:8]
	}
	return &model.Identity{Name: "unknown-" + fp}, model.ConfUnknown
}

func ruleMatches(r *Rule, c model.Credential) bool {
	if len(r.JWT) == 0 && r.TokenFP == "" && r.BasicUser == "" {
		return false
	}
	if len(r.JWT) > 0 {
		if c.Kind != KindBearer || c.Claims == nil {
			return false
		}
		for path, want := range r.JWT {
			if !ClaimMatches(c.Claims, path, want) {
				return false
			}
		}
	}
	if r.TokenFP != "" && r.TokenFP != c.Fingerprint {
		return false
	}
	if r.BasicUser != "" {
		if u, _ := c.Claims["basic_user"].(string); c.Kind != KindBasic || u != r.BasicUser {
			return false
		}
	}
	return true
}

// LoginRule describes a login exchange that reveals which identity a token
// belongs to.
type LoginRule struct{ Method, Path, LoginField, TokenField string }

var redactedRE = regexp.MustCompile(`^\[redacted:([0-9a-f]{12})\]$`)

// LoginToken extracts (token fingerprint, login) from a login exchange: the
// method equals rule.Method, x.Path or template equals rule.Path, the status
// is 2xx, the login is the string at LoginField (dot path) in x.ReqJSON and
// the token is the string at TokenField in x.RespJSON. A token of the form
// "[redacted:<12 hex>]" yields those 12 hex, otherwise its Fingerprint.
func LoginToken(rule LoginRule, x *model.Exchange, template string) (fp, login string, ok bool) {
	if x == nil || x.Method != rule.Method || x.Status < 200 || x.Status > 299 ||
		(x.Path != rule.Path && template != rule.Path) {
		return "", "", false
	}
	login = jsonString(x.ReqJSON, rule.LoginField)
	tok := jsonString(x.RespJSON, rule.TokenField)
	if login == "" || tok == "" {
		return "", "", false
	}
	if m := redactedRE.FindStringSubmatch(tok); m != nil {
		return m[1], login, true
	}
	return redact.Fingerprint(tok), login, true
}

func jsonString(body []byte, path string) string {
	if len(body) == 0 {
		return ""
	}
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		return ""
	}
	got, ok := lookupPath(v, path)
	if !ok {
		return ""
	}
	s, _ := got.(string)
	return s
}

func lookupPath(claims map[string]any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	var cur any = claims
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[seg]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func claimString(claims map[string]any, path string) string {
	v, ok := lookupPath(claims, path)
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	if n, ok := v.(json.Number); ok {
		return n.String()
	}
	return ""
}

// ClaimMatches reports whether the claim at dot path equals want.
func ClaimMatches(claims map[string]any, path, want string) bool {
	v, ok := lookupPath(claims, path)
	if !ok {
		return false
	}
	if list, ok := v.([]any); ok {
		for _, e := range list {
			if scalarEquals(e, want) {
				return true
			}
		}
		return false
	}
	return scalarEquals(v, want)
}

func scalarEquals(v any, want string) bool {
	switch x := v.(type) {
	case string:
		return x == want
	case json.Number:
		return x.String() == want
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64) == want
	case int:
		return strconv.FormatInt(int64(x), 10) == want
	case int32:
		return strconv.FormatInt(int64(x), 10) == want
	case int64:
		return strconv.FormatInt(x, 10) == want
	case uint64:
		return strconv.FormatUint(x, 10) == want
	}
	return false
}
