package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"authzcov/internal/redact"
)

// MaxLoginBody caps the login response read; hitting it is a failure.
const MaxLoginBody = 64 << 10

// Failure reasons (enum; messages carry these, never bodies or secrets).
const (
	ReasonEnv           = "env_invalid"
	ReasonRequest       = "request_invalid"
	ReasonTransport     = "transport"
	ReasonStatus        = "status"
	ReasonRedirect      = "redirect"
	ReasonContentType   = "content_type"
	ReasonBodyTooLarge  = "body_too_large"
	ReasonTokenNotFound = "token_not_found"
	ReasonTokenInvalid  = "token_invalid"
	ReasonFingerprint   = "fingerprint_mismatch"
)

// ErrNoRecipe means the identity has no login recipe (use token_env instead).
var ErrNoRecipe = errors.New("no login recipe for identity")

// LoginResponse is what the Doer returns. Body is read at most MaxLoginBody+1 bytes.
type LoginResponse struct {
	Status int
	Header map[string][]string
	Body   io.ReadCloser
}

// Doer sends a login request through exec's pinned, safety-checked client. It
// must not follow redirects.
type Doer interface {
	Do(ctx context.Context, req LoginRequest) (LoginResponse, error)
}

// LoginError is a sanitized login failure.
type LoginError struct {
	Identity    string
	Status      int
	ContentType string
	Reason      string
	Detail      string // pointer, header or cookie name, env var message
	Path        string
}

func (e *LoginError) Error() string {
	s := fmt.Sprintf("login identity=%s status=%d reason=%s", e.Identity, e.Status, e.Reason)
	if e.ContentType != "" {
		s += " content_type=" + e.ContentType
	}
	if e.Path != "" {
		s += " path=" + e.Path
	}
	if e.Detail != "" {
		s += " " + e.Detail
	}
	return s
}

// Credential is a logged-in identity's token.
type Credential struct {
	Identity string
	Apply    Apply
	Token    Secret
}

// SetOn calls set once with the header that carries the token.
func (c Credential) SetOn(set func(name, value string)) {
	switch c.Apply.Kind {
	case "bearer":
		set("Authorization", "Bearer "+c.Token.Expose())
	case "header":
		set(c.Apply.Name, c.Token.Expose())
	case "cookie":
		set("Cookie", c.Apply.Name+"="+c.Token.Expose())
	}
}

type result struct {
	cred Credential
	err  error
}

// Provider logs in once per identity and caches the outcome, success or
// failure. It never logs in again on a 401: that is the observation under test.
type Provider struct {
	Recipes  map[string]Recipe
	Lookup   func(string) string // env lookup; defaults to os.Getenv
	ExpectFP map[string]string   // optional identity -> 12-hex token fingerprint
	TokenEnv map[string]string   // identity -> env var NAME of a static bearer token

	mu    sync.Mutex // guards cache only; never held across a login
	cache map[string]*entry
}

// entry serialises the login of one identity.
type entry struct {
	mu   sync.Mutex
	done bool
	res  result
}

// NewProvider returns a Provider for the given per-identity recipes.
func NewProvider(recipes map[string]Recipe) *Provider {
	return &Provider{Recipes: recipes, Lookup: os.Getenv, cache: map[string]*entry{}}
}

// For returns the identity's credential, logging in through d on first use.
func (p *Provider) For(ctx context.Context, identity string, d Doer) (Credential, error) {
	rec, ok := p.Recipes[identity]
	if !ok {
		if name, ok := p.TokenEnv[identity]; ok {
			return p.static(identity, name)
		}
		return Credential{}, ErrNoRecipe
	}
	p.mu.Lock()
	e := p.cache[identity]
	if e == nil {
		e = &entry{}
		p.cache[identity] = e
	}
	p.mu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.done {
		return e.res.cred, e.res.err
	}
	cred, err := p.login(ctx, identity, rec, d)
	if err != nil && ctx.Err() != nil {
		return cred, err // cancellation is not a verdict on the login: do not cache
	}
	e.done, e.res = true, result{cred, err}
	return cred, err
}

// static loads an identity's static token from its env var (bearer).
func (p *Provider) static(identity, name string) (Credential, error) {
	lookup := p.Lookup
	if lookup == nil {
		lookup = os.Getenv
	}
	s, err := LoadEnvFrom(name, lookup)
	if err != nil {
		return Credential{}, fmt.Errorf("identity %s: %w", identity, err)
	}
	return Credential{Identity: identity, Apply: Apply{Kind: "bearer"}, Token: s}, nil
}

// CheckEnv verifies every recipe's env placeholders (probe start, before any
// login). The error names the identity, field and variable, never a value.
func (p *Provider) CheckEnv() error {
	lookup := p.Lookup
	if lookup == nil {
		lookup = os.Getenv
	}
	ids := make([]string, 0, len(p.Recipes))
	for id := range p.Recipes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := p.Recipes[id].CheckEnv(lookup); err != nil {
			return fmt.Errorf("identity %s: %w", id, err)
		}
	}
	tids := make([]string, 0, len(p.TokenEnv))
	for id := range p.TokenEnv {
		tids = append(tids, id)
	}
	sort.Strings(tids)
	for _, id := range tids {
		if _, ok := p.Recipes[id]; ok {
			continue
		}
		if _, err := LoadEnvFrom(p.TokenEnv[id], lookup); err != nil {
			return fmt.Errorf("identity %s: %w", id, err)
		}
	}
	return nil
}

// Close zeroes cached tokens (best effort).
func (p *Provider) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.cache {
		e.mu.Lock()
		e.res.cred.Token.Zero()
		e.mu.Unlock()
	}
}

func (p *Provider) login(ctx context.Context, id string, rec Recipe, d Doer) (Credential, error) {
	le := &LoginError{Identity: id, Path: pathNoQuery(rec.Path)}
	lookup := p.Lookup
	if lookup == nil {
		lookup = os.Getenv
	}
	req, err := rec.BuildRequest(lookup)
	if err != nil {
		var re *RecipeError
		if errors.As(err, &re) {
			le.Reason = ReasonRequest
			le.Detail = "field=" + re.Field
		} else {
			le.Reason = ReasonEnv
			le.Detail = err.Error() // names the var; never the value
		}
		return Credential{}, le
	}
	resp, err := d.Do(ctx, req)
	req.Body.Zero()
	if err != nil {
		le.Reason = ReasonTransport // err text may carry a URL or query; drop it
		return Credential{}, le
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	le.Status = resp.Status
	le.ContentType = mediaType(resp.Header)
	tok, reason, detail := extract(rec.TokenFrom, resp)
	if reason != "" {
		le.Reason, le.Detail = reason, detail
		return Credential{}, le
	}
	if r := checkApplyToken(tok, rec.Apply); r != "" {
		le.Reason = r
		return Credential{}, le
	}
	if want := p.ExpectFP[id]; want != "" && redact.Fingerprint(tok) != want {
		le.Reason = ReasonFingerprint
		return Credential{}, le
	}
	return Credential{Identity: id, Apply: rec.Apply, Token: NewSecret([]byte(tok))}, nil
}

func pathNoQuery(p string) string { s, _, _ := strings.Cut(p, "?"); return s }

func headerValues(h map[string][]string, name string) []string {
	var out []string
	for k, v := range h {
		if strings.EqualFold(k, name) {
			out = append(out, v...)
		}
	}
	return out
}

func mediaType(h map[string][]string) string {
	v := headerValues(h, "Content-Type")
	if len(v) == 0 {
		return ""
	}
	mt, _, err := mime.ParseMediaType(v[0])
	if err != nil || !tcharRE.MatchString(strings.ReplaceAll(mt, "/", "")) {
		return ""
	}
	return mt
}

func cookieValue(h map[string][]string, name string) (string, bool) {
	for _, sc := range headerValues(h, "Set-Cookie") {
		first, _, _ := strings.Cut(sc, ";")
		k, v, ok := strings.Cut(first, "=")
		if ok && strings.TrimSpace(k) == name {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

// extract returns the token or a failure reason (+ detail naming the recipe
// location, never response content).
func extract(tf TokenFrom, resp LoginResponse) (tok, reason, detail string) {
	loc := tf.Kind + "=" + tf.Name
	switch tf.Kind {
	case "json":
		loc = "pointer=" + tf.Name
	case "header":
		loc = "header=" + tf.Name
	case "cookie":
		loc = "cookie=" + tf.Name
	}
	st := resp.Status
	switch {
	case st >= 300 && st < 400:
		if tf.Kind == "cookie" {
			if v, ok := cookieValue(resp.Header, tf.Name); ok {
				return checkToken(v, loc)
			}
		}
		return "", ReasonRedirect, ""
	case st < 200 || st >= 300:
		return "", ReasonStatus, ""
	}
	switch tf.Kind {
	case "header":
		vs := headerValues(resp.Header, tf.Name)
		if len(vs) == 0 {
			return "", ReasonTokenNotFound, loc
		}
		v := strings.TrimSpace(vs[0])
		if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
			v = strings.TrimSpace(v[7:])
		}
		return checkToken(v, loc)
	case "cookie":
		v, ok := cookieValue(resp.Header, tf.Name)
		if !ok {
			return "", ReasonTokenNotFound, loc
		}
		return checkToken(v, loc)
	}
	mt := mediaType(resp.Header)
	if mt != "application/json" && !strings.HasSuffix(mt, "+json") {
		return "", ReasonContentType, ""
	}
	if resp.Body == nil {
		return "", ReasonTokenNotFound, loc
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxLoginBody+1))
	if err != nil {
		return "", ReasonTransport, ""
	}
	if len(body) > MaxLoginBody {
		return "", ReasonBodyTooLarge, ""
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", ReasonTokenNotFound, loc
	}
	v, ok := pointer(doc, tf.Name)
	if !ok {
		return "", ReasonTokenNotFound, loc
	}
	return checkToken(v, loc)
}

func checkToken(v, loc string) (string, string, string) {
	if strings.TrimSpace(v) == "" {
		return "", ReasonTokenNotFound, loc
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return "", ReasonTokenInvalid, loc
		}
	}
	return v, "", ""
}

// checkApplyToken rejects tokens that would add cookie pairs when sent as a cookie.
func checkApplyToken(tok string, a Apply) string {
	if a.Kind == "cookie" && strings.ContainsAny(tok, "; ,\"\\") {
		return ReasonTokenInvalid
	}
	return ""
}

// pointer resolves an RFC 6901 pointer to a string value.
func pointer(doc any, ptr string) (string, bool) {
	cur := doc
	for _, raw := range strings.Split(ptr[1:], "/") {
		seg := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch n := cur.(type) {
		case map[string]any:
			v, ok := n[seg]
			if !ok {
				return "", false
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(n) || strconv.Itoa(i) != seg {
				return "", false
			}
			cur = n[i]
		default:
			return "", false
		}
	}
	s, ok := cur.(string)
	return s, ok
}
