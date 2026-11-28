package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Recipe describes one login request and where the token comes back.
type Recipe struct {
	Method      string // POST | PUT
	Path        string // starts with "/", joined to the confirmed target by exec
	ContentType string // json | form
	Fields      map[string]string
	TokenFrom   TokenFrom
	Apply       Apply
}

// TokenFrom says where in the login response the token is.
type TokenFrom struct {
	Kind string // json | header | cookie
	Name string // JSON pointer, header name or cookie name
}

// Apply says how the token is used on probe requests.
type Apply struct {
	Kind string // bearer | header | cookie
	Name string // header or cookie name; empty for bearer
}

// RecipeError names the offending recipe field (relative, e.g. "fields.password").
type RecipeError struct{ Field, Msg string }

func (e *RecipeError) Error() string { return "login_recipe." + e.Field + ": " + e.Msg }

func rerr(field, format string, a ...any) error {
	return &RecipeError{Field: field, Msg: fmt.Sprintf(format, a...)}
}

var tcharRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

var forbiddenApplyHeader = map[string]bool{
	"host": true, "content-length": true, "cookie": true, "set-cookie": true,
	"authorization": true, "transfer-encoding": true, "connection": true,
	"proxy-authorization": true, "te": true, "upgrade": true,
}

// ParseApply parses "bearer", "header:Name" or "cookie:name".
func ParseApply(s string) (Apply, error) {
	k, n, has := strings.Cut(s, ":")
	a := Apply{Kind: k}
	if has {
		a.Name = n
	}
	return a, validApply(a)
}

func validApply(a Apply) error {
	switch a.Kind {
	case "bearer":
		if a.Name != "" {
			return rerr("apply", "bearer takes no name")
		}
	case "header":
		if !tcharRE.MatchString(a.Name) {
			return rerr("apply", "header:Name needs a valid header name")
		}
		if forbiddenApplyHeader[strings.ToLower(a.Name)] || strings.HasPrefix(strings.ToLower(a.Name), "x-forwarded-") {
			return rerr("apply", "header %s cannot be set here (use bearer for Authorization)", a.Name)
		}
	case "cookie":
		if !tcharRE.MatchString(a.Name) {
			return rerr("apply", "cookie:name needs a valid cookie name")
		}
	default:
		return rerr("apply", "must be bearer, header:Name or cookie:name")
	}
	return nil
}

func validPath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return rerr("path", "must start with /")
	}
	for _, r := range p {
		if r < 0x21 || r == 0x7f || r == '\\' || r == '@' || r == '#' {
			return rerr("path", "contains a character that is not allowed (control, space, backslash, @ or #)")
		}
	}
	if strings.Contains(p, "//") {
		return rerr("path", "must not contain //")
	}
	pathOnly, _, _ := strings.Cut(p, "?")
	for _, seg := range strings.Split(pathOnly, "/") {
		if seg == ".." || seg == "." {
			return rerr("path", "must not contain . or .. segments")
		}
	}
	low := strings.ToLower(p)
	for _, enc := range []string{"%2e", "%2f", "%5c"} {
		if strings.Contains(low, enc) {
			return rerr("path", "must not contain encoded dots or separators")
		}
	}
	return nil
}

// placeholder returns the env name when v is exactly ${NAME}.
func placeholder(v string) (name string, ok bool) {
	if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
		return v[2 : len(v)-1], true
	}
	return "", false
}

// Validate checks the recipe without touching the environment.
func (r Recipe) Validate() error {
	if r.Method != "POST" && r.Method != "PUT" {
		return rerr("method", "must be POST or PUT")
	}
	if err := validPath(r.Path); err != nil {
		return err
	}
	if r.ContentType != "json" && r.ContentType != "form" {
		return rerr("content_type", "must be json or form")
	}
	if len(r.Fields) == 0 {
		return rerr("fields", "at least one field is required")
	}
	keys := make([]string, 0, len(r.Fields))
	for k := range r.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "" || strings.ContainsAny(k, "\r\n\x00") {
			return rerr("fields", "field names must be non-empty and free of control characters")
		}
		v := r.Fields[k]
		fp := "fields." + k
		if name, ok := placeholder(v); ok {
			if err := CheckEnvName(name); err != nil {
				return rerr(fp, "%s", err.Error())
			}
			continue
		}
		if strings.Contains(v, "$") {
			return rerr(fp, "only a whole-value ${NAME} placeholder is allowed (no $VAR, nesting or concatenation)")
		}
		if strings.ContainsAny(v, "\r\n\x00") {
			return rerr(fp, "must not contain CR, LF or NUL")
		}
	}
	if err := r.TokenFrom.validate(); err != nil {
		return err
	}
	return validApply(r.Apply)
}

func (t TokenFrom) validate() error {
	switch t.Kind {
	case "json":
		if !strings.HasPrefix(t.Name, "/") {
			return rerr("token_from", "json needs a non-empty RFC 6901 pointer starting with /")
		}
		for _, r := range t.Name {
			if r < 0x20 || r == 0x7f {
				return rerr("token_from", "pointer must not contain control characters")
			}
		}
	case "header":
		if !tcharRE.MatchString(t.Name) || strings.EqualFold(t.Name, "Set-Cookie") {
			return rerr("token_from", "header needs a valid header name other than Set-Cookie (use cookie:)")
		}
	case "cookie":
		if !tcharRE.MatchString(t.Name) {
			return rerr("token_from", "cookie needs a valid cookie name")
		}
	default:
		return rerr("token_from", "must be json, header or cookie")
	}
	return nil
}

// LoginRequest is what exec sends. Body is a Secret so printing it is safe.
type LoginRequest struct {
	Method string
	Path   string
	Header map[string]string
	Body   Secret
}

// CheckEnv verifies, at probe time, that every env placeholder is set and
// well-formed. Errors name the field and variable, never a value.
func (r Recipe) CheckEnv(lookup func(string) string) error {
	keys := make([]string, 0, len(r.Fields))
	for k := range r.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if name, ok := placeholder(r.Fields[k]); ok {
			if _, err := loadEnv(name, lookup); err != nil {
				return fmt.Errorf("fields.%s: %w", k, err)
			}
		}
	}
	return nil
}

// BuildRequest resolves placeholders from lookup and encodes the fields with
// the content-type encoder; values are never spliced into text.
func (r Recipe) BuildRequest(lookup func(string) string) (LoginRequest, error) {
	if err := r.Validate(); err != nil {
		return LoginRequest{}, err
	}
	vals := make(map[string]string, len(r.Fields))
	keys := make([]string, 0, len(r.Fields))
	for k := range r.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := r.Fields[k]
		if name, ok := placeholder(v); ok {
			s, err := loadEnv(name, lookup)
			if err != nil {
				return LoginRequest{}, fmt.Errorf("fields.%s: %w", k, err)
			}
			v = s.Expose()
		}
		vals[k] = v
	}
	req := LoginRequest{Method: r.Method, Path: r.Path, Header: map[string]string{}}
	switch r.ContentType {
	case "json":
		b, err := json.Marshal(vals)
		if err != nil {
			return LoginRequest{}, errors.New("encode login body")
		}
		req.Header["Content-Type"] = "application/json"
		req.Body = NewSecret(b)
	default:
		q := url.Values{}
		for k, v := range vals {
			q.Set(k, v)
		}
		req.Header["Content-Type"] = "application/x-www-form-urlencoded"
		req.Body = NewSecret([]byte(q.Encode()))
	}
	return req, nil
}
