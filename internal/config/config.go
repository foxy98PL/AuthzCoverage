// Package config loads and validates identities.yaml (schema v1 (v0 files still parse)).
// Validation walks the YAML node tree so every error carries a line number
// and key path. Raw credentials are rejected and never echoed.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"authzcov/internal/redact"
)

// MaxSize is the largest identities file Load will read.
const MaxSize = 1 << 20

// File is a validated identities.yaml.
type File struct {
	Path       string
	Version    int
	Roles      map[string]int
	Identities []Identity
	Resources  map[string]string
	Ownership  Ownership

	Credentials []Credential // defaults applied when the key is absent
	JWTSubject  string       // dot path of the JWT subject claim; default "sub"
	JWTTenant   string       // optional dot path of the JWT claim holding the caller's tenant
	// TenantParams maps a path parameter name to "name": the parameter's value
	// is the tenant of the addressed object.
	TenantParams map[string]string
	Overrides    []Override
	LearnTokens  []LearnToken
}

// Credential says where a request carries its credential.
type Credential struct {
	Type, Header string
	Schemes      []string
	Name         string
	Line         int
}

// LearnToken learns token->identity bindings from a login exchange.
type LearnToken struct {
	Method, Path, IdentityFromRequestJSON, TokenFromResponseJSON string
	Line                                                         int
}

// Identity is one declared caller.
type Identity struct {
	Name, Role, Tenant string
	JWT                map[string]string
	// TokenFP is the first 12 hex of the SHA-256 of the credential; the
	// credential itself is never stored.
	TokenFP, BasicUser, Login string
	Markers                   []string
	Line                      int
}

// Override picks the object parameter of one endpoint by hand.
type Override struct {
	Endpoint, ObjectParam string // Endpoint is an exact endpoint ID, "GET /orgs/{orgId}"
	Line                  int
}

// Ownership holds ownership hints.
type Ownership struct {
	SelfParams      map[string]string
	LearnFromCreate []CreateRule
	LearnFromLists  []ListRule
}

// ListRule learns object ownership from a list response: every id found by
// IDsFromResponseJSON (dot path, "[]" = every element) belongs to the caller.
type ListRule struct {
	Method, Path, Resource, IDsFromResponseJSON string
	Line                                        int
}

// CreateRule learns object ownership from a create request.
type CreateRule struct {
	Method, Path, Resource, IDFromRequestJSON string
	Line                                      int
}

// Error is a validation error with location.
type Error struct {
	File      string
	Line      int
	Path, Msg string
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(e.File)
	if e.Line > 0 {
		b.WriteString(":" + strconv.Itoa(e.Line))
	}
	b.WriteString(": ")
	if e.Path != "" {
		b.WriteString(e.Path + ": ")
	}
	b.WriteString(e.Msg)
	return b.String()
}

// HasTenants reports whether the config has any tenancy: an identity with a
// tenant, tenancy.tenant_params, or jwt.tenant.
func (f *File) HasTenants() bool {
	if len(f.TenantParams) > 0 || f.JWTTenant != "" {
		return true
	}
	for _, id := range f.Identities {
		if id.Tenant != "" {
			return true
		}
	}
	return false
}

// Load reads and parses path, rejecting files larger than MaxSize.
func Load(path string) (*File, error) {
	fh, err := os.Open(path) //nolint:gosec // path is the user's own --identities flag
	if err != nil {
		return nil, fmt.Errorf("read identities file %s: %w", path, err)
	}
	defer func() { _ = fh.Close() }()
	data, err := io.ReadAll(io.LimitReader(fh, MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read identities file %s: %w", path, err)
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("identities file %s is larger than %d bytes; split or trim it", path, MaxSize)
	}
	return Parse(data, path)
}

const rawCredMsg = "raw credentials are not allowed in identities.yaml; store a hash (token_sha256) or an env var name (token_env), not the secret"

var (
	nameRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	secretKeys = map[string]bool{
		"token": true, "bearer": true, "password": true, "secret": true,
		"api_key": true, "apikey": true, "cookie": true, "authorization": true,
	}
	envRE     = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	sha256RE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	dotPathRE = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$`)
	methods   = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}
)

type parser struct{ file string }

func (p *parser) err(n *yaml.Node, path, format string, args ...any) *Error {
	e := &Error{File: p.file, Path: path, Msg: fmt.Sprintf(format, args...)}
	if n != nil {
		e.Line = n.Line
	}
	return e
}

// Parse validates data (named path in errors) and returns the File.
func Parse(data []byte, path string) (*File, error) {
	p := &parser{file: path}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, p.err(nil, "", "file is empty; see docs for the identities.yaml format")
		}
		return nil, p.err(nil, "", "invalid yaml: %s", firstLine(err.Error()))
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, p.err(&extra, "", "multiple yaml documents are not allowed; keep one document")
	}
	if e := p.noAnchors(&doc); e != nil {
		return nil, e
	}
	if e := p.noSecrets(&doc, ""); e != nil {
		return nil, e
	}
	if len(doc.Content) == 0 {
		return nil, p.err(nil, "", "file is empty; see docs for the identities.yaml format")
	}
	f, e := p.file0(doc.Content[0])
	if e != nil {
		return nil, e
	}
	f.Path = path
	return f, nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}

func (p *parser) noAnchors(n *yaml.Node) *Error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return p.err(n, "", "yaml anchors and aliases are not allowed")
	}
	for _, c := range n.Content {
		if e := p.noAnchors(c); e != nil {
			return e
		}
	}
	return nil
}

func (p *parser) noSecrets(n *yaml.Node, path string) *Error {
	switch n.Kind {
	case yaml.ScalarNode:
		if redact.LooksLikeJWT(n.Value) {
			return p.err(n, path, "%s", rawCredMsg)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			kp := join(path, k.Value)
			if secretKeys[strings.ToLower(k.Value)] || redact.LooksLikeJWT(k.Value) {
				return p.err(k, path, "%s", rawCredMsg) // parent path: the key itself may be a secret
			}
			if e := p.noSecrets(v, kp); e != nil {
				return e
			}
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			if e := p.noSecrets(c, fmt.Sprintf("%s[%d]", path, i)); e != nil {
				return e
			}
		}
	case yaml.DocumentNode:
		for _, c := range n.Content {
			if e := p.noSecrets(c, path); e != nil {
				return e
			}
		}
	}
	return nil
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// fields validates a mapping node and returns its values by key.
func (p *parser) fields(n *yaml.Node, path string, allowed ...string) (map[string]*yaml.Node, *Error) {
	if n.Kind != yaml.MappingNode {
		return nil, p.err(n, path, "must be a mapping")
	}
	out := map[string]*yaml.Node{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			return nil, p.err(k, path, "keys must be plain strings")
		}
		if allowed != nil {
			ok := false
			for _, a := range allowed {
				ok = ok || a == k.Value
			}
			if !ok {
				return nil, p.err(k, path, "unknown key %q; allowed keys: %s", k.Value, strings.Join(allowed, ", "))
			}
		}
		if _, dup := out[k.Value]; dup {
			return nil, p.err(k, join(path, k.Value), "duplicate key %q", k.Value)
		}
		out[k.Value] = v
	}
	return out, nil
}

func (p *parser) scalar(n *yaml.Node, path string) (string, *Error) {
	if n.Kind != yaml.ScalarNode {
		return "", p.err(n, path, "must be a scalar value")
	}
	return n.Value, nil
}

func (p *parser) nonEmptyString(n *yaml.Node, path string) (string, *Error) {
	s, e := p.scalar(n, path)
	if e != nil {
		return "", e
	}
	if s == "" {
		return "", p.err(n, path, "must not be empty")
	}
	return s, nil
}

var topLevelKeys = []string{"version", "roles", "identities", "resources", "ownership", "credentials", "jwt", "learn_tokens", "tenancy", "requirements"}

// TopLevelKeys returns the allowed top-level keys of identities.yaml, sorted.
func TopLevelKeys() []string {
	out := append([]string(nil), topLevelKeys...)
	sort.Strings(out)
	return out
}

func (p *parser) file0(root *yaml.Node) (*File, *Error) {
	m, e := p.fields(root, "", topLevelKeys...)
	if e != nil {
		return nil, e
	}
	f := &File{Resources: map[string]string{}}
	for _, req := range []string{"version", "roles", "identities"} {
		if m[req] == nil {
			return nil, p.err(root, req, "required key %q is missing", req)
		}
	}
	vn := m["version"]
	if v, err := strconv.Atoi(vn.Value); err != nil || vn.Kind != yaml.ScalarNode || v != 1 {
		return nil, p.err(vn, "version", "unsupported version; this build reads version: 1")
	}
	f.Version = 1
	if f.Roles, e = p.roles(m["roles"]); e != nil {
		return nil, e
	}
	if f.Identities, e = p.identities(m["identities"], f.Roles); e != nil {
		return nil, e
	}
	if f.Credentials, e = p.credentials(m["credentials"]); e != nil {
		return nil, e
	}
	if f.JWTSubject, f.JWTTenant, e = p.jwt(m["jwt"]); e != nil {
		return nil, e
	}
	if tn := m["tenancy"]; tn != nil {
		if f.TenantParams, e = p.tenancy(tn); e != nil {
			return nil, e
		}
	}
	if rn := m["requirements"]; rn != nil {
		if f.Overrides, e = p.requirements(rn); e != nil {
			return nil, e
		}
	}
	if ln := m["learn_tokens"]; ln != nil {
		if f.LearnTokens, e = p.learnTokens(ln); e != nil {
			return nil, e
		}
	}
	if rn := m["resources"]; rn != nil {
		if e = p.stringMap(rn, "resources", f.Resources, nil); e != nil {
			return nil, e
		}
	}
	if on := m["ownership"]; on != nil {
		if f.Ownership, e = p.ownership(on); e != nil {
			return nil, e
		}
	}
	return f, nil
}

func (p *parser) stringMap(n *yaml.Node, path string, dst map[string]string, check func(*yaml.Node, string, string) *Error) *Error {
	if _, e := p.fields(n, path); e != nil {
		return e
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		kp := join(path, k.Value)
		s, e := p.nonEmptyString(v, kp)
		if e != nil {
			return e
		}
		if check != nil {
			if e := check(v, kp, s); e != nil {
				return e
			}
		}
		dst[k.Value] = s
	}
	return nil
}

func (p *parser) roles(n *yaml.Node) (map[string]int, *Error) {
	if _, e := p.fields(n, "roles"); e != nil {
		return nil, e
	}
	if len(n.Content) == 0 {
		return nil, p.err(n, "roles", "must define at least one role, e.g. {user: 10, admin: 100}")
	}
	out := map[string]int{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		kp := join("roles", k.Value)
		rank, err := strconv.Atoi(v.Value)
		if v.Kind != yaml.ScalarNode || v.Tag != "!!int" || err != nil || rank < 0 || rank > 1000 {
			return nil, p.err(v, kp, "rank must be an integer between 0 and 1000")
		}
		if k.Value == "anonymous" && rank != 0 {
			return nil, p.err(v, kp, "the anonymous role must have rank 0")
		}
		out[k.Value] = rank
	}
	return out, nil
}

func (p *parser) identities(n *yaml.Node, roles map[string]int) ([]Identity, *Error) {
	if n.Kind != yaml.SequenceNode {
		return nil, p.err(n, "identities", "must be a list")
	}
	if len(n.Content) == 0 || len(n.Content) > 200 {
		return nil, p.err(n, "identities", "must contain between 1 and 200 identities")
	}
	known := make([]string, 0, len(roles))
	for r := range roles {
		known = append(known, r)
	}
	sort.Strings(known)
	seen := map[string]bool{}
	var out []Identity
	for i, item := range n.Content {
		ip := fmt.Sprintf("identities[%d]", i)
		m, e := p.fields(item, ip, "name", "role", "tenant", "match", "markers")
		if e != nil {
			return nil, e
		}
		id := Identity{Line: item.Line}
		if m["name"] == nil {
			return nil, p.err(item, ip+".name", "name is required")
		}
		name, e := p.scalar(m["name"], ip+".name")
		if e != nil {
			return nil, e
		}
		switch {
		case !nameRE.MatchString(name):
			return nil, p.err(m["name"], ip+".name", "name must match ^[a-z0-9][a-z0-9._-]{0,62}$")
		case name == "anonymous" || strings.HasPrefix(name, "unknown-"):
			return nil, p.err(m["name"], ip+".name", "name is reserved; pick another (anonymous and unknown-* are built in)")
		case seen[name]:
			return nil, p.err(m["name"], ip+".name", "duplicate identity name %q; names must be unique", name)
		}
		seen[name] = true
		id.Name = name
		if m["role"] == nil {
			return nil, p.err(item, ip+".role", "role is required")
		}
		role, e := p.scalar(m["role"], ip+".role")
		if e != nil {
			return nil, e
		}
		if _, ok := roles[role]; !ok {
			return nil, p.err(m["role"], ip+".role", "unknown role %q; known roles: %s", role, strings.Join(known, ", "))
		}
		id.Role = role
		if t := m["tenant"]; t != nil {
			if id.Tenant, e = p.scalar(t, ip+".tenant"); e != nil {
				return nil, e
			}
		}
		if m["match"] == nil {
			return nil, p.err(item, ip+".match", "match is required, e.g. match: {jwt: {sub: alice}}")
		}
		if mk := m["markers"]; mk != nil {
			if id.Markers, e = p.markers(mk, ip+".markers"); e != nil {
				return nil, e
			}
		}
		if e := p.match(m["match"], ip+".match", &id); e != nil {
			return nil, e
		}
		out = append(out, id)
	}
	return out, nil
}

func (p *parser) ownership(n *yaml.Node) (Ownership, *Error) {
	var o Ownership
	m, e := p.fields(n, "ownership", "self_params", "learn_from_create", "learn_from_lists")
	if e != nil {
		return o, e
	}
	if sp := m["self_params"]; sp != nil {
		o.SelfParams = map[string]string{}
		e := p.stringMap(sp, "ownership.self_params", o.SelfParams, func(v *yaml.Node, path, s string) *Error {
			if s != "subject" {
				return p.err(v, path, "unsupported value; v0 only supports \"subject\"")
			}
			return nil
		})
		if e != nil {
			return o, e
		}
	}
	if l := m["learn_from_create"]; l != nil {
		if l.Kind != yaml.SequenceNode {
			return o, p.err(l, "ownership.learn_from_create", "must be a list")
		}
		for i, item := range l.Content {
			r, e := p.createRule(item, fmt.Sprintf("ownership.learn_from_create[%d]", i))
			if e != nil {
				return o, e
			}
			o.LearnFromCreate = append(o.LearnFromCreate, r)
		}
	}
	if l := m["learn_from_lists"]; l != nil {
		if l.Kind != yaml.SequenceNode {
			return o, p.err(l, "ownership.learn_from_lists", "must be a list")
		}
		for i, item := range l.Content {
			r, e := p.listRule(item, fmt.Sprintf("ownership.learn_from_lists[%d]", i))
			if e != nil {
				return o, e
			}
			o.LearnFromLists = append(o.LearnFromLists, r)
		}
	}
	return o, nil
}

// listPathRE is a dot path whose segments may end in "[]" (every element); a
// segment may also be "[]" alone (top-level array).
var listPathRE = regexp.MustCompile(`^(?:[A-Za-z0-9_-]+(?:\[\])?|\[\])(?:\.(?:[A-Za-z0-9_-]+(?:\[\])?|\[\]))*$`)

func (p *parser) listRule(n *yaml.Node, path string) (ListRule, *Error) {
	r := ListRule{Line: n.Line}
	m, e := p.fields(n, path, "match", "resource", "ids_from")
	if e != nil {
		return r, e
	}
	for _, req := range []string{"match", "resource", "ids_from"} {
		if m[req] == nil {
			return r, p.err(n, join(path, req), "%s is required", req)
		}
	}
	if r.Method, r.Path, e = p.methodPath(m["match"], path+".match"); e != nil {
		return r, e
	}
	if r.Resource, e = p.nonEmptyString(m["resource"], path+".resource"); e != nil {
		return r, e
	}
	im, e := p.fields(m["ids_from"], path+".ids_from", "response_json")
	if e != nil {
		return r, e
	}
	if im["response_json"] == nil {
		return r, p.err(m["ids_from"], path+".ids_from.response_json", "response_json is required")
	}
	jp := path + ".ids_from.response_json"
	if r.IDsFromResponseJSON, e = p.nonEmptyString(im["response_json"], jp); e != nil {
		return r, e
	}
	if !listPathRE.MatchString(r.IDsFromResponseJSON) || strings.Count(r.IDsFromResponseJSON, ".") >= 8 {
		return r, p.err(im["response_json"], jp, "must be a dot path where [] means every element, e.g. items[].id or [].id")
	}
	return r, nil
}

// methodPath reads a {method, path} mapping.
func (p *parser) methodPath(n *yaml.Node, path string) (method, urlPath string, e *Error) {
	mm, e := p.fields(n, path, "method", "path")
	if e != nil {
		return "", "", e
	}
	if mm["method"] == nil {
		return "", "", p.err(n, path+".method", "method is required")
	}
	if method, e = p.scalar(mm["method"], path+".method"); e != nil {
		return "", "", e
	}
	if !methods[method] {
		return "", "", p.err(mm["method"], path+".method", "method must be one of GET, POST, PUT, PATCH, DELETE (upper-case)")
	}
	if mm["path"] == nil {
		return "", "", p.err(n, path+".path", "path is required")
	}
	if urlPath, e = p.scalar(mm["path"], path+".path"); e != nil {
		return "", "", e
	}
	if !strings.HasPrefix(urlPath, "/") {
		return "", "", p.err(mm["path"], path+".path", "path must start with \"/\"")
	}
	return method, urlPath, nil
}

func (p *parser) tenancy(n *yaml.Node) (map[string]string, *Error) {
	m, e := p.fields(n, "tenancy", "tenant_params")
	if e != nil {
		return nil, e
	}
	tp := m["tenant_params"]
	if tp == nil {
		return nil, nil
	}
	out := map[string]string{}
	e = p.stringMap(tp, "tenancy.tenant_params", out, func(v *yaml.Node, path, s string) *Error {
		if s != "name" {
			return p.err(v, path, "unsupported value; only \"name\" is supported (the parameter's value is the tenant)")
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (p *parser) requirements(n *yaml.Node) ([]Override, *Error) {
	m, e := p.fields(n, "requirements", "overrides")
	if e != nil {
		return nil, e
	}
	on := m["overrides"]
	if on == nil {
		return nil, nil
	}
	if on.Kind != yaml.SequenceNode {
		return nil, p.err(on, "requirements.overrides", "must be a list")
	}
	if len(on.Content) > 200 {
		return nil, p.err(on, "requirements.overrides", "at most 200 entries")
	}
	var out []Override
	seen := map[string]bool{}
	for i, item := range on.Content {
		op := fmt.Sprintf("requirements.overrides[%d]", i)
		im, e := p.fields(item, op, "endpoint", "object_param")
		if e != nil {
			return nil, e
		}
		for _, req := range []string{"endpoint", "object_param"} {
			if im[req] == nil {
				return nil, p.err(item, join(op, req), "%s is required", req)
			}
		}
		ov := Override{Line: item.Line}
		if ov.Endpoint, e = p.nonEmptyString(im["endpoint"], op+".endpoint"); e != nil {
			return nil, e
		}
		method, rest, ok := strings.Cut(ov.Endpoint, " ")
		if !ok || !methods[strings.ToUpper(method)] || !strings.HasPrefix(rest, "/") || strings.ContainsAny(rest, " \t") {
			return nil, p.err(im["endpoint"], op+".endpoint", "must be an endpoint ID such as \"GET /orgs/{orgId}/repos/{repo}\"")
		}
		if seen[ov.Endpoint] {
			return nil, p.err(im["endpoint"], op+".endpoint", "duplicate override for %q", ov.Endpoint)
		}
		seen[ov.Endpoint] = true
		if ov.ObjectParam, e = p.nonEmptyString(im["object_param"], op+".object_param"); e != nil {
			return nil, e
		}
		out = append(out, ov)
	}
	return out, nil
}

func (p *parser) createRule(n *yaml.Node, path string) (CreateRule, *Error) {
	r := CreateRule{Line: n.Line}
	m, e := p.fields(n, path, "match", "resource", "id_from")
	if e != nil {
		return r, e
	}
	for _, req := range []string{"match", "resource", "id_from"} {
		if m[req] == nil {
			return r, p.err(n, join(path, req), "%s is required", req)
		}
	}
	mm, e := p.fields(m["match"], path+".match", "method", "path")
	if e != nil {
		return r, e
	}
	if mm["method"] == nil {
		return r, p.err(m["match"], path+".match.method", "method is required")
	}
	if r.Method, e = p.scalar(mm["method"], path+".match.method"); e != nil {
		return r, e
	}
	if !methods[r.Method] {
		return r, p.err(mm["method"], path+".match.method", "method must be one of GET, POST, PUT, PATCH, DELETE (upper-case)")
	}
	if mm["path"] == nil {
		return r, p.err(m["match"], path+".match.path", "path is required")
	}
	if r.Path, e = p.scalar(mm["path"], path+".match.path"); e != nil {
		return r, e
	}
	if !strings.HasPrefix(r.Path, "/") {
		return r, p.err(mm["path"], path+".match.path", "path must start with \"/\"")
	}
	if r.Resource, e = p.nonEmptyString(m["resource"], path+".resource"); e != nil {
		return r, e
	}
	im, e := p.fields(m["id_from"], path+".id_from", "request_json")
	if e != nil {
		return r, e
	}
	if im["request_json"] == nil {
		return r, p.err(m["id_from"], path+".id_from.request_json", "request_json is required")
	}
	if r.IDFromRequestJSON, e = p.nonEmptyString(im["request_json"], path+".id_from.request_json"); e != nil {
		return r, e
	}
	return r, nil
}

var matchKeys = []string{"jwt", "token_sha256", "apikey_sha256", "token_env", "basic_user", "login"}

func (p *parser) match(n *yaml.Node, mp string, id *Identity) *Error {
	mm, e := p.fields(n, mp, matchKeys...)
	if e != nil {
		return e
	}
	if len(mm) == 0 {
		return p.err(n, mp, "must contain at least one of: %s", strings.Join(matchKeys, ", "))
	}
	if mm["token_sha256"] != nil && mm["apikey_sha256"] != nil {
		return p.err(n, mp, "give only one of token_sha256 and apikey_sha256 (aliases)")
	}
	if mm["token_env"] != nil && (mm["token_sha256"] != nil || mm["apikey_sha256"] != nil) {
		return p.err(n, mp, "give only one of token_sha256/apikey_sha256 and token_env")
	}
	if jn := mm["jwt"]; jn != nil {
		jp := mp + ".jwt"
		if _, e := p.fields(jn, jp); e != nil {
			return e
		}
		if len(jn.Content) == 0 {
			return p.err(jn, jp, "must match at least one claim")
		}
		id.JWT = map[string]string{}
		for j := 0; j+1 < len(jn.Content); j += 2 {
			k, v := jn.Content[j], jn.Content[j+1]
			s, e := p.nonEmptyString(v, join(jp, k.Value))
			if e != nil {
				return e
			}
			id.JWT[k.Value] = s
		}
	}
	for _, key := range []string{"token_sha256", "apikey_sha256"} {
		vn := mm[key]
		if vn == nil {
			continue
		}
		s, e := p.scalar(vn, mp+"."+key)
		if e != nil {
			return e
		}
		if !sha256RE.MatchString(s) {
			return p.err(vn, mp+"."+key, "must be 64 lower-case hex characters (SHA-256 of the token)")
		}
		id.TokenFP = s[:12]
	}
	if vn := mm["token_env"]; vn != nil {
		tp := mp + ".token_env"
		s, e := p.scalar(vn, tp)
		if e != nil {
			return e
		}
		if !envRE.MatchString(s) {
			return p.err(vn, tp, "env var name must match ^[A-Z_][A-Z0-9_]*$")
		}
		val := os.Getenv(s)
		if val == "" {
			return p.err(vn, tp, "env var %s is empty or unset", s)
		}
		id.TokenFP = redact.Fingerprint(val)
	}
	for key, dst := range map[string]*string{"basic_user": &id.BasicUser, "login": &id.Login} {
		if vn := mm[key]; vn != nil {
			s, e := p.nonEmptyString(vn, mp+"."+key)
			if e != nil {
				return e
			}
			*dst = s
		}
	}
	return nil
}

func (p *parser) markers(n *yaml.Node, path string) ([]string, *Error) {
	if n.Kind != yaml.SequenceNode {
		return nil, p.err(n, path, "must be a list")
	}
	if len(n.Content) > 50 {
		return nil, p.err(n, path, "at most 50 markers")
	}
	var out []string
	for i, c := range n.Content {
		mp := fmt.Sprintf("%s[%d]", path, i)
		s, e := p.nonEmptyString(c, mp)
		if e != nil {
			return nil, e
		}
		if len(s) < 6 {
			return nil, p.err(c, mp, "marker must be at least 6 characters to avoid false matches")
		}
		out = append(out, s)
	}
	return out, nil
}

func defaultCredentials() []Credential {
	return []Credential{{Type: "bearer", Header: "Authorization", Schemes: []string{"Bearer"}}}
}

func (p *parser) credentials(n *yaml.Node) ([]Credential, *Error) {
	if n == nil {
		return defaultCredentials(), nil
	}
	if n.Kind != yaml.SequenceNode {
		return nil, p.err(n, "credentials", "must be a list")
	}
	if len(n.Content) == 0 || len(n.Content) > 20 {
		return nil, p.err(n, "credentials", "must contain between 1 and 20 entries")
	}
	var out []Credential
	for i, item := range n.Content {
		cp := fmt.Sprintf("credentials[%d]", i)
		m, e := p.fields(item, cp)
		if e != nil {
			return nil, e
		}
		tn := m["type"]
		if tn == nil {
			return nil, p.err(item, cp+".type", "type is required")
		}
		typ, e := p.scalar(tn, cp+".type")
		if e != nil {
			return nil, e
		}
		c := Credential{Type: typ, Line: item.Line}
		var allowed []string
		switch typ {
		case "bearer":
			allowed = []string{"type", "header", "schemes"}
		case "cookie":
			allowed = []string{"type", "name"}
		case "apikey":
			allowed = []string{"type", "header"}
		case "basic":
			allowed = []string{"type"}
		default:
			return nil, p.err(tn, cp+".type", "type must be one of bearer, cookie, apikey, basic")
		}
		if _, e := p.fields(item, cp, allowed...); e != nil {
			return nil, e
		}
		switch typ {
		case "bearer":
			c.Header, c.Schemes = "Authorization", []string{"Bearer"}
			if hn := m["header"]; hn != nil {
				if c.Header, e = p.nonEmptyString(hn, cp+".header"); e != nil {
					return nil, e
				}
			}
			if sn := m["schemes"]; sn != nil {
				if c.Schemes, e = p.stringList(sn, cp+".schemes"); e != nil {
					return nil, e
				}
			}
		case "cookie":
			if m["name"] == nil {
				return nil, p.err(item, cp+".name", "name is required for cookie credentials")
			}
			if c.Name, e = p.nonEmptyString(m["name"], cp+".name"); e != nil {
				return nil, e
			}
		case "apikey":
			if m["header"] == nil {
				return nil, p.err(item, cp+".header", "header is required for apikey credentials")
			}
			if c.Header, e = p.nonEmptyString(m["header"], cp+".header"); e != nil {
				return nil, e
			}
		}
		out = append(out, c)
	}
	return out, nil
}

func (p *parser) stringList(n *yaml.Node, path string) ([]string, *Error) {
	if n.Kind != yaml.SequenceNode {
		return nil, p.err(n, path, "must be a list")
	}
	if len(n.Content) == 0 {
		return nil, p.err(n, path, "must not be empty")
	}
	var out []string
	for i, c := range n.Content {
		s, e := p.nonEmptyString(c, fmt.Sprintf("%s[%d]", path, i))
		if e != nil {
			return nil, e
		}
		out = append(out, s)
	}
	return out, nil
}

func (p *parser) jwt(n *yaml.Node) (subject, tenant string, e *Error) {
	if n == nil {
		return "sub", "", nil
	}
	m, e := p.fields(n, "jwt", "subject", "tenant")
	if e != nil {
		return "", "", e
	}
	subject = "sub"
	if sn := m["subject"]; sn != nil {
		if subject, e = p.claimPath(sn, "jwt.subject"); e != nil {
			return "", "", e
		}
	}
	if tn := m["tenant"]; tn != nil {
		if tenant, e = p.claimPath(tn, "jwt.tenant"); e != nil {
			return "", "", e
		}
	}
	return subject, tenant, nil
}

func (p *parser) claimPath(n *yaml.Node, path string) (string, *Error) {
	s, e := p.nonEmptyString(n, path)
	if e != nil {
		return "", e
	}
	if !dotPathRE.MatchString(s) {
		return "", p.err(n, path, "must be a dot path such as sub or user.id")
	}
	if strings.Count(s, ".") >= 5 {
		return "", p.err(n, path, "dot path depth must be at most 5")
	}
	return s, nil
}

func (p *parser) learnTokens(n *yaml.Node) ([]LearnToken, *Error) {
	if n.Kind != yaml.SequenceNode {
		return nil, p.err(n, "learn_tokens", "must be a list")
	}
	if len(n.Content) > 50 {
		return nil, p.err(n, "learn_tokens", "at most 50 entries")
	}
	var out []LearnToken
	for i, item := range n.Content {
		lp := fmt.Sprintf("learn_tokens[%d]", i)
		m, e := p.fields(item, lp, "match", "identity_from", "token_from")
		if e != nil {
			return nil, e
		}
		for _, req := range []string{"match", "identity_from", "token_from"} {
			if m[req] == nil {
				return nil, p.err(item, join(lp, req), "%s is required", req)
			}
		}
		l := LearnToken{Line: item.Line}
		mm, e := p.fields(m["match"], lp+".match", "method", "path")
		if e != nil {
			return nil, e
		}
		if mm["method"] == nil {
			return nil, p.err(m["match"], lp+".match.method", "method is required")
		}
		if l.Method, e = p.scalar(mm["method"], lp+".match.method"); e != nil {
			return nil, e
		}
		if !methods[l.Method] {
			return nil, p.err(mm["method"], lp+".match.method", "method must be one of GET, POST, PUT, PATCH, DELETE (upper-case)")
		}
		if mm["path"] == nil {
			return nil, p.err(m["match"], lp+".match.path", "path is required")
		}
		if l.Path, e = p.scalar(mm["path"], lp+".match.path"); e != nil {
			return nil, e
		}
		if !strings.HasPrefix(l.Path, "/") {
			return nil, p.err(mm["path"], lp+".match.path", "path must start with \"/\"")
		}
		if l.IdentityFromRequestJSON, e = p.sourceField(m["identity_from"], lp+".identity_from", "request_json", "request_form", "basic_user"); e != nil {
			return nil, e
		}
		if l.TokenFromResponseJSON, e = p.sourceField(m["token_from"], lp+".token_from", "response_json", "response_header", "set_cookie"); e != nil {
			return nil, e
		}
		out = append(out, l)
	}
	return out, nil
}

// sourceField reads a mapping whose first allowed key is the only supported
// one; the others are recognised but rejected as not supported yet.
func (p *parser) sourceField(n *yaml.Node, path string, supported string, unsupported ...string) (string, *Error) {
	m, e := p.fields(n, path, append([]string{supported}, unsupported...)...)
	if e != nil {
		return "", e
	}
	for _, u := range unsupported {
		if m[u] != nil {
			return "", p.err(m[u], join(path, u), "%s is not supported yet; use %s", u, supported)
		}
	}
	if m[supported] == nil {
		return "", p.err(n, join(path, supported), "%s is required", supported)
	}
	return p.nonEmptyString(m[supported], join(path, supported))
}

// Warnings lists non-fatal configuration problems in a deterministic order.
func (f *File) Warnings() []string {
	type key struct{ role, tenant string }
	count := map[key]int{}
	for _, id := range f.Identities {
		count[key{id.Role, id.Tenant}]++
	}
	var keys []key
	for k, n := range count {
		if n < 2 {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].role != keys[j].role {
			return keys[i].role < keys[j].role
		}
		return keys[i].tenant < keys[j].tenant
	})
	var out []string
	for _, k := range keys {
		out = append(out, fmt.Sprintf("role %q has fewer than two identities in tenant %q: same_role_other_user cannot be covered", k.role, k.tenant))
	}
	return out
}
