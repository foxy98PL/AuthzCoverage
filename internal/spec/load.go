// Package spec loads an OpenAPI 3.x document into endpoints.
package spec

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"

	"authzcov/internal/model"
)

var (
	// ErrDuplicate: two operations share method and template shape.
	ErrDuplicate = errors.New("duplicate endpoint")
	// ErrExternalRef: the spec references another file or URL.
	ErrExternalRef = errors.New("external $ref not allowed")
	// ErrUnsupported: a construct the matcher cannot handle.
	ErrUnsupported = errors.New("unsupported spec construct")
)

// Load reads an OpenAPI 3.0/3.1 file and returns its endpoints sorted by ID.
// It never reads anything but path: external $refs are refused.
func Load(path string) ([]*model.Endpoint, error) {
	data, err := os.ReadFile(path) //nolint:gosec // reading the user-supplied spec is the point
	if err != nil {
		return nil, fmt.Errorf("spec %s: %w", path, err)
	}
	eps, err := parse(data, path)
	if err != nil {
		return nil, fmt.Errorf("spec %s: %w", path, err)
	}
	return eps, nil
}

func parse(data []byte, path string) ([]*model.Endpoint, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false
	// Defence in depth: kin-openapi does not enforce the flag when a custom
	// reader is set, so the custom reader itself refuses everything.
	loader.ReadFromURIFunc = func(_ *openapi3.Loader, u *url.URL) ([]byte, error) {
		return nil, fmt.Errorf("%w: %s", ErrExternalRef, u.Redacted())
	}
	doc, err := loader.LoadFromData(data)
	if err != nil {
		var dis *openapi3.DisallowedExternalRefError
		if errors.As(err, &dis) {
			return nil, fmt.Errorf("%w: %q (bundle the spec into one file first)", ErrExternalRef, dis.Ref)
		}
		return nil, fmt.Errorf("parse: %w", err)
	}
	if doc.OpenAPI == "" {
		return nil, fmt.Errorf("%w: missing \"openapi\" field (Swagger 2.0 is not supported; convert to OpenAPI 3.x)", ErrUnsupported)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		return nil, fmt.Errorf("%w: openapi version %q, want 3.x", ErrUnsupported, doc.OpenAPI)
	}
	eps, err := endpoints(doc, data, path)
	if err != nil {
		return nil, err
	}
	// Validate after our own checks so duplicates get our deterministic message.
	if err := doc.Validate(context.Background(), openapi3.DisableExamplesValidation()); err != nil {
		return nil, fmt.Errorf("invalid openapi document: %w", err)
	}
	return eps, nil
}

func endpoints(doc *openapi3.T, data []byte, path string) ([]*model.Endpoint, error) {
	if doc.Paths == nil {
		return nil, nil
	}
	pm := doc.Paths.Map()
	tmpls := make([]string, 0, len(pm))
	for t := range pm {
		tmpls = append(tmpls, t)
	}
	sort.Strings(tmpls)

	lines := pathLines(data)
	seen := map[string]string{} // method + shape -> template
	var eps []*model.Endpoint
	for _, tmpl := range tmpls {
		item := pm[tmpl]
		params, err := templateParams(tmpl)
		if err != nil {
			return nil, err
		}
		for method, op := range item.Operations() {
			method = strings.ToUpper(method)
			key := method + " " + shape(tmpl)
			if prev, ok := seen[key]; ok {
				return nil, fmt.Errorf("%w: %s %s and %s %s match the same requests", ErrDuplicate, method, prev, method, tmpl)
			}
			seen[key] = tmpl
			ep := newEndpoint(method, tmpl, params, path, lines[tmpl])
			ep.QueryParams = queryParams(item, op)
			ep.AuthRequired = authRequired(doc.Security, op.Security)
			eps = append(eps, ep)
		}
	}
	sort.Slice(eps, func(i, j int) bool { return eps[i].ID < eps[j].ID })
	return eps, nil
}

func newEndpoint(method, tmpl string, params []string, file string, line int) *model.Endpoint {
	ep := &model.Endpoint{
		ID:       method + " " + tmpl,
		Method:   method,
		Template: tmpl,
		Params:   params,
		SpecFile: file,
		SpecLine: line,
	}
	if len(params) == 0 {
		return ep
	}
	ep.ObjectParam = params[len(params)-1]
	ep.Kind = model.ObjectLevel
	segs := segments(tmpl)
	for i, s := range segs {
		if s == "{"+ep.ObjectParam+"}" && i > 0 && !isParam(segs[i-1]) {
			ep.Resource = segs[i-1]
		}
	}
	return ep
}

// templateParams returns whole-segment {param} names in order. Params that
// share a segment with literal text ("/{id}.json") cannot be matched by the
// segment trie, so they are rejected instead of silently never matching.
func templateParams(tmpl string) ([]string, error) {
	var params []string
	for _, s := range segments(tmpl) {
		if isParam(s) {
			params = append(params, s[1:len(s)-1])
			continue
		}
		if strings.ContainsAny(s, "{}") {
			return nil, fmt.Errorf("%w: path %q: parameter must fill a whole segment", ErrUnsupported, tmpl)
		}
	}
	return params, nil
}

// shape normalises a template for duplicate detection: param names are
// erased and a trailing slash is ignored, mirroring the matcher.
func shape(tmpl string) string {
	segs := segments(tmpl)
	for i, s := range segs {
		if isParam(s) {
			segs[i] = "{}"
		}
	}
	return "/" + strings.Join(segs, "/")
}

func segments(tmpl string) []string {
	t := strings.Trim(tmpl, "/")
	if t == "" {
		return nil
	}
	return strings.Split(t, "/")
}

func isParam(s string) bool {
	return len(s) > 2 && s[0] == '{' && s[len(s)-1] == '}' && !strings.ContainsAny(s[1:len(s)-1], "{}")
}

// authRequired reports whether an operation's effective security requires
// authentication. An operation-level security list (even an empty one)
// replaces the document-level one; no list anywhere means public, and so does
// an empty list or any empty requirement object ({} = anonymous allowed).
func authRequired(global openapi3.SecurityRequirements, op *openapi3.SecurityRequirements) bool {
	reqs := global
	if op != nil {
		reqs = *op
	}
	if len(reqs) == 0 {
		return false
	}
	for _, r := range reqs {
		if len(r) == 0 {
			return false
		}
	}
	return true
}

// queryParams returns the sorted names of the in:query parameters declared
// on the path item or the operation (the operation wins on a name clash, but
// only the name matters here).
func queryParams(item *openapi3.PathItem, op *openapi3.Operation) []string {
	set := map[string]bool{}
	for _, ps := range []openapi3.Parameters{item.Parameters, op.Parameters} {
		for _, p := range ps {
			if p != nil && p.Value != nil && p.Value.In == openapi3.ParameterInQuery && p.Value.Name != "" {
				set[p.Value.Name] = true
			}
		}
	}
	if len(set) == 0 {
		return nil
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
