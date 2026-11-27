// Package ownership learns who owns which object from recorded traffic.
// Pass 1 (Learn) builds indexes; pass 2 (Owner) answers queries. Results do
// not depend on the order observations were learned in.
package ownership

import (
	"bytes"
	"cmp"
	"encoding/json"
	"slices"
	"strings"

	"authzcov/internal/model"
)

// CreateRule says that a successful request matching Method+Path creates an
// object of Resource whose id is found at IDField in the request JSON.
type CreateRule struct {
	Method, Path, Resource, IDField string // IDField: dot path into request JSON
}

// ListRule says that every id found by IDsPath in the JSON response of a
// successful request matching Method+Path belongs to the caller. IDsPath is a
// dot path where "[]" after a name (or alone, for a top-level array) means
// every element, e.g. "items[].id" or "[].id".
type ListRule struct {
	Method, Path, Resource, IDsPath string
}

// maxListIDs caps the ids taken from one response.
const maxListIDs = 10000

// Config configures a Registry.
type Config struct {
	SelfParams map[string]string // param -> "subject"
	Create     []CreateRule
	Lists      []ListRule
	Resources  map[string]string // param name -> resource; overrides Endpoint.Resource
}

type claim struct {
	id       *model.Identity
	conf     model.Confidence
	conflict bool
	source   string // "self", "create" or "list"
}

type key struct{ resource, id string }

// Sources of an Object's owner claim.
const (
	SourceSelf   = "self"
	SourceCreate = "create"
	SourceList   = "list"
	// SubjectResource is the Resource reported for self (subject) claims.
	SubjectResource = "subject"
)

// Object is one learned owner claim, for reports.
type Object struct {
	Resource, ID string
	Owner        *model.Identity
	Conf         model.Confidence
	Source       string // SourceSelf, SourceCreate or SourceList
}

// Objects lists every non-conflicted learned owner claim, sorted by
// (Resource, ID). Subject claims use Resource SubjectResource. It is read-only.
func (r *Registry) Objects() []Object {
	out := make([]Object, 0, len(r.subjects)+len(r.owners))
	for s, c := range r.subjects {
		if !c.conflict {
			out = append(out, Object{Resource: SubjectResource, ID: s, Owner: c.id, Conf: c.conf, Source: c.source})
		}
	}
	for k, c := range r.owners {
		if !c.conflict {
			out = append(out, Object{Resource: k.resource, ID: k.id, Owner: c.id, Conf: c.conf, Source: c.source})
		}
	}
	slices.SortFunc(out, func(a, b Object) int {
		return cmp.Or(cmp.Compare(a.Resource, b.Resource), cmp.Compare(a.ID, b.ID), cmp.Compare(a.Source, b.Source))
	})
	return out
}

// Registry holds learned subjects and object owners.
type Registry struct {
	cfg      Config
	subjects map[string]*claim
	owners   map[key]*claim
}

// New returns an empty Registry.
func New(cfg Config) *Registry {
	return &Registry{cfg: cfg, subjects: map[string]*claim{}, owners: map[key]*claim{}}
}

// ResourceOf returns cfg.Resources[ep.ObjectParam] if set, else ep.Resource.
func (r *Registry) ResourceOf(ep *model.Endpoint) string {
	if ep == nil {
		return ""
	}
	if v, ok := r.cfg.Resources[ep.ObjectParam]; ok && v != "" {
		return v
	}
	return ep.Resource
}

// merge adds c to m[k]: higher confidence wins; equal confidence with a
// different identity name marks the entry conflicted (sticky).
func merge[K comparable](m map[K]*claim, k K, c claim) {
	cur := m[k]
	switch {
	case cur == nil || c.conf > cur.conf:
		m[k] = &c
	case c.conf == cur.conf && !cur.conflict && cur.id.Name != c.id.Name:
		m[k] = &claim{id: cur.id, conf: cur.conf, conflict: true, source: cur.source}
	}
}

func (r *Registry) mergeOwner(k key, c claim) { merge(r.owners, k, c) }

func known(o *model.Observation) bool {
	return o.Identity != nil && !o.Identity.Anonymous && o.IDConf >= model.ConfLearned
}

// Learn is pass 1. Call it for every matched observation.
func (r *Registry) Learn(o *model.Observation) {
	if o == nil || !known(o) {
		return
	}
	if s := o.Identity.Subject; s != "" {
		merge(r.subjects, s, claim{id: o.Identity, conf: model.ConfLearned, source: SourceSelf})
	}
	if o.X == nil || o.Endpoint == nil || o.X.Status < 200 || o.X.Status > 299 {
		return
	}
	for _, rule := range r.cfg.Create {
		if o.X.Method != rule.Method || (o.Endpoint.Template != rule.Path && o.X.Path != rule.Path) {
			continue
		}
		id, ok := jsonField(o.X.ReqJSON, rule.IDField)
		if !ok {
			continue
		}
		r.mergeOwner(key{rule.Resource, id}, claim{id: o.Identity, conf: model.ConfLearned, source: SourceCreate})
	}
	for _, rule := range r.cfg.Lists {
		if o.X.Method != rule.Method || (o.Endpoint.Template != rule.Path && o.X.Path != rule.Path) {
			continue
		}
		for _, id := range jsonValues(o.X.RespJSON, rule.IDsPath) {
			r.mergeOwner(key{rule.Resource, id}, claim{id: o.Identity, conf: model.ConfInferred, source: SourceList})
		}
	}
}

// jsonValues returns every string or number found at path in body. A nil or
// invalid body, or a path that does not resolve, yields nothing.
func jsonValues(body []byte, path string) []string {
	if len(body) == 0 || path == "" {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	cur := []any{v}
	for _, part := range strings.Split(path, ".") {
		name, each := strings.CutSuffix(part, "[]")
		var next []any
		for _, c := range cur {
			if name != "" {
				m, ok := c.(map[string]any)
				if !ok {
					continue
				}
				if c, ok = m[name]; !ok {
					continue
				}
			}
			if !each {
				next = append(next, c)
				continue
			}
			if arr, ok := c.([]any); ok {
				next = append(next, arr...)
			}
		}
		if len(next) > maxListIDs {
			next = next[:maxListIDs]
		}
		if cur = next; len(cur) == 0 {
			return nil
		}
	}
	var out []string
	for _, c := range cur {
		switch t := c.(type) {
		case string:
			if t != "" {
				out = append(out, t)
			}
		case json.Number:
			out = append(out, t.String())
		}
	}
	return out
}

func jsonField(body []byte, path string) (string, bool) {
	if len(body) == 0 || path == "" {
		return "", false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", false
	}
	for _, part := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return "", false
		}
		if v, ok = m[part]; !ok {
			return "", false
		}
	}
	var s string
	switch t := v.(type) {
	case string:
		s = t
	case json.Number:
		s = t.String()
	default:
		return "", false
	}
	return s, s != ""
}

// Owner is pass 2: the owner of the object addressed by o (object-level
// endpoints only). The returned identity may be shared; callers must not
// mutate it.
func (r *Registry) Owner(o *model.Observation) (*model.Identity, model.Confidence) {
	if o == nil || o.Endpoint == nil || o.Endpoint.Kind != model.ObjectLevel || o.Endpoint.ObjectParam == "" {
		return nil, model.ConfUnknown
	}
	p := o.Endpoint.ObjectParam
	v := o.Params[p]
	if v == "" {
		return nil, model.ConfUnknown
	}
	if r.cfg.SelfParams[p] == "subject" {
		if known(o) && o.Identity.Subject == v {
			return o.Identity, model.ConfDeclared
		}
		if c := r.subjects[v]; c != nil && !c.conflict {
			return c.id, model.ConfLearned
		}
		return nil, model.ConfUnknown
	}
	if c := r.owners[key{r.ResourceOf(o.Endpoint), v}]; c != nil && !c.conflict {
		return c.id, c.conf
	}
	return nil, model.ConfUnknown
}
