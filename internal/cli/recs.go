package cli

import (
	"strconv"
	"strings"

	"authzcov/internal/model"
)

// A HAR with a million entries must not keep a million model.Exchange
// values (plus their strings) alive while the pipeline runs. Ingest folds each
// exchange into a rec: a 48-byte value holding a pointer to a shared shape
// (method, host, credential, status), the path and the source position.
// Everything else is dropped unless a learning rule can read it. The full
// Exchange is rebuilt only for the few requests that need it.

const recChunk = 1 << 15

type rec struct {
	shape *model.Exchange // shared: Method, Host, Cred, Status only
	path  string
	query map[string][]string
	body  *recBodies // nil: no JSON body; sentinels: see below; else the kept bodies
	label uint32     // index into recStore.labels
	idx   int32      // entry index; -1 when the source has no "#index" suffix
}

type recBodies struct{ req, resp []byte }

// Sentinels for responses that no rule reads. suspicious only asks whether a
// GET/HEAD response was empty.
var (
	bodyEmpty   = &recBodies{}
	bodyPresent = &recBodies{}
)

type recStore struct {
	needs  *bodyNeeds
	chunks [][]rec
	n      int
	labels []string
	labelI map[string]uint32
	shapes map[shapeKey]*model.Exchange
	// Query-derived values and bodies that a rule reads stay per rec.
}

type shapeKey struct {
	method, host, kind, fp string
	status                 int
	body                   uint8 // observation shapes only: 0 nil, 1 empty, 2 present
}

func newRecStore(needs *bodyNeeds) *recStore {
	return &recStore{needs: needs, labelI: map[string]uint32{}, shapes: map[shapeKey]*model.Exchange{}}
}

func (s *recStore) label(l string) uint32 {
	if i, ok := s.labelI[l]; ok {
		return i
	}
	i := uint32(len(s.labels)) //nolint:gosec // one label per HAR file or zip member
	s.labels = append(s.labels, l)
	s.labelI[l] = i
	return i
}

// add folds x into a rec. x is not kept.
func (s *recStore) add(x *model.Exchange) {
	r := rec{path: strings.Clone(x.Path), query: x.Query, idx: -1}
	lab := x.Source
	if i := strings.LastIndexByte(x.Source, '#'); i >= 0 {
		if n, err := strconv.ParseInt(x.Source[i+1:], 10, 32); err == nil && n >= 0 && strconv.FormatInt(n, 10) == x.Source[i+1:] {
			lab, r.idx = x.Source[:i], int32(n) //nolint:gosec // ParseInt bitSize 32
		}
	}
	r.label = s.label(lab)
	k := shapeKey{method: x.Method, host: x.Host, kind: x.Cred.Kind, fp: x.Cred.Fingerprint, status: x.Status}
	sh := s.shapes[k]
	if sh == nil {
		sh = &model.Exchange{Method: strings.Clone(x.Method), Host: strings.Clone(x.Host), Cred: x.Cred, Status: x.Status}
		s.shapes[k] = sh
	}
	r.shape = sh
	switch {
	case s.needs == nil || s.needs.methodMayNeed(x.Method):
		if x.ReqJSON != nil || x.RespJSON != nil {
			r.body = &recBodies{req: x.ReqJSON, resp: x.RespJSON}
		}
	default:
		r.body = slimBody(x.Method, x.RespJSON)
	}
	if s.n%recChunk == 0 {
		s.chunks = append(s.chunks, make([]rec, 0, recChunk))
	}
	c := len(s.chunks) - 1
	s.chunks[c] = append(s.chunks[c], r)
	s.n++
}

// slimBody reduces a response no rule reads to what suspicious needs.
func slimBody(method string, resp []byte) *recBodies {
	if resp == nil || (method != "GET" && method != "HEAD") {
		return nil
	}
	return bodyState(resp)
}

func bodyState(resp []byte) *recBodies {
	if isEmptyJSON(resp) {
		return bodyEmpty
	}
	return bodyPresent
}

// bodyKind classifies the response body: 0 none, 1 empty, 2 present.
func (r *rec) bodyKind() uint8 {
	switch r.body {
	case nil:
		return 0
	case bodyEmpty:
		return 1
	case bodyPresent:
		return 2
	}
	if r.body.resp == nil {
		return 0
	}
	if isEmptyJSON(r.body.resp) {
		return 1
	}
	return 2
}

// each calls fn for every rec in order. Setting free releases consumed
// chunks as it goes.
func (s *recStore) each(free bool, fn func(r *rec)) {
	for ci := range s.chunks {
		c := s.chunks[ci]
		for i := range c {
			fn(&c[i])
		}
		if free {
			s.chunks[ci] = nil
		}
	}
}

// exchange rebuilds the full exchange for r with the given path.
func (s *recStore) exchange(r *rec, path string) *model.Exchange {
	x := &model.Exchange{
		Source: s.source(r), Method: r.shape.Method, Host: r.shape.Host, Path: path,
		Cred: r.shape.Cred, Status: r.shape.Status, Query: r.query,
	}
	switch r.body {
	case nil:
	case bodyEmpty:
		x.RespJSON = []byte{}
	case bodyPresent:
		x.RespJSON = presentBody
	default:
		x.ReqJSON, x.RespJSON = r.body.req, r.body.resp
	}
	return x
}

func (s *recStore) source(r *rec) string {
	l := s.labels[r.label]
	if r.idx < 0 {
		return l
	}
	return l + "#" + strconv.Itoa(int(r.idx))
}

// obsShape returns the shared exchange of observations that no rule reads.
// Invariant: the key omits Cred.Claims because an identical credential kind
// and fingerprint implies the identical token, hence identical claims. If a
// fingerprint ever becomes lossy (e.g. a truncated hash), add claims to
// shapeKey or shared exchanges would silently mix claims.
func (s *recStore) obsShape(r *rec) *model.Exchange {
	k := shapeKey{method: r.shape.Method, kind: r.shape.Cred.Kind, fp: r.shape.Cred.Fingerprint, status: r.shape.Status, body: r.bodyKind()}
	if sh, ok := s.shapes[k]; ok {
		return sh
	}
	sh := &model.Exchange{Method: r.shape.Method, Cred: r.shape.Cred, Status: r.shape.Status}
	switch k.body {
	case 1:
		sh.RespJSON = []byte{}
	case 2:
		sh.RespJSON = presentBody
	}
	s.shapes[k] = sh
	return sh
}
