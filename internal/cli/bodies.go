package cli

import (
	"bytes"

	"authzcov/internal/config"
)

// presentBody stands in for a response body that nothing will parse but whose
// non-emptiness suspicious.modifiedOrReturned still reads.
var presentBody = []byte("1")

// bodyNeeds says which exchange bodies a configured learning rule can read.
// Everything else is dropped as soon as it is known to be unused (see recStore),
// so a large HAR does not keep one body copy per entry. Only ReqJSON/RespJSON
// bytes are affected; the learning and suspicious semantics do not change.
type bodyNeeds struct {
	rules []bodyRule
}

type bodyRule struct{ method, path string }

func newBodyNeeds(cfg *config.File) *bodyNeeds {
	b := &bodyNeeds{}
	for _, r := range cfg.Ownership.LearnFromCreate {
		b.rules = append(b.rules, bodyRule{r.Method, r.Path})
	}
	for _, r := range cfg.Ownership.LearnFromLists {
		b.rules = append(b.rules, bodyRule{r.Method, r.Path})
	}
	for _, r := range cfg.LearnTokens {
		b.rules = append(b.rules, bodyRule{r.Method, r.Path})
	}
	return b
}

// methodMayNeed reports whether any rule uses this method (path unknown yet).
func (b *bodyNeeds) methodMayNeed(method string) bool {
	for _, r := range b.rules {
		if r.method == method {
			return true
		}
	}
	return false
}

// needs mirrors ownership.Learn and identity.LoginToken: the method matches
// and the path or the endpoint template equals the rule path.
func (b *bodyNeeds) needs(method, path, template string) bool {
	for _, r := range b.rules {
		if r.method == method && (r.path == template || r.path == path) {
			return true
		}
	}
	return false
}

// isEmptyJSON mirrors suspicious.modifiedOrReturned's notion of an empty body.
func isEmptyJSON(b []byte) bool {
	switch string(bytes.TrimSpace(b)) {
	case "", "[]", "{}", "null", `""`:
		return true
	}
	return false
}
