// Package suspicious finds suspicious_allow findings: requests where a caller
// who should not have access (another user with the same role, another tenant,
// a lower role, or anonymous) received a 2xx response for an object-level
// endpoint, with enough identity and owner evidence to be sure.
//
// Unknown never counts: a caller or owner that is unknown or only inferred
// produces no finding. Find is pure and deterministic: input order does not
// matter. Messages carry identity names only, never credentials or raw object
// IDs.
package suspicious

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"authzcov/internal/model"
)

// MaxEvidence caps Allow.Evidence, matching the matrix.
const MaxEvidence = 5

// Allow is one aggregated suspicious_allow finding for an (endpoint,
// relationship) pair.
type Allow struct {
	Endpoint     string
	Relationship string
	Message      string
	Evidence     []string // sorted unique sources, at most MaxEvidence
	Count        int      // number of suspicious observations
}

type example struct {
	source string
	msg    string
}

// Find returns one Allow per (endpoint, relationship), sorted by endpoint then
// relationship. The result is never nil.
func Find(obs []*model.Observation) []Allow {
	type key struct{ ep, rel string }
	groups := map[key][]example{}
	for _, o := range obs {
		msg, ok := check(o)
		if !ok {
			continue
		}
		k := key{o.Endpoint.ID, string(o.Rel)}
		groups[k] = append(groups[k], example{source: o.X.Source, msg: msg})
	}
	out := make([]Allow, 0, len(groups))
	for k, exs := range groups {
		// Total order: evidence order, then message, so ties are deterministic.
		slices.SortFunc(exs, func(a, b example) int {
			return cmp.Or(compareEvidence(a.source, b.source), strings.Compare(a.msg, b.msg))
		})
		var ev []string
		for _, e := range exs {
			if e.source != "" && !slices.Contains(ev, e.source) {
				ev = append(ev, e.source)
			}
		}
		if len(ev) > MaxEvidence {
			ev = ev[:MaxEvidence]
		}
		msg := exs[0].msg
		if n := len(exs) - 1; n > 0 {
			msg += fmt.Sprintf(" (and %d more)", n)
		}
		out = append(out, Allow{Endpoint: k.ep, Relationship: k.rel, Message: msg, Evidence: ev, Count: len(exs)})
	}
	slices.SortFunc(out, func(a, b Allow) int {
		return cmp.Or(cmp.Compare(a.Endpoint, b.Endpoint), cmp.Compare(a.Relationship, b.Relationship))
	})
	return out
}

// check reports whether o is suspicious and returns its example message.
func check(o *model.Observation) (string, bool) {
	if o == nil || o.X == nil || o.Endpoint == nil || o.Identity == nil {
		return "", false
	}
	if o.Endpoint.Kind != model.ObjectLevel {
		return "", false
	}
	switch o.Rel {
	case model.RelSameRoleOtherUser, model.RelOtherTenant, model.RelLowerRole, model.RelAnonymous:
	default:
		return "", false
	}
	st := o.X.Status
	if st < 200 || st > 299 {
		return "", false
	}
	// An anonymous caller is only trusted as such under RelAnonymous; any
	// other pairing is inconsistent input (review KAN-88 F3).
	if o.Identity.Anonymous && o.Rel != model.RelAnonymous {
		return "", false
	}
	if !o.Identity.Anonymous && o.IDConf < model.ConfLearned {
		return "", false
	}
	byTenant := o.Rel == model.RelOtherTenant && o.ObjectTenantKnown
	hasOwner := o.Owner != nil && o.OwnerConf >= model.ConfLearned
	if !byTenant && !hasOwner {
		return "", false
	}
	if !modifiedOrReturned(o.X) {
		return "", false
	}
	caller := o.Identity.Name
	if o.Identity.Anonymous || caller == "" {
		caller = "anonymous"
	}
	if byTenant && !hasOwner {
		return fmt.Sprintf("%s (tenant %s) received %d for an object in tenant %s",
			caller, o.Identity.Tenant, st, o.ObjectTenant), true
	}
	if byTenant {
		// Name both the owner and the tenant mismatch (review KAN-88 F4).
		return fmt.Sprintf("%s (tenant %s) received %d for an object owned by %s in tenant %s",
			caller, o.Identity.Tenant, st, o.Owner.Name, o.ObjectTenant), true
	}
	return fmt.Sprintf("%s received %d for an object owned by %s", caller, st, o.Owner.Name), true
}

// modifiedOrReturned: reads need a captured non-empty JSON body; writes count
// on any 2xx.
func modifiedOrReturned(x *model.Exchange) bool {
	switch strings.ToUpper(x.Method) {
	case "GET", "HEAD":
		if x.Status == 204 || x.RespJSON == nil {
			return false
		}
		switch string(bytes.TrimSpace(x.RespJSON)) {
		case "", "[]", "{}", "null", `""`:
			return false
		}
	}
	return true
}

// compareEvidence orders "file#index" by file, then numeric index; sources
// without a numeric index sort after numeric ones. It is a total order and
// mirrors the matrix's evidence order.
func compareEvidence(a, b string) int {
	fa, na, oka := splitEvidence(a)
	fb, nb, okb := splitEvidence(b)
	if c := cmp.Compare(fa, fb); c != 0 {
		return c
	}
	switch {
	case oka && okb:
		if c := cmp.Compare(na, nb); c != 0 {
			return c
		}
	case oka:
		return -1
	case okb:
		return 1
	}
	return strings.Compare(a, b)
}

func splitEvidence(s string) (file string, n int, ok bool) {
	i := strings.LastIndexByte(s, '#')
	if i < 0 {
		return s, 0, false
	}
	n, err := strconv.Atoi(s[i+1:])
	return s[:i], n, err == nil
}
