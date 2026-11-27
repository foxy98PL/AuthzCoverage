// Package relate classifies the relationship between a caller and the object
// owner (or the minimum allowed role). Unknown never counts as covered: any
// missing or low-confidence input yields RelUnknown.
package relate

import "authzcov/internal/model"

// Input is everything Classify needs for one observation.
type Input struct {
	Endpoint     *model.Endpoint
	Caller       *model.Identity
	CallerConf   model.Confidence
	Owner        *model.Identity // object-level only
	OwnerConf    model.Confidence
	MinRank      int // function-level: minimum allowed rank
	MinRankKnown bool
	// ObjectTenant is the tenant of the addressed object when it is known
	// from a tenant path parameter (ObjectTenantKnown). It takes precedence
	// over the owner's tenant and does not need a known owner.
	ObjectTenant      string
	ObjectTenantKnown bool
}

// Classify returns the caller/owner relationship, or RelUnknown when it cannot
// be established.
func Classify(in Input) model.Relationship {
	c := in.Caller
	if c == nil {
		return model.RelUnknown
	}
	if c.Anonymous {
		return model.RelAnonymous
	}
	if in.CallerConf == model.ConfUnknown || in.Endpoint == nil {
		return model.RelUnknown
	}
	ep := in.Endpoint
	if ep.TenantScoped && ep.Kind == model.ObjectLevel {
		return classifyTenantScoped(in)
	}
	if ep.Kind == model.ObjectLevel {
		o := in.Owner
		if in.ObjectTenantKnown {
			// A caller without a tenant is "other" too: tenant params exist only
			// when the config declares tenancy.
			if c.Tenant != "*" && c.Tenant != in.ObjectTenant {
				return model.RelOtherTenant
			}
		} else if o != nil && in.OwnerConf >= model.ConfInferred && o.Tenant != "" &&
			c.Tenant != "*" && c.Tenant != o.Tenant {
			return model.RelOtherTenant
		}
		if o == nil || in.OwnerConf == model.ConfUnknown {
			return model.RelUnknown
		}
		if c.Name == o.Name {
			return model.RelOwner
		}
		return byRank(c.Rank, o.Rank, model.RelSameRoleOtherUser)
	}
	min, ok := minRank(in)
	if !ok {
		return model.RelUnknown
	}
	return byRank(c.Rank, min, model.RelOwner)
}

// minRank is the minimum allowed rank: the endpoint's declared one
// (requirements.overrides[].min_role) beats the learned one.
func minRank(in Input) (int, bool) {
	if in.Endpoint.MinRankDeclared {
		return in.Endpoint.MinRank, true
	}
	return in.MinRank, in.MinRankKnown
}

// classifyTenantScoped handles endpoints whose object is the tenant. Another
// tenant is other_tenant; a member is classified with the function-level rule
// except that every role at or above the minimum counts as owner (a member
// with enough role).
func classifyTenantScoped(in Input) model.Relationship {
	c := in.Caller
	if !in.ObjectTenantKnown {
		return model.RelUnknown
	}
	if c.Tenant != "*" && c.Tenant != in.ObjectTenant {
		return model.RelOtherTenant
	}
	min, ok := minRank(in)
	if !ok {
		return model.RelUnknown
	}
	if c.Rank < min {
		return model.RelLowerRole
	}
	return model.RelOwner
}

func byRank(caller, ref int, equal model.Relationship) model.Relationship {
	switch {
	case caller < ref:
		return model.RelLowerRole
	case caller > ref:
		return model.RelHigherRole
	}
	return equal
}

// MinRanks computes the learned minimum allowed rank per function-level or
// tenant-scoped endpoint ID: the lowest Rank among non-anonymous callers with
// confidence >= learned that received a 2xx. On a tenant-scoped endpoint only
// members of the addressed tenant count (a 2xx for another tenant is a bug,
// not a permission). Endpoints with no such call are absent (unknown). A
// declared min_role replaces this (see Classify).
func MinRanks(obs []*model.Observation) map[string]int {
	out := map[string]int{}
	for _, o := range obs {
		if o == nil || o.Endpoint == nil || o.X == nil || o.Identity == nil {
			continue
		}
		scoped := o.Endpoint.TenantScoped && o.Endpoint.Kind == model.ObjectLevel
		if (o.Endpoint.Kind != model.FunctionLevel && !scoped) || o.Identity.Anonymous ||
			o.IDConf < model.ConfLearned || o.X.Status < 200 || o.X.Status > 299 {
			continue
		}
		if scoped && (!o.ObjectTenantKnown || (o.Identity.Tenant != "*" && o.Identity.Tenant != o.ObjectTenant)) {
			continue
		}
		if cur, ok := out[o.Endpoint.ID]; !ok || o.Identity.Rank < cur {
			out[o.Endpoint.ID] = o.Identity.Rank
		}
	}
	return out
}
