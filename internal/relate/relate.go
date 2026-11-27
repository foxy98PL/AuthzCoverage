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
	if in.Endpoint.Kind == model.ObjectLevel {
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
	if !in.MinRankKnown {
		return model.RelUnknown
	}
	return byRank(c.Rank, in.MinRank, model.RelOwner)
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

// MinRanks computes v0 minimum allowed rank per function-level endpoint ID: the
// lowest Rank among non-anonymous callers with confidence >= learned that
// received a 2xx. Endpoints with no such call are absent (unknown). Kept
// isolated: config will replace it.
func MinRanks(obs []*model.Observation) map[string]int {
	out := map[string]int{}
	for _, o := range obs {
		if o == nil || o.Endpoint == nil || o.X == nil || o.Identity == nil {
			continue
		}
		if o.Endpoint.Kind != model.FunctionLevel || o.Identity.Anonymous ||
			o.IDConf < model.ConfLearned || o.X.Status < 200 || o.X.Status > 299 {
			continue
		}
		if cur, ok := out[o.Endpoint.ID]; !ok || o.Identity.Rank < cur {
			out[o.Endpoint.ID] = o.Identity.Rank
		}
	}
	return out
}
