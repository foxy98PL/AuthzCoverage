// Package matrix builds the endpoint x relationship coverage matrix. An
// observation only counts as coverage when both the caller identity and (for
// object-level endpoints) the owner are known with enough confidence; unknown
// never counts as covered.
package matrix

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"authzcov/internal/model"
)

// MaxEvidence caps the evidence list per cell.
const MaxEvidence = 5

// Summary totals the Required cells.
type Summary struct {
	Required, Covered, Gaps int
	Percent                 float64
}

// Matrix is the full coverage result.
type Matrix struct {
	Endpoints []*model.Endpoint                // sorted by ID
	Cells     map[string][]*model.CoverageCell // endpoint ID -> one cell per relationship, in model.Relationships() order
	Summary   Summary
}

// Requirements lists the relationships an endpoint kind must be tested with.
// other_tenant is dropped when the identity set has no tenants.
func Requirements(kind model.EndpointKind, hasTenants bool) []model.Relationship {
	var reqs []model.Relationship
	if kind == model.ObjectLevel {
		reqs = []model.Relationship{model.RelOwner, model.RelSameRoleOtherUser, model.RelOtherTenant, model.RelAnonymous}
	} else {
		reqs = []model.Relationship{model.RelOwner, model.RelLowerRole, model.RelAnonymous}
	}
	if !hasTenants {
		reqs = slices.DeleteFunc(reqs, func(r model.Relationship) bool { return r == model.RelOtherTenant })
	}
	return reqs
}

// RequirementsFor is Requirements for a concrete endpoint. A tenant-scoped
// endpoint (its object is the tenant) has no per-user owner, so it requires
// owner (a member with enough role), lower_role, other_tenant and anonymous.
func RequirementsFor(e *model.Endpoint, hasTenants bool) []model.Relationship {
	if e == nil || !e.TenantScoped || e.Kind != model.ObjectLevel {
		if e == nil {
			return Requirements(model.FunctionLevel, hasTenants)
		}
		return Requirements(e.Kind, hasTenants)
	}
	reqs := []model.Relationship{model.RelOwner, model.RelLowerRole, model.RelOtherTenant, model.RelAnonymous}
	if !hasTenants {
		reqs = slices.DeleteFunc(reqs, func(r model.Relationship) bool { return r == model.RelOtherTenant })
	}
	return reqs
}

type cellAcc struct {
	cell     *model.CoverageCell
	ids      map[string]bool
	evidence map[string]bool
	minConf  model.Confidence
}

// Options tunes Build.
type Options struct {
	// Strict counts an observation only when its caller identity and, for
	// object-level endpoints, its owner are known with confidence >= learned.
	Strict bool
	// HasLowestRank says LowestRank is set: the lowest rank among the defined
	// roles. MinRanks holds the learned minimum rank per endpoint ID. Together
	// they decide whether lower_role is required: it is not when the
	// effective minimum (declared, else learned) is not above LowestRank,
	// because no defined role could be below it. An unknown minimum keeps it
	// required.
	HasLowestRank bool
	LowestRank    int
	MinRanks      map[string]int
}

// Build computes the matrix without strict mode.
func Build(endpoints []*model.Endpoint, obs []*model.Observation, hasTenants bool) *Matrix {
	return BuildWith(endpoints, obs, hasTenants, Options{})
}

// BuildWith computes the matrix. Output does not depend on input order.
func BuildWith(endpoints []*model.Endpoint, obs []*model.Observation, hasTenants bool, opts Options) *Matrix {
	ownerMin := model.ConfInferred
	if opts.Strict {
		ownerMin = model.ConfLearned
	}
	eps := make([]*model.Endpoint, 0, len(endpoints))
	for _, e := range endpoints {
		if e != nil {
			eps = append(eps, e)
		}
	}
	slices.SortStableFunc(eps, func(a, b *model.Endpoint) int { return cmp.Compare(a.ID, b.ID) })

	m := &Matrix{Endpoints: eps, Cells: make(map[string][]*model.CoverageCell, len(eps))}
	accs := make(map[string]map[model.Relationship]*cellAcc, len(eps))
	needsOwner := make(map[string]bool, len(eps)) // object-level and not tenant-scoped
	for _, e := range eps {
		if _, dup := accs[e.ID]; dup {
			continue
		}
		needsOwner[e.ID] = e.Kind == model.ObjectLevel && !e.TenantScoped
		req := RequirementsFor(e, hasTenants)
		if opts.HasLowestRank && (e.Kind != model.ObjectLevel || e.TenantScoped) {
			min, known := e.MinRank, e.MinRankDeclared
			if !known {
				min, known = opts.MinRanks[e.ID]
			}
			if known && min <= opts.LowestRank {
				req = slices.DeleteFunc(slices.Clone(req), func(r model.Relationship) bool { return r == model.RelLowerRole })
			}
		}
		byRel := map[model.Relationship]*cellAcc{}
		var cells []*model.CoverageCell
		for _, rel := range model.Relationships() {
			c := &model.CoverageCell{
				Endpoint: e.ID, Rel: rel, Statuses: map[int]int{},
				Required: slices.Contains(req, rel),
			}
			byRel[rel] = &cellAcc{cell: c, ids: map[string]bool{}, evidence: map[string]bool{}, minConf: model.ConfDeclared}
			cells = append(cells, c)
		}
		accs[e.ID] = byRel
		m.Cells[e.ID] = cells
	}

	counted := map[*cellAcc]bool{}
	for _, o := range obs {
		if o == nil || o.Endpoint == nil {
			continue
		}
		byRel, ok := accs[o.Endpoint.ID]
		if !ok {
			continue
		}
		rel := o.Rel
		if rel == "" {
			rel = model.RelUnknown
		}
		a, ok := byRel[rel]
		if !ok {
			a = byRel[model.RelUnknown]
			rel = model.RelUnknown
		}
		if o.X != nil {
			a.cell.Statuses[o.X.Status]++
			if o.X.Source != "" {
				a.evidence[o.X.Source] = true
			}
		}
		if o.Identity != nil && o.Identity.Name != "" {
			a.ids[o.Identity.Name] = true
		}
		// Anonymous is never the owner (O3), other_tenant decided by a tenant
		// path parameter needs no owner, and a tenant-scoped endpoint has no
		// per-user owner at all (O4).
		byTenantParam := rel == model.RelOtherTenant && o.ObjectTenantKnown
		needOwner := needsOwner[o.Endpoint.ID] && !byTenantParam && rel != model.RelAnonymous
		if rel == model.RelUnknown || o.IDConf < model.ConfLearned || (needOwner && o.OwnerConf < ownerMin) {
			continue
		}
		conf := o.IDConf
		if needOwner {
			conf = min(conf, o.OwnerConf)
		}
		a.minConf = min(a.minConf, conf)
		counted[a] = true
	}

	seen := map[string]bool{}
	for _, e := range eps {
		if seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		for _, rel := range model.Relationships() {
			a := accs[e.ID][rel]
			c := a.cell
			c.Identities = slices.Sorted(mapKeys(a.ids))
			ev := slices.SortedFunc(mapKeys(a.evidence), compareEvidence)
			if len(ev) > MaxEvidence {
				ev = ev[:MaxEvidence]
			}
			c.Evidence = ev
			if counted[a] {
				c.Covered = true
				c.MinConf = a.minConf
			}
			if c.Required {
				m.Summary.Required++
				if c.Covered {
					m.Summary.Covered++
				}
			}
		}
	}
	m.Summary.Gaps = m.Summary.Required - m.Summary.Covered
	if m.Summary.Required > 0 {
		m.Summary.Percent = 100 * float64(m.Summary.Covered) / float64(m.Summary.Required)
	}
	return m
}

func mapKeys[V any](m map[string]V) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// compareEvidence orders "file#index" by file, then numeric index; anything
// without a numeric index sorts after numeric ones and falls back to string
// comparison. It is a total order.
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
