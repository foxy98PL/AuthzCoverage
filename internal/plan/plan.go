// Package plan turns the gaps of a coverage.json into a versioned probe plan
// (schema authzcov.plan, version 1) that another authorization tester can
// execute. Build is pure: no file IO, no clock, no environment.
//
// A plan never contains credentials: an attacker is an identity NAME from
// identities.yaml. Raw object IDs appear only when the caller supplies them
// through Raw (an opt-in re-run of the pipeline); coverage.json itself stores
// only id_hash.
package plan

import (
	"cmp"
	"slices"
	"strings"

	"authzcov/internal/model"
	"authzcov/internal/report/coveragejson"
)

// Version is the value of Plan.PlanVersion.
const Version = 1

// Expected outcomes.
const (
	ExpectDeny   = "deny"
	ExpectAllow  = "allow"
	ExpectPolicy = "policy" // either outcome is legitimate; the application's policy decides
)

// Notes on probes without an attacker.
const (
	NoteNoIdentity = "no identity with this relationship was seen"
	NoteNoObject   = "no object with a known owner was seen for this resource"
	NoteNoMinRole  = "no minimum allowed role was inferred for this endpoint"
	// HintResolveIDs is set on probes with an object in a hash-only plan.
	HintResolveIDs = "raw ID omitted; re-run with --har --spec --identities --out <file> to resolve id_hash"
	// NoteIDNotFound is set in raw mode when the HAR does not hold the object's hash.
	NoteIDNotFound = "id_hash not found in the given --har; raw ID left empty (the HAR differs from the one coverage.json was built from)"
)

// Plan is the whole plan document. Field order is output order.
type Plan struct {
	PlanVersion    int               `json:"plan_version"`
	Tool           coveragejson.Tool `json:"tool"`
	GeneratedAt    string            `json:"generated_at"`
	Source         Source            `json:"source"`
	ContainsRawIDs bool              `json:"contains_raw_ids"`
	Probes         []Probe           `json:"probes"`
}

// Source identifies the coverage.json the plan was derived from.
type Source struct {
	CoverageSHA256 string `json:"coverage_sha256"`
	GeneratedAt    string `json:"generated_at"`
}

// Probe is one request an authorization tester should send and judge.
type Probe struct {
	ID           string            `json:"id"`
	Endpoint     string            `json:"endpoint"`
	Method       string            `json:"method"`
	PathTemplate string            `json:"path_template"`
	Relationship string            `json:"relationship"`
	Attacker     *Attacker         `json:"attacker"`
	Object       *Object           `json:"object,omitempty"`
	Expect       string            `json:"expect"`
	PathParams   map[string]string `json:"path_params,omitempty"`
	Waived       bool              `json:"waived,omitempty"`
	Note         string            `json:"note,omitempty"`
}

// Attacker names the identity that sends the probe. Never a credential.
type Attacker struct {
	Identity string `json:"identity"`
	Role     string `json:"role"`
	Tenant   string `json:"tenant,omitempty"`
}

// Object is the victim object a probe addresses.
type Object struct {
	Resource string `json:"resource"`
	Param    string `json:"param"`
	IDHash   string `json:"id_hash,omitempty"`
	ID       string `json:"id,omitempty"` // raw; only in raw mode
	Owner    string `json:"owner,omitempty"`
	Tenant   string `json:"tenant,omitempty"`
}

// Raw carries what only a re-run of the pipeline knows.
type Raw struct {
	// IDs maps resource+"/"+id_hash to the raw object ID seen in the recording.
	IDs map[string]string
	// TenantParams are the path parameters that hold the object's tenant
	// (identities.yaml tenancy.tenant_params).
	TenantParams map[string]bool
	// Declared are identities from identities.yaml, used when coverage.json
	// has no observation for them.
	Declared []coveragejson.Identity
}

// Options control Build.
type Options struct {
	IncludeWaived bool
	Raw           *Raw // nil: no raw IDs
}

// Build derives the plan from r. GeneratedAt and the coverage hash are the
// caller's: they come from the clock and the file bytes.
func Build(r *coveragejson.Report, opt Options) *Plan {
	p := &Plan{PlanVersion: Version, Tool: r.Tool, ContainsRawIDs: opt.Raw != nil, Probes: []Probe{}}
	p.Source.GeneratedAt = r.GeneratedAt
	ids := candidates(r, opt.Raw)
	eps := map[string]coveragejson.Endpoint{}
	for _, e := range r.Endpoints {
		eps[e.ID] = e
	}
	ranks := roleRanks(ids)
	for _, c := range r.Cells {
		if !c.Required || c.Covered || (c.Waiver != nil && !opt.IncludeWaived) {
			continue
		}
		ep, ok := eps[c.Endpoint]
		if !ok {
			continue
		}
		p.Probes = append(p.Probes, probe(ep, c, r.Objects, ids, ranks, opt.Raw))
	}
	relIdx := map[string]int{}
	for i, rel := range model.Relationships() {
		relIdx[string(rel)] = i
	}
	slices.SortStableFunc(p.Probes, func(a, b Probe) int {
		return cmp.Or(cmp.Compare(a.Endpoint, b.Endpoint), cmp.Compare(relIdx[a.Relationship], relIdx[b.Relationship]),
			cmp.Compare(attackerName(a), attackerName(b)))
	})
	return p
}

func attackerName(p Probe) string {
	if p.Attacker == nil {
		return ""
	}
	return p.Attacker.Identity
}

// candidates are the real (named, non-anonymous, known-role) identities,
// sorted by name then tenant. Observed identities win over declared ones.
func candidates(r *coveragejson.Report, raw *Raw) []coveragejson.Identity {
	var out []coveragejson.Identity
	seen := map[string]bool{}
	add := func(id coveragejson.Identity) {
		if id.Name == "anonymous" || strings.HasPrefix(id.Name, "unknown-") || id.Role == "unknown" || id.Role == "anonymous" {
			return
		}
		out = append(out, id)
		seen[id.Name] = true
	}
	for _, id := range r.Identities {
		add(id)
	}
	if raw != nil {
		for _, id := range raw.Declared {
			if !seen[id.Name] {
				add(id)
			}
		}
	}
	slices.SortFunc(out, func(a, b coveragejson.Identity) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Tenant, b.Tenant))
	})
	return out
}

func roleRanks(ids []coveragejson.Identity) map[string]int {
	m := map[string]int{}
	for _, id := range ids {
		m[id.Role] = id.Rank
	}
	return m
}

func probe(ep coveragejson.Endpoint, c coveragejson.Cell, objs []coveragejson.Object, ids []coveragejson.Identity,
	ranks map[string]int, raw *Raw) Probe {
	p := Probe{
		ID: coveragejson.Fingerprint("probe", c.Endpoint, c.Relationship), Endpoint: ep.ID, Method: ep.Method,
		PathTemplate: ep.Template, Relationship: c.Relationship, Expect: expect(ep, c.Relationship), Waived: c.Waiver != nil,
	}
	var cands []coveragejson.Object
	if ep.Kind == "object" {
		for _, o := range objs {
			if o.Resource == ep.Resource && o.Owner != "" {
				cands = append(cands, o)
			}
		}
		p.Object = &Object{Resource: ep.Resource, Param: ep.ObjectParam}
	}
	if c.Relationship == string(model.RelAnonymous) {
		p.Attacker = &Attacker{Identity: "anonymous", Role: "anonymous"}
		if len(cands) > 0 {
			setObject(&p, ep, cands[0], raw)
		}
		return p
	}
	if ep.Kind == "object" {
		if len(cands) == 0 {
			p.Note = NoteNoObject
			return p
		}
		for _, o := range cands {
			if a := pickObject(c.Relationship, o, ids); a != nil {
				p.Attacker = &Attacker{Identity: a.Name, Role: a.Role, Tenant: a.Tenant}
				setObject(&p, ep, o, raw)
				return p
			}
		}
		p.Note = NoteNoIdentity
		return p
	}
	// Function-level: relationships are relative to the minimum allowed role.
	if ep.MinAllowedRole == nil {
		p.Note = NoteNoMinRole
		return p
	}
	min, ok := ranks[ep.MinAllowedRole.Role]
	if !ok {
		p.Note = NoteNoIdentity
		return p
	}
	for _, a := range ids {
		if rankRel(c.Relationship, a.Rank, min) {
			p.Attacker = &Attacker{Identity: a.Name, Role: a.Role, Tenant: a.Tenant}
			return p
		}
	}
	p.Note = NoteNoIdentity
	return p
}

func setObject(p *Probe, ep coveragejson.Endpoint, o coveragejson.Object, raw *Raw) {
	p.Object.IDHash, p.Object.Owner, p.Object.Tenant = o.IDHash, o.Owner, o.Tenant
	if raw == nil {
		if o.IDHash != "" && p.Note == "" {
			p.Note = HintResolveIDs
		}
		return
	}
	// Never fall back to another object of the same resource: a wrong object
	// would turn into a false "deny" result.
	if id, ok := raw.IDs[o.Resource+"/"+o.IDHash]; ok {
		p.Object.ID = id
	} else if o.IDHash != "" && p.Note == "" {
		p.Note = NoteIDNotFound
	}
	if o.Tenant == "" {
		return
	}
	for _, name := range pathParams(ep.Template) {
		if name != ep.ObjectParam && raw.TenantParams[name] {
			if p.PathParams == nil {
				p.PathParams = map[string]string{}
			}
			p.PathParams[name] = o.Tenant
		}
	}
}

// pathParams lists the {name} segments of a template in order.
func pathParams(tpl string) []string {
	var out []string
	for _, seg := range strings.Split(tpl, "/") {
		if len(seg) > 2 && seg[0] == '{' && seg[len(seg)-1] == '}' {
			out = append(out, seg[1:len(seg)-1])
		}
	}
	return out
}

func rankRel(rel string, rank, ref int) bool {
	switch model.Relationship(rel) {
	case model.RelOwner:
		return rank == ref
	case model.RelLowerRole:
		return rank < ref
	case model.RelHigherRole:
		return rank > ref
	}
	return false
}

// pickObject returns the first identity (sorted) that has relationship rel to
// the object, mirroring relate.Classify: a different tenant wins over rank.
func pickObject(rel string, o coveragejson.Object, ids []coveragejson.Identity) *coveragejson.Identity {
	var owner *coveragejson.Identity
	for i := range ids {
		if ids[i].Name == o.Owner {
			owner = &ids[i]
			break
		}
	}
	for i := range ids {
		a := &ids[i]
		otherTenant := a.Tenant != "*" && a.Tenant != o.Tenant
		var ok bool
		switch model.Relationship(rel) {
		case model.RelOwner:
			ok = a.Name == o.Owner
		case model.RelOtherTenant:
			ok = otherTenant
		case model.RelSameRoleOtherUser:
			ok = !otherTenant && owner != nil && a.Name != o.Owner && a.Rank == owner.Rank
		case model.RelLowerRole:
			ok = !otherTenant && owner != nil && a.Rank < owner.Rank
		case model.RelHigherRole:
			ok = !otherTenant && owner != nil && a.Rank > owner.Rank
		}
		if ok {
			return a
		}
	}
	return nil
}

func expect(ep coveragejson.Endpoint, rel string) string {
	switch model.Relationship(rel) {
	case model.RelOwner:
		return ExpectAllow
	case model.RelHigherRole:
		if ep.Kind == "object" {
			return ExpectPolicy
		}
		return ExpectAllow
	}
	return ExpectDeny
}
