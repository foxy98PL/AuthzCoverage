// Package model holds the structs shared by all pipeline stages. Stdlib only.
package model

import (
	"slices"
	"strconv"
)

// Confidence orders how sure we are about an identity or owner.
// Order matters: ConfUnknown < ConfInferred < ConfLearned < ConfDeclared.
type Confidence uint8

const (
	ConfUnknown Confidence = iota
	ConfInferred
	ConfLearned
	ConfDeclared
)

func (c Confidence) String() string {
	switch c {
	case ConfInferred:
		return "inferred"
	case ConfLearned:
		return "learned"
	case ConfDeclared:
		return "declared"
	default:
		return "unknown"
	}
}

// EndpointKind says whether an endpoint addresses a single object.
type EndpointKind uint8

const (
	FunctionLevel EndpointKind = iota
	ObjectLevel
)

func (k EndpointKind) String() string {
	if k == ObjectLevel {
		return "object"
	}
	return "function"
}

// Endpoint is one OpenAPI operation.
type Endpoint struct {
	ID       string // "GET /books/v1/{book_title}"
	Method   string // upper-case
	Template string // path template as written in the spec
	Params   []string
	// QueryParams are the declared in:query parameter names (path item and
	// operation level), sorted.
	QueryParams []string
	ObjectParam string // last path param; "" => FunctionLevel
	Resource    string // literal segment before ObjectParam, as written
	// ObjectInQuery is true when ObjectParam is a declared query parameter
	// (requirements.overrides) instead of a path parameter. Its value comes
	// from the request query only when exactly one plain value is present.
	ObjectInQuery bool
	Kind          EndpointKind
	SpecFile      string
	SpecLine      int // line of the path key; 0 if unknown

	// AuthRequired is true when the operation's effective OpenAPI security
	// requires authentication (operation security overrides the global one;
	// none, [] or an empty requirement object means public).
	AuthRequired bool
	// TenantScoped is true when ObjectParam is a tenancy.tenant_params
	// parameter (e.g. /orgs/{orgId}/orders): the tenant is the object, so no
	// per-user owner exists. Set from the config after the spec is loaded.
	TenantScoped bool
	// MinRankDeclared is true when requirements.overrides[].min_role declares
	// the minimum allowed role; MinRank is its rank and replaces the learned
	// minimum.
	MinRankDeclared bool
	MinRank         int
	MinRole         string
}

// Credential is a redacted credential: never holds the raw value.
type Credential struct {
	Kind        string
	Fingerprint string
	Claims      map[string]any
}

// Identity is a named caller.
type Identity struct {
	Name      string
	Role      string
	Tenant    string
	Subject   string
	Rank      int
	Anonymous bool
}

// Exchange is one recorded request/response after ingest and redaction.
type Exchange struct {
	Source   string // "file.har#index"
	Method   string
	Host     string
	Path     string // escaped path
	Cred     Credential
	Status   int
	ReqJSON  []byte
	RespJSON []byte
	// Query holds the decoded values of the query keys named in
	// har.Options.QueryKeys only (every other key is dropped at ingest).
	Query map[string][]string
}

// Relationship between caller and object owner (or minimum allowed role).
type Relationship string

const (
	RelOwner             Relationship = "owner"
	RelSameRoleOtherUser Relationship = "same_role_other_user"
	RelLowerRole         Relationship = "lower_role"
	RelHigherRole        Relationship = "higher_role"
	RelOtherTenant       Relationship = "other_tenant"
	RelAnonymous         Relationship = "anonymous"
	RelUnknown           Relationship = "unknown"
)

// Relationships lists all relationships in the fixed output order.
func Relationships() []Relationship {
	return []Relationship{
		RelOwner, RelSameRoleOtherUser, RelLowerRole, RelHigherRole,
		RelOtherTenant, RelAnonymous, RelUnknown,
	}
}

// Observation is one classified exchange. Fields are ordered to keep the
// struct small: a run holds one Observation per matched request.
type Observation struct {
	// X may be shared between observations that agree on every field a later
	// stage reads (see Source for the per-request source label).
	X        *Exchange
	Endpoint *Endpoint
	Identity *Identity
	Owner    *Identity
	// Params holds the parameter values, parallel to Endpoint.Params (plus the
	// query-bound object parameter last, when the endpoint has one that is
	// not a path parameter). "" means the request did not bind it. Read it
	// with Param.
	Params []string
	Rel    Relationship
	// ObjectTenant is that tenant value (set only with ObjectTenantKnown).
	ObjectTenant string
	// SrcLabel and SrcIdx rebuild the "file.har#index" source when X is shared
	// (nil SrcLabel means use X.Source); SrcIdx < 0 means the label alone.
	SrcLabel  *string
	SrcIdx    int32
	IDConf    Confidence
	OwnerConf Confidence
	// ObjectTenantKnown is true when the object's tenant came from a tenant
	// path parameter, so other_tenant needs no known owner.
	ObjectTenantKnown bool
}

// ParamCount is the number of values an observation of ep carries.
func ParamCount(ep *Endpoint) int {
	n := len(ep.Params)
	if ep.ObjectInQuery && !slices.Contains(ep.Params, ep.ObjectParam) {
		n++
	}
	return n
}

// Param returns the value of the named parameter, or "".
func (o *Observation) Param(name string) string {
	if o.Endpoint == nil {
		return ""
	}
	if i := slices.Index(o.Endpoint.Params, name); i >= 0 {
		if i < len(o.Params) {
			return o.Params[i]
		}
		return ""
	}
	if o.Endpoint.ObjectInQuery && name == o.Endpoint.ObjectParam {
		if i := len(o.Endpoint.Params); i < len(o.Params) {
			return o.Params[i]
		}
	}
	return ""
}

// Source returns the "file.har#index" label of the request, or "".
func (o *Observation) Source() string {
	if o.SrcLabel != nil {
		if o.SrcIdx < 0 {
			return *o.SrcLabel
		}
		return *o.SrcLabel + "#" + strconv.Itoa(int(o.SrcIdx))
	}
	if o.X != nil {
		return o.X.Source
	}
	return ""
}

// CoverageCell is one endpoint x relationship cell of the matrix.
type CoverageCell struct {
	Endpoint   string
	Rel        Relationship
	Required   bool
	Covered    bool
	Statuses   map[int]int
	Identities []string
	Evidence   []string
	MinConf    Confidence
}
