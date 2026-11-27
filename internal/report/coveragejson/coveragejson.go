// Package coveragejson defines the versioned coverage.json report (schema
// authzcov.coverage/v1): Build assembles it from pipeline results, Write and
// Read serialise it deterministically, and ToMatrix rebuilds the matrix so
// `authzcov report` can render the table without reading any input again.
//
// Build is pure: no file IO, no environment, no clock except Input.Now.
// Raw credentials and raw object IDs never enter a Report: identities carry
// 12-hex credential fingerprints and objects carry an 8-hex ID hash.
package coveragejson

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	"authzcov/internal/matrix"
	"authzcov/internal/model"
	"authzcov/internal/ownership"
	"authzcov/internal/relate"
	"authzcov/internal/suspicious"
)

// SchemaV1 is the value of Report.Schema.
const SchemaV1 = "authzcov.coverage/v1"

// Finding kinds, in output order.
const (
	KindGap               = "gap"
	KindSuspiciousAllow   = "suspicious_allow"
	KindUnmatchedRequest  = "unmatched_request"
	KindAmbiguousMatch    = "ambiguous_match"
	KindUndocumentedMeth  = "undocumented_method"
	SeverityError         = "error"
	SeverityNote          = "note"
	SeverityWarning       = "warning"
	WarnConfig            = "config"
	WarnSingleIdentity    = "single_identity_role"
	WarnBasePathLowMatch  = "base_path_low_match"
	BasePathModeAuto      = "auto"
	BasePathModeNone      = "none"
	BasePathModeExplicit  = "explicit"
	EvidenceRefs          = "refs"
	lowMatchRatio         = 0.5
	objectHashHex         = 8
	findingFingerprintHex = 16
)

var kindOrder = []string{KindGap, KindSuspiciousAllow, KindUnmatchedRequest, KindAmbiguousMatch, KindUndocumentedMeth}

// Report is the whole coverage.json document. Field order is output order.
type Report struct {
	Schema      string     `json:"schema"`
	Tool        Tool       `json:"tool"`
	GeneratedAt string     `json:"generated_at"`
	Inputs      Inputs     `json:"inputs"`
	Identities  []Identity `json:"identities"`
	Endpoints   []Endpoint `json:"endpoints"`
	Cells       []Cell     `json:"cells"`
	Objects     []Object   `json:"objects"`
	Findings    []Finding  `json:"findings"`
	Warnings    []Warning  `json:"warnings"`
	Summary     Summary    `json:"summary"`
}

// Tool names the producer.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// Inputs records what the run read.
type Inputs struct {
	Spec       FileRef   `json:"spec"`
	HAR        []HARFile `json:"har"`
	Identities FileRef   `json:"identities"`
	BasePath   BasePath  `json:"base_path"`
	Strict     bool      `json:"strict"`
	Evidence   string    `json:"evidence"`
}

// FileRef is an input file as given on the command line plus its SHA-256.
type FileRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// HARFile is one HAR input; Entries counts kept entries after filtering.
type HARFile struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Entries int    `json:"entries"`
}

// BasePath records the base-path decision. Callers set Mode and Hosts; Build
// derives Value and MatchedRatio.
type BasePath struct {
	Value        string       `json:"value"`
	Mode         string       `json:"mode"`
	MatchedRatio float64      `json:"matched_ratio"`
	Hosts        []HostChoice `json:"hosts"`
}

// HostChoice is the prefix picked for one host.
type HostChoice struct {
	Host    string `json:"host"`
	Prefix  string `json:"prefix"`
	Matched int    `json:"matched"`
	Total   int    `json:"total"`
}

// Identity is one distinct (name, tenant) seen in matched observations.
type Identity struct {
	Name         string   `json:"name"`
	Role         string   `json:"role"`
	Rank         int      `json:"rank"`
	Tenant       string   `json:"tenant"`
	Requests     int      `json:"requests"`
	Fingerprints []string `json:"fingerprints"`
}

// Endpoint is one spec operation.
type Endpoint struct {
	ID             string      `json:"id"`
	Method         string      `json:"method"`
	Template       string      `json:"template"`
	Kind           string      `json:"kind"`
	Resource       string      `json:"resource"`
	ObjectParam    string      `json:"object_param"`
	Public         bool        `json:"public"`
	SpecFile       string      `json:"spec_file"`
	SpecLine       int         `json:"spec_line"`
	Requests       int         `json:"requests"`
	MinAllowedRole *MinAllowed `json:"min_allowed_role,omitempty"`
}

// MinAllowed is the inferred minimum role allowed on a function-level endpoint.
type MinAllowed struct {
	Role       string `json:"role"`
	Confidence string `json:"confidence"`
}

// Cell is one endpoint x relationship cell. Cells are emitted when required or
// observed.
type Cell struct {
	Endpoint      string         `json:"endpoint"`
	Relationship  string         `json:"relationship"`
	Required      bool           `json:"required"`
	Covered       bool           `json:"covered"`
	Statuses      map[string]int `json:"statuses,omitempty"`
	Identities    []string       `json:"identities,omitempty"`
	MinConfidence string         `json:"min_confidence,omitempty"`
	Evidence      []string       `json:"evidence,omitempty"`
	Waiver        *CellWaiver    `json:"waiver,omitempty"`
}

// CellWaiver records the waiver that accepts an uncovered required cell.
type CellWaiver struct {
	Reason  string `json:"reason"`
	Expires string `json:"expires"`
}

// Object is a learned owner claim; the raw object ID is never stored.
type Object struct {
	Resource   string `json:"resource"`
	IDHash     string `json:"id_hash"`
	Owner      string `json:"owner"`
	Tenant     string `json:"tenant"`
	Confidence string `json:"confidence"`
	Source     string `json:"source"`
}

// Finding is one gap or note.
type Finding struct {
	Fingerprint  string   `json:"fingerprint"`
	Kind         string   `json:"kind"`
	Severity     string   `json:"severity"`
	Endpoint     string   `json:"endpoint"`
	Relationship string   `json:"relationship,omitempty"`
	Message      string   `json:"message"`
	Evidence     []string `json:"evidence,omitempty"`
}

// Warning is a run-level caveat.
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Summary totals the run. Percent is covered/(required-waived)*100 rounded to
// one decimal, the same rounding the table prints.
type Summary struct {
	Required         int     `json:"required"`
	Covered          int     `json:"covered"`
	Waived           int     `json:"waived"`
	Percent          float64 `json:"percent"`
	Gaps             int     `json:"gaps"`
	SuspiciousAllows int     `json:"suspicious_allows"`
	UnmatchedReqs    int     `json:"unmatched_requests"`
	AmbiguousMatches int     `json:"ambiguous_matches"`
}

// Shape is a group of identical request shapes ("METHOD /path" with ID-like
// segments replaced) and how many requests had it.
type Shape struct {
	Key   string
	Count int
}

// Input is everything Build needs.
type Input struct {
	Matrix  *matrix.Matrix
	Obs     []*model.Observation
	Objects []ownership.Object
	// Inputs carries paths, hashes, HAR entry counts, the base-path Mode and
	// per-host Hosts; Build fills the derived fields.
	Inputs   Inputs
	Roles    map[string]int   // role name -> rank
	Declared []model.Identity // identities declared in the config
	Warnings []Warning        // e.g. code "config" per config warning
	// Unmatched and MethodMiss group exchanges without an operation by shape.
	Unmatched, MethodMiss []Shape
	Ambiguous             map[string]int // endpoint ID -> ambiguous matches
	// Suspicious are the suspicious_allow findings from suspicious.Find.
	Suspicious []suspicious.Allow
	Tool       Tool
	Now        func() time.Time // nil: Unix epoch
}

// Build assembles the report. Every slice is non-nil and sorted.
func Build(in Input) *Report {
	m := in.Matrix
	if m == nil {
		m = &matrix.Matrix{}
	}
	// Build never reads the wall clock: a nil Now yields the Unix epoch.
	generated := time.Unix(0, 0)
	if in.Now != nil {
		generated = in.Now()
	}
	r := &Report{
		Schema:      SchemaV1,
		Tool:        in.Tool,
		GeneratedAt: generated.UTC().Format(time.RFC3339),
		Inputs:      in.Inputs,
	}
	r.Inputs.Evidence = EvidenceRefs
	r.Inputs.HAR = nonNil(slices.Clone(in.Inputs.HAR))
	r.Inputs.BasePath = basePath(in.Inputs.BasePath)

	r.Identities = identities(in.Obs)
	r.Endpoints = endpoints(m, in.Obs, in.Roles)
	r.Cells = cells(m)
	r.Objects = objects(in.Objects)
	r.Findings = findings(m, in)
	r.Warnings = warnings(in, r.Inputs.BasePath)
	r.Summary = summary(m, in)
	return r
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func basePath(b BasePath) BasePath {
	hosts := nonNil(slices.Clone(b.Hosts))
	slices.SortFunc(hosts, func(x, y HostChoice) int { return cmp.Compare(x.Host, y.Host) })
	b.Hosts = hosts
	var matched, total, best int
	b.Value = ""
	for _, h := range hosts {
		matched += h.Matched
		total += h.Total
		if h.Matched > best { // hosts are sorted, so ties keep the smaller host
			best, b.Value = h.Matched, h.Prefix
		}
	}
	b.MatchedRatio = 0
	if total > 0 {
		b.MatchedRatio = math.Round(100*float64(matched)/float64(total)) / 100
	}
	return b
}

func identities(obs []*model.Observation) []Identity {
	type key struct{ name, tenant string }
	byKey := map[key]*Identity{}
	fps := map[key]map[string]bool{}
	for _, o := range obs {
		if o == nil || o.Identity == nil {
			continue
		}
		id := o.Identity
		k := key{id.Name, id.Tenant}
		e := byKey[k]
		if e == nil {
			e = &Identity{Name: id.Name, Role: id.Role, Rank: id.Rank, Tenant: id.Tenant}
			switch {
			case id.Anonymous:
				e.Role, e.Rank = "anonymous", 0
			case o.IDConf == model.ConfUnknown:
				e.Role, e.Rank = "unknown", -1
			}
			byKey[k] = e
			fps[k] = map[string]bool{}
		}
		e.Requests++
		if o.X != nil && o.X.Cred.Fingerprint != "" {
			fps[k][o.X.Cred.Fingerprint] = true
		}
	}
	out := make([]Identity, 0, len(byKey))
	for k, e := range byKey {
		e.Fingerprints = nonNil(slices.Sorted(keys(fps[k])))
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b Identity) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Tenant, b.Tenant))
	})
	return out
}

func keys[V any](m map[string]V) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func endpoints(m *matrix.Matrix, obs []*model.Observation, roles map[string]int) []Endpoint {
	reqs := map[string]int{}
	for _, o := range obs {
		if o != nil && o.Endpoint != nil {
			reqs[o.Endpoint.ID]++
		}
	}
	minRanks := relate.MinRanks(obs)
	out := make([]Endpoint, 0, len(m.Endpoints))
	seen := map[string]bool{}
	for _, e := range m.Endpoints {
		if e == nil || seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		ep := Endpoint{
			ID: e.ID, Method: e.Method, Template: e.Template, Kind: e.Kind.String(),
			Resource: e.Resource, ObjectParam: e.ObjectParam, SpecFile: e.SpecFile, SpecLine: e.SpecLine,
			Requests: reqs[e.ID],
		}
		if rank, ok := minRanks[e.ID]; ok && e.Kind == model.FunctionLevel {
			if name, ok := roleWithRank(roles, rank); ok {
				ep.MinAllowedRole = &MinAllowed{Role: name, Confidence: model.ConfInferred.String()}
			}
		}
		out = append(out, ep)
	}
	slices.SortFunc(out, func(a, b Endpoint) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

// roleWithRank returns the alphabetically first role with the given rank.
func roleWithRank(roles map[string]int, rank int) (string, bool) {
	best, found := "", false
	for name, r := range roles {
		if r == rank && (!found || name < best) {
			best, found = name, true
		}
	}
	return best, found
}

func cells(m *matrix.Matrix) []Cell {
	out := []Cell{}
	seen := map[string]bool{}
	for _, e := range m.Endpoints {
		if e == nil || seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		for _, c := range m.Cells[e.ID] {
			if c == nil || (!c.Required && len(c.Statuses) == 0) {
				continue
			}
			jc := Cell{
				Endpoint: c.Endpoint, Relationship: string(c.Rel), Required: c.Required, Covered: c.Covered,
				Identities: slices.Clone(c.Identities), Evidence: slices.Clone(c.Evidence),
			}
			if len(c.Statuses) > 0 {
				jc.Statuses = make(map[string]int, len(c.Statuses))
				for s, n := range c.Statuses {
					jc.Statuses[strconv.Itoa(s)] = n
				}
			}
			if c.Covered {
				jc.MinConfidence = c.MinConf.String()
			}
			out = append(out, jc)
		}
	}
	// Endpoint id first; relationship order is model.Relationships() order,
	// which the matrix already uses per endpoint.
	relIdx := map[string]int{}
	for i, rel := range model.Relationships() {
		relIdx[string(rel)] = i
	}
	slices.SortStableFunc(out, func(a, b Cell) int {
		return cmp.Or(cmp.Compare(a.Endpoint, b.Endpoint), cmp.Compare(relIdx[a.Relationship], relIdx[b.Relationship]))
	})
	return out
}

func hashHex(s string, n int) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:n]
}

func objects(objs []ownership.Object) []Object {
	out := make([]Object, 0, len(objs))
	for _, o := range objs {
		if o.Owner == nil {
			continue
		}
		out = append(out, Object{
			Resource: o.Resource, IDHash: hashHex(o.Resource+"/"+o.ID, objectHashHex),
			Owner: o.Owner.Name, Tenant: o.Owner.Tenant, Confidence: o.Conf.String(), Source: o.Source,
		})
	}
	slices.SortFunc(out, func(a, b Object) int {
		return cmp.Or(cmp.Compare(a.Resource, b.Resource), cmp.Compare(a.IDHash, b.IDHash),
			cmp.Compare(a.Owner, b.Owner), cmp.Compare(a.Source, b.Source))
	})
	return out
}

// Fingerprint is the stable ID of a finding.
func Fingerprint(kind, endpoint, relationship string) string {
	return hashHex(kind+"|"+endpoint+"|"+relationship, findingFingerprintHex)
}

func findings(m *matrix.Matrix, in Input) []Finding {
	out := []Finding{}
	add := func(kind, sev, ep, rel, msg string, ev []string) {
		out = append(out, Finding{Fingerprint: Fingerprint(kind, ep, rel), Kind: kind, Severity: sev,
			Endpoint: ep, Relationship: rel, Message: msg, Evidence: slices.Clone(ev)})
	}
	seen := map[string]bool{}
	for _, e := range m.Endpoints {
		if e == nil || seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		for _, c := range m.Cells[e.ID] {
			if c == nil || !c.Required || c.Covered {
				continue
			}
			msg := fmt.Sprintf("%s was never called as %s", c.Endpoint, c.Rel)
			if len(c.Statuses) > 0 {
				msg = fmt.Sprintf("%s was called as %s only with identity or owner evidence too weak to count", c.Endpoint, c.Rel)
			}
			add(KindGap, SeverityError, c.Endpoint, string(c.Rel), msg, c.Evidence)
		}
	}
	for _, a := range in.Suspicious {
		add(KindSuspiciousAllow, SeverityWarning, a.Endpoint, a.Relationship, a.Message, a.Evidence)
	}
	for _, s := range in.Unmatched {
		add(KindUnmatchedRequest, SeverityNote, s.Key, "", fmt.Sprintf("%d requests match no operation in the spec", s.Count), nil)
	}
	for _, s := range in.MethodMiss {
		add(KindUndocumentedMeth, SeverityNote, s.Key, "",
			fmt.Sprintf("%d requests use a method the spec does not document for this path", s.Count), nil)
	}
	for ep, n := range in.Ambiguous {
		if n > 0 {
			add(KindAmbiguousMatch, SeverityNote, ep, "", fmt.Sprintf("%d requests also fit another operation (ambiguous match)", n), nil)
		}
	}
	slices.SortFunc(out, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(slices.Index(kindOrder, a.Kind), slices.Index(kindOrder, b.Kind)),
			cmp.Compare(a.Endpoint, b.Endpoint), cmp.Compare(a.Relationship, b.Relationship))
	})
	return out
}

func warnings(in Input, bp BasePath) []Warning {
	out := slices.Clone(in.Warnings)
	type key struct{ role, tenant string }
	count := map[key]int{}
	for _, id := range in.Declared {
		if !id.Anonymous {
			count[key{id.Role, id.Tenant}]++
		}
	}
	for k, n := range count {
		if n == 1 {
			out = append(out, Warning{WarnSingleIdentity,
				fmt.Sprintf("role %q has exactly one identity in tenant %q: same_role_other_user cannot be covered", k.role, k.tenant)})
		}
	}
	total := 0
	for _, h := range bp.Hosts {
		total += h.Total
	}
	if total > 0 && bp.MatchedRatio < lowMatchRatio {
		out = append(out, Warning{WarnBasePathLowMatch,
			fmt.Sprintf("only %.0f%% of requests matched the spec under the chosen base path", 100*bp.MatchedRatio)})
	}
	slices.SortFunc(out, func(a, b Warning) int {
		return cmp.Or(cmp.Compare(a.Code, b.Code), cmp.Compare(a.Message, b.Message))
	})
	return nonNil(out)
}

// Percent is covered/(required-waived)*100 rounded to one decimal; 0 when the
// denominator is 0. It agrees with the table's %.1f.
func Percent(covered, required, waived int) float64 {
	den := required - waived
	if den <= 0 {
		return 0
	}
	p, _ := strconv.ParseFloat(strconv.FormatFloat(100*float64(covered)/float64(den), 'f', 1, 64), 64)
	return p
}

func summary(m *matrix.Matrix, in Input) Summary {
	s := Summary{Required: m.Summary.Required, Covered: m.Summary.Covered, Gaps: m.Summary.Required - m.Summary.Covered}
	s.Percent = Percent(s.Covered, s.Required, 0)
	s.SuspiciousAllows = len(in.Suspicious)
	for _, sh := range in.Unmatched {
		s.UnmatchedReqs += sh.Count
	}
	for _, n := range in.Ambiguous {
		s.AmbiguousMatches += n
	}
	return s
}

// ObjectHash is the id_hash of an object: the first 8 hex of SHA-256 of
// "resource/id". Callers that hold a raw ID (an opt-in re-run of the pipeline)
// use it to match coverage.json objects; the raw ID itself is never written.
func ObjectHash(resource, id string) string { return hashHex(resource+"/"+id, objectHashHex) }
