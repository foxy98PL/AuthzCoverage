package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"authzcov/internal/basepath"
	"authzcov/internal/config"
	"authzcov/internal/identity"
	"authzcov/internal/ingest/har"
	"authzcov/internal/match"
	"authzcov/internal/matrix"
	"authzcov/internal/model"
	"authzcov/internal/ownership"
	"authzcov/internal/redact"
	"authzcov/internal/relate"
	"authzcov/internal/report/coveragejson"
	"authzcov/internal/report/table"
	"authzcov/internal/spec"
	"authzcov/internal/suspicious"
	"authzcov/internal/waivers"
)

// matchStats counts how recorded exchanges mapped onto the spec.
type matchStats struct {
	matched, unmatched, methodMiss, ambiguous int
	droppedHosts                              int
	unmatchedX                                []*model.Exchange // kept exchanges that got no endpoint (incl. method misses), for grouping
	methodMissX                               []*model.Exchange // the method-miss subset of unmatchedX
	ambiguousBy                               map[string]int    // endpoint ID -> ambiguous matches
}

// analysis is the result of the offline pipeline before any output is written.
type analysis struct {
	cfg       *config.File
	ws        []waivers.Waiver
	endpoints []*model.Endpoint
	obs       []*model.Observation
	objects   []ownership.Object
	allows    []suspicious.Allow
	m         *matrix.Matrix
	ms        matchStats
	choices   []basepath.Choice
	perFile   []har.Stats
}

// analyze runs the whole offline pipeline (config, spec, HARs, ownership,
// matrix) and writes only diagnostics to stderr. runCoverage and
// `export --plan --har` both use it.
func analyze(o *coverageOpts, stderr io.Writer) (*analysis, error) {
	cfg, err := config.Load(o.identities)
	if err != nil {
		return nil, usageErr(err)
	}
	ws, err := loadWaivers(o.waivers, o.waiversExplicit)
	if err != nil {
		return nil, err
	}
	endpoints, err := spec.Load(o.spec)
	if err != nil {
		return nil, inputErr(err)
	}
	endpoints, err = applyOverrides(cfg, endpoints)
	if err != nil {
		return nil, usageErr(err)
	}
	trie, byID, err := buildTrie(endpoints, o.spec)
	if err != nil {
		return nil, inputErr(err)
	}
	resolver := newResolver(cfg)
	extract := identity.NewExtractor(credSpecs(cfg))

	exchanges, perFile, err := readHARsByFile(o.hars, extract)
	if err != nil {
		return nil, inputErr(err)
	}
	hs := sumStats(perFile)
	for _, w := range cfg.Warnings() {
		_, _ = fmt.Fprintf(stderr, "warning: %s\n", redact.StripControl(w))
	}
	exchanges, choices, droppedHosts := applyBasePath(exchanges, trie, o.basePath, stderr)
	obs, ms := matchExchanges(exchanges, trie, byID)
	learnTokens(cfg, resolver, obs)
	resolveAll(resolver, obs)
	applyJWTTenant(cfg, obs)
	ms.droppedHosts = droppedHosts
	writeSummary(stderr, len(o.hars), &hs, ms)
	writeUnmatched(stderr, ms.unmatchedX)
	if len(obs) == 0 {
		return nil, inputErr(errors.New("no recorded request matched the spec (check --base-path and --spec)"))
	}

	objects := classify(cfg, obs)
	allows := suspicious.Find(obs)
	m := matrix.BuildWith(endpoints, obs, cfg.HasTenants(), matrix.Options{Strict: o.strict})
	return &analysis{cfg: cfg, ws: ws, endpoints: endpoints, obs: obs, objects: objects, allows: allows,
		m: m, ms: ms, choices: choices, perFile: perFile}, nil
}

// runCoverage executes the whole offline pipeline, writes the table to stdout
// and (unless --out is empty) coverage.json to the output directory.
func runCoverage(o *coverageOpts, stdout, stderr io.Writer) error {
	a, err := analyze(o, stderr)
	if err != nil {
		return err
	}
	cfg, m, obs, objects, allows, ms, choices, perFile, ws := a.cfg, a.m, a.obs, a.objects, a.allows, a.ms, a.choices, a.perFile, a.ws
	if o.out != "" {
		in, err := reportInput(o, cfg, m, obs, objects, allows, ms, choices, perFile)
		if err != nil {
			return inputErr(err)
		}
		rep := coveragejson.Build(in)
		if len(ws) > 0 {
			waivers.Apply(rep, ws, today())
		}
		path, err := writeCoverageJSON(o.out, rep)
		if err != nil {
			return &exitError{code: ExitInternal, err: err}
		}
		_, _ = fmt.Fprintf(stderr, "wrote %s\n", redact.StripControl(path))
	}
	if err := table.RenderWith(redact.NewWriter(stdout), m, table.Options{SuspiciousAllows: len(allows)}); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

// reportInput gathers what coveragejson.Build needs.
func reportInput(o *coverageOpts, cfg *config.File, m *matrix.Matrix, obs []*model.Observation,
	objects []ownership.Object, allows []suspicious.Allow, ms matchStats, choices []basepath.Choice, perFile []har.Stats) (coveragejson.Input, error) {
	specSum, err := fileSHA256(o.spec)
	if err != nil {
		return coveragejson.Input{}, err
	}
	idsSum, err := fileSHA256(o.identities)
	if err != nil {
		return coveragejson.Input{}, err
	}
	hars := make([]coveragejson.HARFile, len(o.hars))
	for i, p := range o.hars {
		sum, err := fileSHA256(p)
		if err != nil {
			return coveragejson.Input{}, err
		}
		hars[i] = coveragejson.HARFile{Path: p, SHA256: sum, Entries: perFile[i].Kept}
	}
	mode := coveragejson.BasePathModeExplicit
	switch o.basePath {
	case basePathAuto:
		mode = coveragejson.BasePathModeAuto
	case basePathNone:
		mode = coveragejson.BasePathModeNone
	}
	hosts := make([]coveragejson.HostChoice, len(choices))
	for i, c := range choices {
		hosts[i] = coveragejson.HostChoice{Host: c.Host, Prefix: c.Prefix, Matched: c.Matched, Total: c.Total}
	}
	declared := make([]model.Identity, len(cfg.Identities))
	for i, id := range cfg.Identities {
		declared[i] = model.Identity{Name: id.Name, Role: id.Role, Tenant: id.Tenant, Rank: cfg.Roles[id.Role]}
	}
	// cfg.Warnings() only reports single-identity roles today, which
	// coveragejson already emits as single_identity_role; passing them as
	// "config" too would duplicate them. Add other config warnings here.
	var warns []coveragejson.Warning
	return coveragejson.Input{
		Matrix: m, Obs: obs, Objects: objects, Suspicious: allows,
		Inputs: coveragejson.Inputs{
			Spec: coveragejson.FileRef{Path: o.spec, SHA256: specSum}, HAR: hars,
			Identities: coveragejson.FileRef{Path: o.identities, SHA256: idsSum},
			BasePath:   coveragejson.BasePath{Mode: mode, Hosts: hosts}, Strict: o.strict,
		},
		Roles: cfg.Roles, Declared: declared, Warnings: warns,
		Unmatched: groupShapes(excludeX(ms.unmatchedX, ms.methodMissX)), MethodMiss: groupShapes(ms.methodMissX),
		Ambiguous: ms.ambiguousBy,
		Tool:      coveragejson.Tool{Name: "authzcov", Version: version, Commit: commit},
		Now:       clock(),
	}, nil
}

// excludeX returns all without the exchanges in drop (pointer identity).
func excludeX(all, drop []*model.Exchange) []*model.Exchange {
	skip := make(map[*model.Exchange]bool, len(drop))
	for _, x := range drop {
		skip[x] = true
	}
	var out []*model.Exchange
	for _, x := range all {
		if !skip[x] {
			out = append(out, x)
		}
	}
	return out
}

// clock returns the report clock: SOURCE_DATE_EPOCH (unix seconds) when set
// and valid, else the wall clock.
func clock() func() time.Time {
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			return func() time.Time { return time.Unix(n, 0) }
		}
	}
	return time.Now
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // path is a user-supplied CLI argument
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeCoverageJSON writes dir/coverage.json via a temp file and rename, and
// returns the final path.
func writeCoverageJSON(dir string, r *coveragejson.Report) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // report directory is meant to be readable
		return "", fmt.Errorf("create output directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".coverage-*.json")
	if err != nil {
		return "", fmt.Errorf("write coverage.json: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if err := coveragejson.Write(tmp, r); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("write coverage.json: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil { //nolint:gosec // report is meant to be readable
		_ = tmp.Close()
		return "", fmt.Errorf("write coverage.json: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("write coverage.json: %w", err)
	}
	path := filepath.Join(dir, "coverage.json")
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", fmt.Errorf("write coverage.json: %w", err)
	}
	return path, nil
}

func newResolver(cfg *config.File) *identity.Resolver {
	rules := make([]identity.Rule, 0, len(cfg.Identities))
	for _, id := range cfg.Identities {
		rules = append(rules, identity.Rule{
			Identity: model.Identity{Name: id.Name, Role: id.Role, Tenant: id.Tenant, Rank: cfg.Roles[id.Role]},
			JWT:      id.JWT, TokenFP: id.TokenFP, BasicUser: id.BasicUser, Login: id.Login,
		})
	}
	return identity.NewResolver(rules, cfg.JWTSubject)
}

func credSpecs(cfg *config.File) []identity.CredSpec {
	specs := make([]identity.CredSpec, 0, len(cfg.Credentials))
	for _, c := range cfg.Credentials {
		specs = append(specs, identity.CredSpec{Type: c.Type, Header: c.Header, Schemes: c.Schemes, Name: c.Name})
	}
	return specs
}

// learnTokens is pass 1a: every login exchange binds a token fingerprint to an
// identity. It runs over all matched exchanges before any resolution so HAR
// order cannot matter.
func learnTokens(cfg *config.File, r *identity.Resolver, obs []*model.Observation) {
	for _, lt := range cfg.LearnTokens {
		rule := identity.LoginRule{Method: lt.Method, Path: lt.Path, LoginField: lt.IdentityFromRequestJSON, TokenField: lt.TokenFromResponseJSON}
		for _, o := range obs {
			if fp, login, ok := identity.LoginToken(rule, o.X, o.Endpoint.Template); ok {
				r.LearnToken(fp, login)
			}
		}
	}
}

func resolveAll(r *identity.Resolver, obs []*model.Observation) {
	for _, o := range obs {
		o.Identity, o.IDConf = r.Resolve(o.X.Cred)
	}
}

// applyJWTTenant sets the caller tenant from the jwt.tenant claim for every
// resolved identity that declares no tenant. It works on copies: identities
// from the resolver are shared and must not be mutated.
func applyJWTTenant(cfg *config.File, obs []*model.Observation) {
	if cfg.JWTTenant == "" {
		return
	}
	type ck struct {
		id     *model.Identity
		tenant string
	}
	copies := map[ck]*model.Identity{}
	for _, o := range obs {
		id := o.Identity
		if id == nil || id.Anonymous || id.Tenant != "" || o.IDConf == model.ConfUnknown {
			continue
		}
		t, ok := claimPathString(o.X.Cred.Claims, cfg.JWTTenant)
		if !ok {
			continue
		}
		cp := copies[ck{id, t}]
		if cp == nil {
			c := *id
			c.Tenant = t
			cp = &c
			copies[ck{id, t}] = cp
		}
		o.Identity = cp
	}
}

// claimPathString follows a dot path through decoded claims and returns a
// non-empty string value.
func claimPathString(claims map[string]any, path string) (string, bool) {
	var v any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return "", false
		}
		if v, ok = m[part]; !ok {
			return "", false
		}
	}
	s, ok := v.(string)
	return s, ok && s != ""
}

// applyOverrides returns endpoints with requirements.overrides applied to
// copies: the chosen param becomes the object param and the resource is the
// literal segment before it.
func applyOverrides(cfg *config.File, endpoints []*model.Endpoint) ([]*model.Endpoint, error) {
	if len(cfg.Overrides) == 0 {
		return endpoints, nil
	}
	out := slices.Clone(endpoints)
	for _, ov := range cfg.Overrides {
		i := slices.IndexFunc(out, func(e *model.Endpoint) bool { return e.ID == ov.Endpoint })
		if i < 0 {
			return nil, fmt.Errorf("%s:%d: requirements.overrides: endpoint %q is not in the spec", cfg.Path, ov.Line, redact.StripControl(ov.Endpoint))
		}
		if !slices.Contains(out[i].Params, ov.ObjectParam) {
			return nil, fmt.Errorf("%s:%d: requirements.overrides: object_param %q is not a path parameter of %q (parameters: %s)",
				cfg.Path, ov.Line, redact.StripControl(ov.ObjectParam), redact.StripControl(ov.Endpoint), strings.Join(out[i].Params, ", "))
		}
		cp := *out[i]
		cp.ObjectParam = ov.ObjectParam
		cp.Kind = model.ObjectLevel
		cp.Resource = ""
		segs := strings.Split(strings.Trim(cp.Template, "/"), "/")
		for j, sg := range segs {
			if sg == "{"+ov.ObjectParam+"}" && j > 0 && !strings.HasPrefix(segs[j-1], "{") {
				cp.Resource = segs[j-1]
			}
		}
		out[i] = &cp
	}
	return out, nil
}

func buildTrie(endpoints []*model.Endpoint, specPath string) (*match.Trie, map[string]*model.Endpoint, error) {
	trie := match.New()
	byID := make(map[string]*model.Endpoint, len(endpoints))
	for _, ep := range endpoints {
		if err := trie.Add(ep.Method, ep.Template, ep.ID); err != nil {
			return nil, nil, fmt.Errorf("spec %s: %w", specPath, err)
		}
		byID[ep.ID] = ep
	}
	return trie, byID, nil
}

// readHARs reads every HAR file and accumulates one Stats.
func readHARs(paths []string, extract har.Extractor, st *har.Stats) ([]*model.Exchange, error) {
	xs, perFile, err := readHARsByFile(paths, extract)
	if err != nil {
		return nil, err
	}
	*st = sumStats(perFile)
	return xs, nil
}

// readHARsByFile reads every HAR file and returns one Stats per path.
func readHARsByFile(paths []string, extract har.Extractor) ([]*model.Exchange, []har.Stats, error) {
	var all []*model.Exchange
	perFile := make([]har.Stats, len(paths))
	mk := func(label string) har.Options { return har.Options{Source: label, Extract: extract} }
	for i, p := range paths {
		for x, err := range har.ExchangesFromFile(p, mk, &perFile[i]) {
			if err != nil {
				return nil, nil, err
			}
			all = append(all, x)
		}
	}
	return all, perFile, nil
}

func sumStats(per []har.Stats) har.Stats {
	var t har.Stats
	for _, s := range per {
		t.Entries += s.Entries
		t.Kept += s.Kept
		t.Static += s.Static
		t.Options += s.Options
		t.Status0 += s.Status0
		t.BadURL += s.BadURL
		t.BodyTooLarge += s.BodyTooLarge
	}
	return t
}

// applyBasePath strips the chosen per-host prefix from every exchange path
// (on copies) and drops hosts where nothing matches. It reports one line per
// host on w and returns the exchanges to match, the per-host choices and the
// number of dropped hosts.
func applyBasePath(xs []*model.Exchange, trie *match.Trie, mode string, w io.Writer) ([]*model.Exchange, []basepath.Choice, int) {
	var choices []basepath.Choice
	if mode == basePathAuto {
		choices = basepath.Detect(xs, trie)
	} else {
		prefix := mode
		if mode == basePathNone {
			prefix = ""
		}
		choices = fixedChoices(xs, trie, prefix)
	}
	byHost := make(map[string]basepath.Choice, len(choices))
	dropped := 0
	for _, c := range choices {
		byHost[c.Host] = c
		pct := 0.0
		if c.Total > 0 {
			pct = 100 * float64(c.Matched) / float64(c.Total)
		}
		_, _ = fmt.Fprintf(w, "base path for %s: %q (matched %d/%d, %.1f%%)\n", redact.StripControl(c.Host), redact.StripControl(c.Prefix), c.Matched, c.Total, pct)
		if c.Matched == 0 {
			dropped++
		}
	}
	out := make([]*model.Exchange, 0, len(xs))
	for _, x := range xs {
		c := byHost[x.Host]
		if c.Matched == 0 {
			continue
		}
		if rest, ok := basepath.Strip(x.Path, c.Prefix); ok {
			cp := *x
			cp.Path = rest
			out = append(out, &cp)
		} else {
			out = append(out, x) // not under the prefix: stays unmatched
		}
	}
	return out, choices, dropped
}

// fixedChoices scores one prefix on every host.
func fixedChoices(xs []*model.Exchange, trie *match.Trie, prefix string) []basepath.Choice {
	byHost := map[string]*basepath.Choice{}
	for _, x := range xs {
		c := byHost[x.Host]
		if c == nil {
			c = &basepath.Choice{Host: x.Host, Prefix: prefix}
			byHost[x.Host] = c
		}
		c.Total++
		if rest, ok := basepath.Strip(x.Path, prefix); ok && trie.Match(x.Method, rest).Op != nil {
			c.Matched++
		}
	}
	out := make([]basepath.Choice, 0, len(byHost))
	for _, c := range byHost {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

func matchExchanges(xs []*model.Exchange, trie *match.Trie, byID map[string]*model.Endpoint) ([]*model.Observation, matchStats) {
	var ms matchStats
	var obs []*model.Observation
	for _, x := range xs {
		res := trie.Match(x.Method, x.Path)
		if res.Op == nil {
			if res.MethodMiss {
				ms.methodMiss++
				ms.methodMissX = append(ms.methodMissX, x)
			} else {
				ms.unmatched++
			}
			ms.unmatchedX = append(ms.unmatchedX, x)
			continue
		}
		ep := byID[res.Op.ID]
		if ep == nil {
			ms.unmatched++
			ms.unmatchedX = append(ms.unmatchedX, x)
			continue
		}
		ms.matched++
		if len(res.Ambiguous) > 0 {
			ms.ambiguous++
			if ms.ambiguousBy == nil {
				ms.ambiguousBy = map[string]int{}
			}
			ms.ambiguousBy[ep.ID]++
		}
		obs = append(obs, &model.Observation{X: x, Endpoint: ep, Params: res.Params})
	}
	return obs, ms
}

// classify runs ownership pass 1 (learn) and pass 2 (owner + relationship)
// and returns the learned owner claims for the report.
func classify(cfg *config.File, obs []*model.Observation) []ownership.Object {
	create := make([]ownership.CreateRule, 0, len(cfg.Ownership.LearnFromCreate))
	for _, c := range cfg.Ownership.LearnFromCreate {
		create = append(create, ownership.CreateRule{Method: c.Method, Path: c.Path, Resource: c.Resource, IDField: c.IDFromRequestJSON, IDFromResponse: c.IDFromResponseJSON})
	}
	lists := make([]ownership.ListRule, 0, len(cfg.Ownership.LearnFromLists))
	for _, l := range cfg.Ownership.LearnFromLists {
		lists = append(lists, ownership.ListRule{Method: l.Method, Path: l.Path, Resource: l.Resource, IDsPath: l.IDsFromResponseJSON})
	}
	reg := ownership.New(ownership.Config{SelfParams: cfg.Ownership.SelfParams, Create: create, Lists: lists, Resources: cfg.Resources})
	for _, o := range obs {
		reg.Learn(o)
	}
	minRanks := relate.MinRanks(obs)
	for _, o := range obs {
		if o.Endpoint.Kind == model.ObjectLevel {
			o.Owner, o.OwnerConf = reg.Owner(o)
		}
		minRank, known := minRanks[o.Endpoint.ID]
		tenant, tenantKnown := objectTenant(cfg, o)
		o.ObjectTenantKnown = tenantKnown && o.Endpoint.Kind == model.ObjectLevel
		if o.ObjectTenantKnown {
			o.ObjectTenant = tenant
		}
		o.Rel = relate.Classify(relate.Input{
			Endpoint: o.Endpoint, Caller: o.Identity, CallerConf: o.IDConf,
			Owner: o.Owner, OwnerConf: o.OwnerConf, MinRank: minRank, MinRankKnown: known,
			ObjectTenant: tenant, ObjectTenantKnown: o.ObjectTenantKnown,
		})
	}
	return reg.Objects()
}

// objectTenant returns the value of the first tenancy.tenant_params path
// parameter of the endpoint (in path order), if the request bound it.
func objectTenant(cfg *config.File, o *model.Observation) (string, bool) {
	for _, p := range o.Endpoint.Params {
		if _, ok := cfg.TenantParams[p]; !ok {
			continue
		}
		if v := o.Params[p]; v != "" {
			return v, true
		}
		return "", false
	}
	return "", false
}

func writeSummary(w io.Writer, nHAR int, hs *har.Stats, ms matchStats) {
	_, _ = fmt.Fprintf(w, "read %d entries from %d HAR file(s): kept %d, matched %d, unmatched %d, method miss %d, ambiguous %d; dropped static %d, options %d, status 0 %d, bad url %d; hosts without matches %d\n",
		hs.Entries, nHAR, hs.Kept, ms.matched, ms.unmatched, ms.methodMiss, ms.ambiguous, hs.Static, hs.Options, hs.Status0, hs.BadURL, ms.droppedHosts)
}
