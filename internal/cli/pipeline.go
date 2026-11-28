package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

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

	needs := newBodyNeeds(cfg)
	store := newRecStore(needs)
	perFile, err := readHARsInto(o.hars, extract, store, objectQueryKeys(endpoints)...)
	if err != nil {
		return nil, inputErr(err)
	}
	hs := sumStats(perFile)
	for _, w := range cfg.Warnings() {
		_, _ = fmt.Fprintf(stderr, "warning: %s\n", redact.StripControl(w))
	}
	byHost, choices, droppedHosts := chooseBasePath(store, trie, o.basePath, stderr)
	obs, ms := matchRecs(store, byHost, trie, byID, needs)
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
	mopts := matrix.Options{Strict: o.strict, MinRanks: relate.MinRanks(obs)}
	for name, rank := range cfg.Roles {
		if name != "anonymous" && (!mopts.HasLowestRank || rank < mopts.LowestRank) {
			mopts.HasLowestRank, mopts.LowestRank = true, rank
		}
	}
	m := matrix.BuildWith(endpoints, obs, cfg.HasTenants(), mopts)
	return &analysis{cfg: cfg, ws: ws, endpoints: endpoints, obs: obs, objects: objects, allows: allows,
		m: m, ms: ms, choices: choices, perFile: perFile}, nil
}

// runCoverage executes the whole offline pipeline, writes the table to stdout
// and (unless --out is empty) coverage.json to the output directory.
func runCoverage(o *coverageOpts, stdout, stderr io.Writer) error {
	defer limitGC()()
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
	// Resolve is a function of the credential, and observations only read the
	// identity (applyJWTTenant copies before changing it), so the many
	// requests of one caller share one identity. The key includes the claims
	// map pointer: equal fingerprints with different decoded claims never share.
	type resolved struct {
		id   *model.Identity
		conf model.Confidence
	}
	type ck struct {
		kind, fp string
		claims   uintptr
	}
	const maxCached = 4096
	cache := map[ck]resolved{}
	for _, o := range obs {
		c := o.X.Cred
		k := ck{kind: c.Kind, fp: c.Fingerprint}
		if c.Claims != nil {
			k.claims = reflect.ValueOf(c.Claims).Pointer()
		}
		if hit, ok := cache[k]; ok {
			o.Identity, o.IDConf = hit.id, hit.conf
			continue
		}
		o.Identity, o.IDConf = r.Resolve(c)
		if len(cache) < maxCached {
			cache[k] = resolved{o.Identity, o.IDConf}
		}
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

// applyOverrides returns endpoints with the config applied to copies:
// requirements.overrides pick the object param (the resource is the literal
// segment before it) and declare min_role; every endpoint whose object param
// is a tenancy.tenant_params parameter becomes tenant-scoped.
func applyOverrides(cfg *config.File, endpoints []*model.Endpoint) ([]*model.Endpoint, error) {
	out := slices.Clone(endpoints)
	for _, ov := range cfg.Overrides {
		i := slices.IndexFunc(out, func(e *model.Endpoint) bool { return e.ID == ov.Endpoint })
		if i < 0 {
			return nil, fmt.Errorf("%s:%d: requirements.overrides: endpoint %q is not in the spec", cfg.Path, ov.Line, redact.StripControl(ov.Endpoint))
		}
		cp := *out[i]
		if ov.ObjectParam != "" {
			inPath := slices.Contains(cp.Params, ov.ObjectParam)
			if !inPath && !slices.Contains(cp.QueryParams, ov.ObjectParam) {
				return nil, fmt.Errorf("%s:%d: requirements.overrides: object_param %q is not a path parameter or a declared query parameter of %q (path parameters: %s; query parameters: %s)",
					cfg.Path, ov.Line, redact.StripControl(ov.ObjectParam), redact.StripControl(ov.Endpoint),
					redact.StripControl(strings.Join(cp.Params, ", ")), redact.StripControl(strings.Join(cp.QueryParams, ", ")))
			}
			if _, tenant := cfg.TenantParams[ov.ObjectParam]; tenant && !inPath {
				return nil, fmt.Errorf("%s:%d: requirements.overrides: object_param %q is a query parameter and also listed in tenancy.tenant_params; tenant scoping applies only to path parameters",
					cfg.Path, ov.Line, redact.StripControl(ov.ObjectParam))
			}
			cp.ObjectInQuery = !inPath
			cp.ObjectParam = ov.ObjectParam
			cp.Kind = model.ObjectLevel
			cp.Resource = ""
			segs := strings.Split(strings.Trim(cp.Template, "/"), "/")
			for j, sg := range segs {
				if sg == "{"+ov.ObjectParam+"}" && j > 0 && !strings.HasPrefix(segs[j-1], "{") {
					cp.Resource = segs[j-1]
				}
			}
		}
		if ov.MinRole != "" {
			rank, ok := cfg.Roles[ov.MinRole]
			if !ok {
				return nil, fmt.Errorf("%s:%d: requirements.overrides: min_role %q is not a role", cfg.Path, ov.Line, redact.StripControl(ov.MinRole))
			}
			cp.MinRole, cp.MinRank, cp.MinRankDeclared = ov.MinRole, rank, true
		}
		out[i] = &cp
	}
	for i, e := range out {
		if e.Kind != model.ObjectLevel || e.TenantScoped || e.ObjectInQuery {
			continue
		}
		if _, ok := cfg.TenantParams[e.ObjectParam]; ok {
			cp := *e
			cp.TenantScoped = true
			out[i] = &cp
		}
	}
	for _, ov := range cfg.Overrides {
		if ov.MinRole == "" {
			continue
		}
		if e := out[slices.IndexFunc(out, func(e *model.Endpoint) bool { return e.ID == ov.Endpoint })]; e.Kind == model.ObjectLevel && !e.TenantScoped {
			return nil, fmt.Errorf("%s:%d: requirements.overrides: min_role applies only to function-level or tenant-scoped endpoints; %q addresses a single object (parameter %q is not in tenancy.tenant_params)",
				cfg.Path, ov.Line, redact.StripControl(ov.Endpoint), e.ObjectParam)
		}
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

// objectQueryKeys lists the query names that carry an object param, the only
// query keys ingest keeps.
func objectQueryKeys(eps []*model.Endpoint) []string {
	var keys []string
	for _, e := range eps {
		if e.ObjectInQuery && !slices.Contains(keys, e.ObjectParam) {
			keys = append(keys, e.ObjectParam)
		}
	}
	slices.Sort(keys)
	return keys
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
func readHARsByFile(paths []string, extract har.Extractor, queryKeys ...string) ([]*model.Exchange, []har.Stats, error) {
	var all []*model.Exchange
	perFile, err := readHARsEach(paths, extract, queryKeys, func(x *model.Exchange) { all = append(all, x) })
	return all, perFile, err
}

// readHARsInto folds every exchange into store as it is read.
func readHARsInto(paths []string, extract har.Extractor, store *recStore, queryKeys ...string) ([]har.Stats, error) {
	return readHARsEach(paths, extract, queryKeys, store.add)
}

func readHARsEach(paths []string, extract har.Extractor, queryKeys []string, fn func(*model.Exchange)) ([]har.Stats, error) {
	perFile := make([]har.Stats, len(paths))
	mk := func(label string) har.Options {
		return har.Options{Source: label, Extract: extract, QueryKeys: queryKeys}
	}
	for i, p := range paths {
		for x, err := range har.ExchangesFromFile(p, mk, &perFile[i]) {
			if err != nil {
				return nil, err
			}
			fn(x)
		}
	}
	return perFile, nil
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

// chooseBasePath picks the per-host path prefix to strip (printing one line
// per host on w) and returns the choice by host, all choices and the number
// of hosts where nothing matches (their requests are dropped).
func chooseBasePath(store *recStore, trie *match.Trie, mode string, w io.Writer) (map[string]basepath.Choice, []basepath.Choice, int) {
	var choices []basepath.Choice
	if mode == basePathAuto {
		c := basepath.NewCounter()
		store.each(false, func(r *rec) { c.Add(r.shape.Host, r.shape.Method, r.path) })
		choices = c.Choices(trie)
	} else {
		prefix := mode
		if mode == basePathNone {
			prefix = ""
		}
		choices = fixedChoices(store, trie, prefix)
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
	return byHost, choices, dropped
}

// fixedChoices scores one prefix on every host.
func fixedChoices(store *recStore, trie *match.Trie, prefix string) []basepath.Choice {
	byHost := map[string]*basepath.Choice{}
	store.each(false, func(r *rec) {
		c := byHost[r.shape.Host]
		if c == nil {
			c = &basepath.Choice{Host: r.shape.Host, Prefix: prefix}
			byHost[r.shape.Host] = c
		}
		c.Total++
		if rest, ok := basepath.Strip(r.path, prefix); ok && trie.Match(r.shape.Method, rest).Op != nil {
			c.Matched++
		}
	})
	out := make([]basepath.Choice, 0, len(byHost))
	for _, c := range byHost {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// matchExchanges matches already-read exchanges with no base-path handling
// (tests and helpers); analyze uses matchRecs.
func matchExchanges(xs []*model.Exchange, trie *match.Trie, byID map[string]*model.Endpoint, needs *bodyNeeds) ([]*model.Observation, matchStats) {
	store := newRecStore(needs)
	for _, x := range xs {
		store.add(x)
	}
	return matchRecs(store, nil, trie, byID, needs)
}

// matchRecs matches every rec (stripping the base path chosen for its host
// and dropping hosts where nothing matches; byHost == nil means no base path)
// and builds the observations. It consumes store.
func matchRecs(store *recStore, byHost map[string]basepath.Choice, trie *match.Trie, byID map[string]*model.Endpoint, needs *bodyNeeds) ([]*model.Observation, matchStats) {
	var ms matchStats
	obs := make([]*model.Observation, 0, store.n)
	var slab []model.Observation // observations are allocated in blocks, not one by one
	store.each(true, func(r *rec) {
		path := r.path
		if byHost != nil {
			c := byHost[r.shape.Host]
			if c.Matched == 0 {
				return
			}
			if rest, ok := basepath.Strip(path, c.Prefix); ok {
				path = rest
			} // else: not under the prefix: stays unmatched
		}
		method := r.shape.Method
		res := trie.Match(method, path)
		if res.Op == nil {
			x := store.exchange(r, path)
			if res.MethodMiss {
				ms.methodMiss++
				ms.methodMissX = append(ms.methodMissX, x)
			} else {
				ms.unmatched++
			}
			ms.unmatchedX = append(ms.unmatchedX, x)
			return
		}
		ep := byID[res.Op.ID]
		if ep == nil {
			ms.unmatched++
			ms.unmatchedX = append(ms.unmatchedX, store.exchange(r, path))
			return
		}
		ms.matched++
		if len(res.Ambiguous) > 0 {
			ms.ambiguous++
			if ms.ambiguousBy == nil {
				ms.ambiguousBy = map[string]int{}
			}
			ms.ambiguousBy[ep.ID]++
		}
		var params []string
		if n := model.ParamCount(ep); n > 0 {
			params = make([]string, n)
			for i, name := range ep.Params {
				params[i] = res.Params[name]
			}
			if ep.ObjectInQuery {
				if v, ok := queryObjectValue(r.query, ep.ObjectParam); ok {
					if i := slices.Index(ep.Params, ep.ObjectParam); i >= 0 {
						params[i] = v
					} else {
						params[n-1] = v
					}
				}
			}
		}
		if len(slab) == 0 {
			slab = make([]model.Observation, 1024)
		}
		o := &slab[0]
		slab = slab[1:]
		o.Endpoint, o.Params = ep, params
		if needs == nil || needs.needs(method, path, ep.Template) {
			o.X = store.exchange(r, path)
		} else {
			// No learning rule reads this request's path or bodies: share a
			// slim exchange with look-alikes and keep only the source position.
			o.X = store.obsShape(r)
			lab := &store.labels[r.label]
			o.SrcLabel, o.SrcIdx = lab, r.idx
		}
		obs = append(obs, o)
	})
	return obs, ms
}

// queryObjectValue returns the object value of a query-bound object param.
// It fails closed: the key must appear exactly once with a non-empty,
// single plain value (no comma list, array syntax, whitespace or control chars); anything else is
// unknown and never counts as covered.
func queryObjectValue(query map[string][]string, name string) (string, bool) {
	vs := query[name]
	if len(vs) != 1 {
		return "", false
	}
	v := vs[0]
	if v == "" || strings.ContainsAny(v, ",[]") || strings.IndexFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", false
	}
	return v, true
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
		lists = append(lists, ownership.ListRule{Method: l.Method, Path: l.Path, Resource: l.Resource, IDsPath: l.IDsFromResponseJSON, Exclusive: l.Exclusive})
	}
	reg := ownership.New(ownership.Config{SelfParams: cfg.Ownership.SelfParams, Create: create, Lists: lists, Resources: cfg.Resources})
	for _, o := range obs {
		reg.Learn(o)
	}
	// Tenant first: the learned minimum of a tenant-scoped endpoint only
	// counts same-tenant callers.
	tenants := make([]string, len(obs))
	for i, o := range obs {
		tenant, tenantKnown := objectTenant(cfg, o)
		o.ObjectTenantKnown = tenantKnown && o.Endpoint.Kind == model.ObjectLevel
		if o.ObjectTenantKnown {
			o.ObjectTenant = tenant
		}
		tenants[i] = tenant
	}
	minRanks := relate.MinRanks(obs)
	for i, o := range obs {
		if o.Endpoint.Kind == model.ObjectLevel {
			o.Owner, o.OwnerConf = reg.Owner(o)
		}
		minRank, known := minRanks[o.Endpoint.ID]
		tenant := tenants[i]
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
		if v := o.Param(p); v != "" {
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

// limitGC trades a little CPU for a smaller peak heap: the pipeline holds one
// small record per request, so with Go's default GOGC=100 the heap would grow
// to twice that. An explicit GOGC in the environment wins. The returned func
// restores the previous setting so it does not leak process-wide.
func limitGC() func() {
	if os.Getenv("GOGC") != "" {
		return func() {}
	}
	old := debug.SetGCPercent(30)
	return func() { debug.SetGCPercent(old) }
}
