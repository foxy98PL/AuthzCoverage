// Package tenantshop runs the two tenantshop validation suites: seeded-mutant detection and
// recorder ablation. Everything runs in-process (httptest); HARs only live in temp dirs.
package tenantshop

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"authzcoveval/harness"
	"authzcoveval/result"

	"tenantshop/record"
	"tenantshop/shop"
)

const harBase = "http://tenantshop.test"

// Env is a built authzcov plus the inputs every run shares.
type Env struct {
	Bin, Version     string // authzcov binary and its `version` output
	Spec, Identities string
	Tmp              string // scratch dir (HARs, coverage.json)
	Log              func(format string, args ...any)
	n                int
	GeneratedAt      string
}

// NewEnv builds authzcov from the repository at root into tmp.
func NewEnv(root, tmp string, log func(string, ...any)) (*Env, error) {
	bin, ver, err := harness.Build(root, tmp)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = func(string, ...any) {}
	}
	app := filepath.Join(root, "e2e", "apps", "tenantshop")
	return &Env{Bin: bin, Version: ver, Spec: filepath.Join(app, "shop", "openapi.yaml"),
		Identities: filepath.Join(app, "identities.yaml"), Tmp: tmp, Log: log, GeneratedAt: result.Now()}, nil
}

// Record runs steps against a fresh server of the variant and returns authzcov's coverage.
func (e *Env) Record(variant string, steps []record.Step) (*harness.Coverage, error) {
	h, err := shop.NewVariant(variant)
	if err != nil {
		return nil, err
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	har, err := record.RecordScript(srv.URL, harBase, &http.Client{Timeout: 10 * time.Second}, steps)
	if err != nil {
		return nil, fmt.Errorf("record %s: %w", variant, err)
	}
	e.n++
	dir := filepath.Join(e.Tmp, fmt.Sprintf("run-%03d", e.n))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	harPath := filepath.Join(dir, "rec.har")
	if err := os.WriteFile(harPath, har, 0o600); err != nil {
		return nil, err
	}
	cov, err := harness.Run(e.Bin, e.Spec, e.Identities, harPath, dir)
	if err != nil {
		return nil, err
	}
	e.Log("[%s] %d entries, coverage %.1f%% (%d/%d), suspicious_allow: %v", variant, cov.Entries(),
		cov.Summary.Percent, cov.Summary.Covered, cov.Summary.Required, suspicious(cov))
	return cov, nil
}

func (e *Env) base(suite string) *result.Result {
	return &result.Result{
		SchemaVersion: result.SchemaVersion, Suite: suite, GeneratedAt: e.GeneratedAt,
		App:      result.App{Name: "tenantshop", Version: "in-tree"},
		Authzcov: result.ParseVersion(e.Version), Machine: result.Machine(),
	}
}

func key(c result.Cell) string { return c.Endpoint + "|" + c.Relationship }

func suspicious(cov *harness.Coverage) []result.Cell {
	out := []result.Cell{}
	for _, f := range cov.Findings {
		if f.Kind == "suspicious_allow" {
			out = append(out, result.Cell{Endpoint: f.Endpoint, Relationship: f.Relationship})
		}
	}
	return out
}

type runInfo struct {
	Name        string        `json:"name"`
	Entries     int           `json:"har_entries"`
	CoveragePct float64       `json:"coverage_percent"`
	Required    int           `json:"required"`
	Covered     int           `json:"covered"`
	Suspicious  []result.Cell `json:"suspicious_allow"`
}

func info(name string, cov *harness.Coverage) runInfo {
	return runInfo{Name: name, Entries: cov.Entries(), CoveragePct: cov.Summary.Percent,
		Required: cov.Summary.Required, Covered: cov.Summary.Covered, Suspicious: suspicious(cov)}
}

// unexpected turns every suspicious_allow except want into an fp case.
func unexpected(prefix string, cov *harness.Coverage, want *result.Cell) []result.Case {
	var out []result.Case
	for _, c := range suspicious(cov) {
		if want != nil && *want == c {
			continue
		}
		f, _ := cov.Suspicious(c.Endpoint, c.Relationship)
		out = append(out, result.Case{ID: prefix + "/unexpected/" + key(c), Kind: "unexpected_flag",
			Expected: []result.Cell{}, Flagged: []result.Cell{c}, Result: result.FP,
			Reason: "suspicious_allow on a cell where the app enforces the check: " + f.Message})
	}
	return out
}

// whyMissed explains, from coverage.json, why the expected cell raised no suspicious_allow.
func whyMissed(cov *harness.Coverage, want result.Cell) string {
	c, ok := cov.Cell(want.Endpoint, want.Relationship)
	switch {
	case !ok:
		why := "authzcov built no " + want.Relationship + " cell for this endpoint, so the call was not classified as that relationship"
		if u, ok := cov.Cell(want.Endpoint, "unknown"); ok && len(u.Statuses) > 0 {
			why += fmt.Sprintf("; it was recorded under relationship unknown (statuses %v): without a learned owner or minimum role authzcov will not call it an attack, and unknown never counts", u.Statuses)
		}
		return why
	case !c.Required:
		return "the cell exists but is not required, and suspicious_allow needs a learned owner or tenant for the object"
	case !c.Covered:
		return "the attacker request was never observed (cell is a GAP)"
	default:
		return fmt.Sprintf("the cell is covered with statuses %v but no 2xx with a captured JSON body (or learned owner/tenant) backed a suspicious_allow", c.Statuses)
	}
}

// Mutants runs the mutant suite: FullScript on every variant.
func (e *Env) Mutants() (*result.Result, error) {
	res := e.base("tenantshop-mutants")
	steps := record.FullScript()
	var runs []runInfo
	add := func(c ...result.Case) { res.Cases = append(res.Cases, c...) }

	fixed, err := e.Record("fixed", steps)
	if err != nil {
		return nil, err
	}
	runs = append(runs, info("fixed", fixed))
	if len(suspicious(fixed)) == 0 {
		add(result.Case{ID: "fixed/no-alarm", Kind: "control", Expected: []result.Cell{}, Flagged: []result.Cell{}, Result: result.TN,
			Reason: "no suspicious_allow on the unmutated app"})
	}
	add(unexpected("fixed", fixed, nil)...)

	seeded, err := e.Record("seeded", steps)
	if err != nil {
		return nil, err
	}
	runs = append(runs, info("seeded", seeded))
	add(e.score("seeded/get-tenant", "seeded", "the seeded bug (getOrder without tenant check)",
		result.Cell{Endpoint: "GET /orgs/{orgId}/orders/{orderId}", Relationship: "other_tenant"}, seeded)...)

	for _, m := range shop.Mutants() {
		cov, err := e.Record(m.ID, steps)
		if err != nil {
			return nil, err
		}
		runs = append(runs, info(m.ID, cov))
		add(e.score("mutant/"+m.ID, "mutant", m.Description, result.Cell{Endpoint: m.Endpoint, Relationship: m.Relationship}, cov)...)
	}
	res.Cases = res.Cases[:len(res.Cases):len(res.Cases)]
	res.Summary = result.Summarize(res.Cases)
	res.Extra = map[string]any{
		"runs": runs,
		"note": "every variant is recorded with record.FullScript (one attacker request per required cell); tp = suspicious_allow on the mutant's endpoint and relationship, fp = any other suspicious_allow in that run",
	}
	return res, nil
}

func (e *Env) score(id, kind, what string, want result.Cell, cov *harness.Coverage) []result.Case {
	c := result.Case{ID: id, Kind: kind, Expected: []result.Cell{want}, Flagged: []result.Cell{}}
	if f, ok := cov.Suspicious(want.Endpoint, want.Relationship); ok {
		c.Flagged = []result.Cell{want}
		c.Result, c.Reason = result.TP, what+": suspicious_allow raised: "+f.Message
	} else {
		c.Result, c.Reason = result.FN, what+": no suspicious_allow on "+key(want)+"; "+whyMissed(cov, want)
	}
	return append([]result.Case{c}, unexpected(id, cov, &want)...)
}

type cellState struct{ state, statuses string }

func (c cellState) stateOr() string {
	if c.state == "" {
		return "absent"
	}
	return c.state
}

func states(cov *harness.Coverage) map[string]cellState {
	m := map[string]cellState{}
	for _, c := range cov.Cells {
		s := "unrequired"
		switch {
		case c.Required && c.Covered:
			s = "covered"
		case c.Required:
			s = "missing"
		case c.Covered:
			s = "extra"
		}
		keys := make([]string, 0, len(c.Statuses))
		for k, v := range c.Statuses {
			keys = append(keys, fmt.Sprintf("%s:%d", k, v))
		}
		sort.Strings(keys)
		m[c.Endpoint+"|"+c.Relationship] = cellState{s, strings.Join(keys, ",")}
	}
	return m
}

// Ablation runs the recorder-ablation suite on the fixed app.
func (e *Env) Ablation() (*result.Result, error) {
	res := e.base("tenantshop-ablation")
	steps := record.FullScript()
	base, err := e.Record("fixed", steps)
	if err != nil {
		return nil, err
	}
	want := states(base)
	type skip struct {
		Cell   string `json:"cell"`
		Reason string `json:"reason"`
	}
	var skipped []skip
	ablated, attackers := 0, 0
	for i, s := range steps {
		if s.Cell == "" {
			continue
		}
		attackers++
		st, known := want[s.Cell]
		switch {
		case st.state == "covered":
		case known && st.state == "missing":
			skipped = append(skipped, skip{s.Cell, "required but not covered in the baseline (state missing); there is nothing to lose"})
			continue
		default:
			skipped = append(skipped, skip{s.Cell, "not a required cell for this endpoint (baseline state " + st.stateOr() + "); authzcov does not count it, so dropping it cannot lose coverage"})
			continue
		}
		ablated++
		rest := append(append([]record.Step{}, steps[:i]...), steps[i+1:]...)
		cov, err := e.Record("fixed", rest)
		if err != nil {
			return nil, err
		}
		got := states(cov)
		cell := cellOf(s.Cell)
		c := result.Case{ID: "ablation/" + s.Cell, Kind: "ablation", Expected: []result.Cell{cell}, Flagged: []result.Cell{}}
		if got[s.Cell].state == "missing" {
			c.Flagged = []result.Cell{cell}
			c.Result, c.Reason = result.TP, "dropping the request turned the cell from covered to GAP"
		} else {
			c.Result, c.Reason = result.FN, fmt.Sprintf("dropping the request left the cell %q (statuses %q), expected missing", got[s.Cell].state, got[s.Cell].statuses)
		}
		res.Cases = append(res.Cases, c)
		for k, w := range want {
			if k == s.Cell || got[k] == w {
				continue
			}
			oc := cellOf(k)
			res.Cases = append(res.Cases, result.Case{ID: "ablation/" + s.Cell + "/side-effect/" + k, Kind: "side_effect",
				Expected: []result.Cell{}, Flagged: []result.Cell{oc}, Result: result.FP,
				Reason: fmt.Sprintf("dropping %q also changed %s from %s %q to %s %q", s.Cell, k, w.state, w.statuses, got[k].state, got[k].statuses)})
		}
		for k := range got {
			if _, had := want[k]; !had {
				oc := cellOf(k)
				res.Cases = append(res.Cases, result.Case{ID: "ablation/" + s.Cell + "/side-effect/" + k, Kind: "side_effect",
					Expected: []result.Cell{}, Flagged: []result.Cell{oc}, Result: result.FP,
					Reason: "dropping " + s.Cell + " created a new cell " + k})
			}
		}
	}
	res.Summary = result.Summarize(res.Cases)
	res.Extra = map[string]any{
		"baseline":       info("fixed", base),
		"attacker_steps": attackers,
		"ablatable":      ablated,
		"skipped_steps":  skipped,
		"note":           "precision and recall are over the ablatable cells only (attacker steps whose cell is required and covered in the baseline; the rest are listed in skipped_steps). Each such attacker request of record.FullScript is dropped in turn (fresh server, fresh authzcov run); tp = that cell went covered to missing, fp = any other cell whose state or statuses changed, fn = the cell stayed covered",
	}
	if skipped == nil {
		res.Extra["skipped_steps"] = []skip{}
	}
	return res, nil
}

func cellOf(k string) result.Cell {
	ep, rel, _ := strings.Cut(k, "|")
	return result.Cell{Endpoint: ep, Relationship: rel}
}
