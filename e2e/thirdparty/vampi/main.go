// Command vampieval runs authzcov against the third-party app VAmPI (pinned
// Docker image), records HAR traffic with a scripted recorder, and scores
// authzcov's output against the ground truth in groundtruth.yaml.
//
//	go run . [-v] [-keep] [-out ../../../eval/results/vampi.json]
//
// Requires docker. Everything else (containers, HARs, the authzcov build) lives
// in a temp dir / is removed afterwards.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"authzcoveval/result"
)

const image = "erev0s/vampi@sha256:0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12"

const vampiCommit = "f16052d" // erev0s/VAmPI master, 2026-04-07 (image built same day)

type cell = result.Cell

type scored = result.Case

type runInfo struct {
	Name        string   `json:"name"`
	Vulnerable  int      `json:"vulnerable"`
	Suite       string   `json:"suite"`
	Entries     int      `json:"har_entries"`
	CoveragePct float64  `json:"coverage_percent"`
	Required    int      `json:"required"`
	Covered     int      `json:"covered"`
	Suspicious  []cell   `json:"suspicious_allow"`
	Warnings    []string `json:"warnings,omitempty"`
	Probes      []step   `json:"probes,omitempty"`
	// Summary scores this run's cases alone: honest runs count "gap reported" (tp/fn),
	// attack runs count suspicious_allow detections against ground truth.
	Summary result.Summary `json:"summary"`
}

func main() {
	defer runCleanups()
	verbose := flag.Bool("v", false, "print authzcov tables and probe statuses")
	out := flag.String("out", "", "results JSON path (default <repo>/eval/results/vampi.json)")
	flag.Parse()

	if _, err := exec.LookPath("docker"); err != nil {
		fatal("docker is required")
	}
	root := repoRoot()
	here := filepath.Join(root, "e2e", "thirdparty", "vampi")
	if *out == "" {
		*out = filepath.Join(root, "eval", "results", "vampi.json")
	}
	tmp, err := os.MkdirTemp("", "vampieval-")
	check(err)
	addCleanup(func() { _ = os.RemoveAll(tmp) })

	bin := filepath.Join(tmp, "authzcov")
	gv := strings.TrimSpace(shOutOr(root, "dev", "git", "describe", "--tags", "--always"))
	// Dirty = changes outside eval/results (make eval rewrites those while it runs).
	if strings.TrimSpace(shOutOr(root, "", "git", "status", "--porcelain", "--", ".", ":(exclude)eval/results")) != "" {
		gv += "-dirty"
	}
	gc := strings.TrimSpace(shOutOr(root, "", "git", "rev-parse", "--short", "HEAD"))
	sh(root, "go", "build", "-trimpath", "-ldflags", "-X authzcov/internal/cli.version="+gv+" -X authzcov/internal/cli.commit="+gc, "-o", bin, "./cmd/authzcov")
	ver := strings.TrimSpace(shOut(root, bin, "version"))
	fmt.Println("authzcov:", ver)

	gt, err := loadGroundTruth(filepath.Join(here, "groundtruth.yaml"))
	check(err)
	spec := filepath.Join(root, "testdata", "specs", "vampi.yml")
	ids := filepath.Join(here, "identities.yaml")

	var cases []scored
	var runs []runInfo
	for _, vuln := range []int{1, 0} {
		base, stop := startVampi(vuln)
		addCleanup(stop)
		for _, suite := range []string{"honest", "attack"} {
			name := fmt.Sprintf("v%d/%s", vuln, suite)
			r := recordSession(base, suite, 5)
			dir := filepath.Join(tmp, strings.ReplaceAll(name, "/", "-"))
			check(os.MkdirAll(dir, 0o700))
			har := filepath.Join(dir, "rec.har")
			check(writeHAR(har, r.entries))
			cov := runCoverage(bin, root, spec, ids, har, dir)
			if *verbose {
				fmt.Printf("\n=== %s (%d entries) ===\n%s\n", name, len(r.entries), cov.table)
			}
			ri := runInfo{Name: name, Vulnerable: vuln, Suite: suite, Entries: len(r.entries),
				CoveragePct: cov.Summary.Percent, Required: cov.Summary.Required, Covered: cov.Summary.Covered,
				Warnings: cov.warnings}
			if suite == "attack" {
				ri.Probes = taggedSteps(r.steps)
			}
			for _, f := range cov.Findings {
				if f.Kind == "suspicious_allow" {
					ri.Suspicious = append(ri.Suspicious, cell{Endpoint: f.Endpoint, Relationship: f.Relationship})
				}
			}
			sc := score(gt, vuln, suite, cov, r.steps)
			ri.Summary = result.Summarize(sc)
			runs = append(runs, ri)
			cases = append(cases, sc...)
		}
		stop()
	}

	res := buildResult(ver, cases, runs)
	check(result.Write(*out, res))
	printSummary(res, runs, cases)
	fmt.Println("wrote", *out)
}

func taggedSteps(all []step) []step {
	var o []step
	for _, s := range all {
		if s.Tag != "" {
			o = append(o, s)
		}
	}
	return o
}

type finding struct {
	Kind, Endpoint, Relationship, Message string
}

type covOut struct {
	Findings []finding `json:"-"`
	Summary  struct {
		Required int     `json:"required"`
		Covered  int     `json:"covered"`
		Percent  float64 `json:"percent"`
	}
	table    string
	warnings []string
}

func runCoverage(bin, root, spec, ids, har, dir string) covOut {
	cmd := exec.Command(bin, "coverage", "--spec", spec, "--identities", ids, "--har", har, "--out", dir)
	cmd.Dir = dir // no .authzcov/waivers.yaml here
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	_ = cmd.Run() // exit 1 = gaps; the JSON decides
	raw, err := os.ReadFile(filepath.Join(dir, "coverage.json"))
	if err != nil {
		fatal("authzcov produced no coverage.json: " + se.String() + so.String())
	}
	var doc struct {
		Findings []struct {
			Kind         string `json:"kind"`
			Endpoint     string `json:"endpoint"`
			Relationship string `json:"relationship"`
			Message      string `json:"message"`
		} `json:"findings"`
		Warnings []any `json:"warnings"`
		Summary  struct {
			Required int     `json:"required"`
			Covered  int     `json:"covered"`
			Percent  float64 `json:"percent"`
		} `json:"summary"`
	}
	check(json.Unmarshal(raw, &doc))
	c := covOut{table: so.String() + se.String()}
	c.Summary = doc.Summary
	for _, f := range doc.Findings {
		c.Findings = append(c.Findings, finding{f.Kind, f.Endpoint, f.Relationship, f.Message})
	}
	for _, w := range doc.Warnings {
		c.warnings = append(c.warnings, fmt.Sprint(w))
	}
	return c
}

func (c covOut) has(kind, ep, rel string) (finding, bool) {
	for _, f := range c.Findings {
		if f.Kind == kind && f.Endpoint == ep && f.Relationship == rel {
			return f, true
		}
	}
	return finding{}, false
}

// score turns one (mode, suite) run into cases.
func score(gt []gtItem, vuln int, suite string, cov covOut, steps []step) []scored {
	mode := fmt.Sprintf("v%d/%s", vuln, suite)
	var out []scored
	matched := map[cell]bool{}
	for _, g := range gt {
		c := cell{Endpoint: g.Endpoint, Relationship: g.Relationship}
		if !g.Authz && g.Category != "quirk" {
			if suite == "attack" {
				out = append(out, scored{ID: mode + "/" + g.ID, Kind: "non_authz", Expected: []cell{}, Flagged: []cell{},
					Result: "out_of_scope", Reason: "not an authorization problem: " + g.Name})
			}
			continue
		}
		exp := g.V1
		if vuln == 0 {
			exp = g.V0
		}
		_, gap := cov.has("gap", c.Endpoint, c.Relationship)
		sf, susp := cov.has("suspicious_allow", c.Endpoint, c.Relationship)
		if susp {
			matched[c] = true
		}
		observed := probeStatus(steps, g.Probe)
		r := scored{ID: mode + "/" + g.ID, Kind: g.Category, Expected: []cell{}, Flagged: []cell{}}
		switch suite {
		case "honest":
			if g.Category == "control" || g.Category == "quirk" {
				continue
			}
			r.Kind = "gap"
			r.Expected = []cell{c}
			if gap {
				r.Flagged = []cell{c}
				r.Result, r.Reason = "tp", "gap reported: the test suite never tried this cell ("+g.Name+")"
			} else {
				r.Result, r.Reason = "fn", "no gap finding for this cell (covered or not required)"
			}
		default:
			switch {
			case exp == "allow" && g.Authz:
				r.Expected = []cell{c}
				if susp {
					r.Flagged = []cell{c}
					r.Result, r.Reason = "tp", "suspicious_allow raised; probe status "+observed+": "+sf.Message
				} else {
					r.Result = "fn"
					r.Reason = "no suspicious_allow (probe status " + observed + "); " + missReason(cov, c)
				}
			case exp == "noop" || !g.Authz: // 2xx without effect on the victim
				if susp {
					r.Flagged = []cell{c}
					r.Result, r.Reason = "fp", "flagged, but the 2xx changed only the caller's own record (path ignored), not the named victim: "+g.Name+" (probe status "+observed+"; "+sf.Message+")"
				} else {
					r.Result, r.Reason = "tn", "not flagged ("+g.Name+")"
				}
			default: // expected deny
				if susp {
					r.Flagged = []cell{c}
					r.Result, r.Reason = "fp", "suspicious_allow although VAmPI denies here (probe status "+observed+"): "+sf.Message
				} else {
					r.Result, r.Reason = "tn", "denied by VAmPI (probe status "+observed+") and not flagged"
				}
			}
		}
		out = append(out, r)
	}
	// Any other suspicious_allow is unexplained.
	for _, f := range cov.Findings {
		c := cell{Endpoint: f.Endpoint, Relationship: f.Relationship}
		if f.Kind != "suspicious_allow" || matched[c] {
			continue
		}
		why := "no ground-truth item for this cell"
		if suite == "honest" {
			why = "the honest suite made no cross-user/anonymous attempt"
		}
		out = append(out, scored{ID: mode + "/unexpected/" + f.Endpoint + "/" + f.Relationship, Kind: "unexpected_flag",
			Expected: []cell{}, Flagged: []cell{c}, Result: "fp", Reason: why + ": " + f.Message})
	}
	// Honest suite: also any suspicious_allow on a GT item that is not a gap item is handled above only for attack; cover it.
	if suite == "honest" {
		for _, g := range gt {
			c := cell{Endpoint: g.Endpoint, Relationship: g.Relationship}
			if sf, ok := cov.has("suspicious_allow", c.Endpoint, c.Relationship); ok && matched[c] {
				out = append(out, scored{ID: mode + "/unexpected/" + g.ID, Kind: "unexpected_flag", Expected: []cell{},
					Flagged: []cell{c}, Result: "fp", Reason: "the honest suite made no such attempt: " + sf.Message})
			}
		}
	}
	return out
}

func missReason(cov covOut, c cell) string {
	if _, ok := cov.has("gap", c.Endpoint, c.Relationship); ok {
		return "cell reported as a GAP (no observation matched)"
	}
	return "cell is shown as covered (ok), but suspicious_allow is only raised for object-level endpoints (path has an object parameter); this endpoint has none"
}

func probeStatus(steps []step, tag string) string {
	if tag == "" {
		return "n/a"
	}
	var s []string
	for _, st := range steps {
		if st.Tag == tag {
			s = append(s, fmt.Sprintf("%s:%d", st.Who, st.Status))
		}
	}
	return strings.Join(s, ",")
}

// ---- results ---------------------------------------------------------------

func buildResult(ver string, cases []scored, runs []runInfo) *result.Result {
	return &result.Result{
		SchemaVersion: result.SchemaVersion,
		Suite:         "vampi",
		GeneratedAt:   result.Now(),
		Machine:       result.Machine(),
		Authzcov:      result.ParseVersion(ver),
		App: result.App{Name: "VAmPI", Version: "master@" + vampiCommit,
			ImageDigest: image[strings.Index(image, "sha256:"):]},
		Cases:   cases,
		Summary: result.Summarize(cases),
		Extra:   map[string]any{"runs": runs, "note": "tp/fn in honest runs = gap reported yes/no; attack runs = suspicious_allow vs ground truth; tn/fp only meaningful for expected-deny cells"},
	}
}

func printSummary(res *result.Result, runs []runInfo, cases []scored) {
	fmt.Println("\n== runs ==")
	for _, r := range runs {
		fmt.Printf("%-14s entries=%-3d coverage=%5.1f%% (%d/%d) suspicious_allow=%d\n", r.Name, r.Entries, r.CoveragePct, r.Covered, r.Required, len(r.Suspicious))
	}
	fmt.Println("\n== cases ==")
	for _, c := range cases {
		fmt.Printf("%-3s %-44s %s\n", c.Result, c.ID, c.Reason)
	}
	sb, _ := json.Marshal(res.Summary)
	fmt.Printf("\nsummary: %s\n", sb)
}

// ---- docker / shell ---------------------------------------------------------

func startVampi(vuln int) (base string, stop func()) {
	name := fmt.Sprintf("vampieval-v%d-%d", vuln, os.Getpid())
	sh("", "docker", "run", "-d", "--rm", "--name", name,
		"-e", fmt.Sprintf("vulnerable=%d", vuln), "-e", "tokentimetolive=3600",
		"-p", "127.0.0.1::5000", image)
	stopped := false
	stop = func() {
		if !stopped {
			stopped = true
			_ = exec.Command("docker", "rm", "-f", name).Run()
		}
	}
	addCleanup(stop) // a fatal() below must not leak the container
	port := strings.TrimSpace(shOut("", "docker", "port", name, "5000/tcp"))
	port = port[strings.LastIndex(port, ":")+1:]
	base = "http://127.0.0.1:" + port
	if err := waitReady(newRecorder(base).client, base, 60*time.Second); err != nil {
		fatal(fmt.Sprintf("VAmPI vulnerable=%d not ready: %v", vuln, err))
	}
	fmt.Printf("VAmPI vulnerable=%d up on %s\n", vuln, base)
	return base, stop
}

// waitReady polls until VAmPI answers, /createdb succeeds and the seeded admin
// (models/user_model.py:init_db_users) can log in. None of these requests are
// recorded; the recorder's own /createdb then starts from a warm app. Without
// this, a fresh container sometimes answered "/" before /createdb took effect
// and the recorded admin login failed.
func waitReady(c *http.Client, base string, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	var last string
	for time.Now().Before(deadline) {
		if ok, why := probeReady(c, base); ok {
			return nil
		} else {
			last = why
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("gave up after %v: %s", limit, last)
}

func probeReady(c *http.Client, base string) (bool, string) {
	resp, err := c.Get(base + "/createdb")
	if err != nil {
		return false, err.Error()
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("/createdb: status %d", resp.StatusCode)
	}
	resp, err = c.Post(base+"/users/v1/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"pass1"}`))
	if err != nil {
		return false, err.Error()
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "auth_token") {
		return false, "admin login: " + strings.TrimSpace(string(b))
	}
	return true, ""
}

func repoRoot() string {
	d, _ := os.Getwd()
	for {
		if b, err := os.ReadFile(filepath.Join(d, "go.mod")); err == nil && strings.HasPrefix(string(b), "module authzcov") {
			return d
		}
		p := filepath.Dir(d)
		if p == d {
			fatal("repo root (module authzcov) not found above " + d)
		}
		d = p
	}
}

func sh(dir, name string, args ...string) {
	c := exec.Command(name, args...)
	c.Dir = dir
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	if err := c.Run(); err != nil {
		fatal(fmt.Sprintf("%s %v: %v", name, args, err))
	}
}

func shOut(dir, name string, args ...string) string {
	c := exec.Command(name, args...)
	c.Dir = dir
	b, err := c.Output()
	if err != nil {
		fatal(fmt.Sprintf("%s %v: %v", name, args, err))
	}
	return string(b)
}

func shOutOr(dir, def, name string, args ...string) string {
	c := exec.Command(name, args...)
	c.Dir = dir
	b, err := c.Output()
	if err != nil {
		return def
	}
	return string(b)
}

func check(err error) {
	if err != nil {
		fatal(err.Error())
	}
}

var cleanups []func()

// addCleanup registers f to run (LIFO, once) on normal return from main and before fatal exits.
func addCleanup(f func()) { cleanups = append(cleanups, f) }

func runCleanups() {
	for len(cleanups) > 0 {
		f := cleanups[len(cleanups)-1]
		cleanups = cleanups[:len(cleanups)-1]
		f()
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "vampieval:", msg)
	runCleanups() // os.Exit skips deferred calls
	os.Exit(1)
}
