// Command crapieval runs authzcov against the third-party app crAPI (OWASP, pinned docker images), records HAR
// traffic with a scripted recorder, and scores authzcov's output against the ground truth in groundtruth.yaml.
//
//	go run . [-v] [-out ../../../eval/results/crapi.json]
//
// Requires docker with the compose plugin. A fresh crAPI stack is started per suite (honest, attack) under a
// unique compose project and removed with `docker compose down -v`; HARs and the authzcov build live in a temp dir.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"authzcoveval/result"
)

const (
	crapiTag    = "v1.1.6"
	crapiCommit = "700f03d" // OWASP/crAPI v1.1.6 (2025-09-22); the images are the builds of that day
	upTimeout   = 10 * time.Minute
	readyLimit  = 3 * time.Minute
)

type cell = result.Cell

type scored = result.Case

type runInfo struct {
	Name        string   `json:"name"`
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
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	handleSignals(sigs, os.Exit)
	code := run()
	runCleanups()
	if teardownFailed.Load() {
		code = 1
	}
	os.Exit(code)
}

func run() int {
	verbose := flag.Bool("v", false, "print authzcov tables and probe statuses")
	out := flag.String("out", "", "results JSON path (default <repo>/eval/results/crapi.json)")
	flag.Parse()

	if _, err := exec.LookPath("docker"); err != nil {
		fatal("docker is required")
	}
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		fatal("the docker compose plugin is required")
	}
	root := repoRoot()
	here := filepath.Join(root, "e2e", "thirdparty", "crapi")
	if *out == "" {
		*out = filepath.Join(root, "eval", "results", "crapi.json")
	}
	tmp, err := os.MkdirTemp("", "crapieval-")
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
	spec := filepath.Join(here, "openapi.json")
	ids := filepath.Join(here, "identities.yaml")
	images := composeImages(filepath.Join(here, "compose.yaml"))

	var cases []scored
	var runs []runInfo
	for _, suite := range []string{"honest", "attack"} {
		t0 := time.Now()
		r, stop := recordSession(func() (stack, func()) { return startCrapi(here) }, suite, 3)
		stop() // the recording is complete; tear the stack down before analysing
		fmt.Printf("%s: recorded %d entries in %v\n", suite, len(r.entries), time.Since(t0).Round(time.Second))
		dir := filepath.Join(tmp, suite)
		check(os.MkdirAll(dir, 0o700))
		har := filepath.Join(dir, "rec.har")
		check(writeHAR(har, r.entries))
		cov := runCoverage(bin, root, spec, ids, har, dir)
		if *verbose {
			fmt.Printf("\n=== %s (%d entries) ===\n%s\n", suite, len(r.entries), cov.table)
		}
		ri := runInfo{Name: suite, Suite: suite, Entries: len(r.entries),
			CoveragePct: cov.Summary.Percent, Required: cov.Summary.Required, Covered: cov.Summary.Covered,
			Warnings: cov.warnings, Suspicious: []cell{}}
		if suite == "attack" {
			ri.Probes = taggedSteps(r.steps)
		}
		for _, f := range cov.Findings {
			if f.Kind == "suspicious_allow" {
				ri.Suspicious = append(ri.Suspicious, cell{Endpoint: f.Endpoint, Relationship: f.Relationship})
			}
		}
		sc := score(gt, suite, cov, r.steps)
		ri.Summary = result.Summarize(sc)
		runs = append(runs, ri)
		cases = append(cases, sc...)
	}

	res := buildResult(ver, images, cases, runs)
	check(result.Write(*out, res))
	printSummary(res, runs, cases)
	fmt.Println("wrote", *out)
	return 0
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

// score turns one suite run into cases.
//
//	honest: every authz item (documented, undocumented, query_param) scores "gap reported" (tp) or not (fn);
//	        controls and quirks are skipped, non_authz items are not scored.
//	attack: expect=allow items score tp (suspicious_allow raised) / fn; expect=deny and expect=noop items
//	        score tn (not flagged) / fp (flagged); non_authz items are out_of_scope.
func score(gt []gtItem, suite string, cov covOut, steps []step) []scored {
	var out []scored
	matched := map[cell]bool{}
	for _, g := range gt {
		c := cell{Endpoint: g.Endpoint, Relationship: g.Relationship}
		if !g.Authz && g.Category != "quirk" {
			if suite == "attack" {
				out = append(out, scored{ID: suite + "/" + g.ID, Kind: "non_authz", Expected: []cell{}, Flagged: []cell{},
					Result: "out_of_scope", Reason: "not an authorization problem: " + g.Name})
			}
			continue
		}
		_, gap := cov.has("gap", c.Endpoint, c.Relationship)
		sf, susp := cov.has("suspicious_allow", c.Endpoint, c.Relationship)
		if susp {
			matched[c] = true
		}
		observed := probeStatus(steps, g.Probe)
		r := scored{ID: suite + "/" + g.ID, Kind: g.Category, Expected: []cell{}, Flagged: []cell{}}
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
				r.Result, r.Reason = "fn", "no gap finding for this cell (covered or not required): "+missReason(cov, g)
			}
		default:
			switch {
			case g.Expect == "allow" && g.Authz:
				r.Expected = []cell{c}
				if susp {
					r.Flagged = []cell{c}
					r.Result, r.Reason = "tp", "suspicious_allow raised; probe status "+observed+": "+sf.Message
				} else {
					r.Result = "fn"
					r.Reason = "no suspicious_allow (probe status " + observed + "); " + missReason(cov, g)
				}
			case g.Expect == "noop" || !g.Authz: // 2xx that is not an authorization failure
				if susp {
					r.Flagged = []cell{c}
					r.Result, r.Reason = "fp", "flagged, but this is not an authorization failure: "+g.Name+" (probe status "+observed+"; "+sf.Message+")"
				} else {
					r.Result, r.Reason = "tn", "not flagged ("+g.Name+"; probe status "+observed+")"
				}
			default: // expected deny
				if susp {
					r.Flagged = []cell{c}
					r.Result, r.Reason = "fp", "suspicious_allow although crAPI denies here (probe status "+observed+"): "+sf.Message
				} else {
					r.Result, r.Reason = "tn", "denied by crAPI (probe status "+observed+") and not flagged"
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
		out = append(out, scored{ID: suite + "/unexpected/" + f.Endpoint + "/" + f.Relationship, Kind: "unexpected_flag",
			Expected: []cell{}, Flagged: []cell{c}, Result: "fp", Reason: why + ": " + f.Message})
	}
	// Honest suite: a suspicious_allow on a ground-truth cell is also unexpected, because the honest suite makes no such attempt.
	if suite == "honest" {
		for _, g := range gt {
			c := cell{Endpoint: g.Endpoint, Relationship: g.Relationship}
			if sf, ok := cov.has("suspicious_allow", c.Endpoint, c.Relationship); ok && matched[c] {
				out = append(out, scored{ID: suite + "/unexpected/" + g.ID, Kind: "unexpected_flag", Expected: []cell{},
					Flagged: []cell{c}, Result: "fp", Reason: "the honest suite made no such attempt: " + sf.Message})
			}
		}
	}
	return out
}

func missReason(cov covOut, g gtItem) string {
	c := cell{Endpoint: g.Endpoint, Relationship: g.Relationship}
	if g.Miss != "" {
		return g.Miss
	}
	if g.Category == "query_param" {
		return "the object is addressed by a query parameter; authzcov only analyses path parameters (expected miss)"
	}
	if _, ok := cov.has("gap", c.Endpoint, c.Relationship); ok {
		return "cell reported as a GAP (no observation matched)"
	}
	return "cell is shown as covered (ok) or not required; no suspicious_allow was raised: it needs an object owner or tenant with learned evidence, or (function-level) an anonymous 2xx on an operation whose spec requires auth, or a caller below a declared min_role"
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

var imageRE = regexp.MustCompile(`image:\s*([a-z0-9/._-]+)@(sha256:[0-9a-f]{64})`)

// composeImages lists name -> digest of every image of compose.yaml (so the result cannot drift from the file).
func composeImages(path string) map[string]string {
	b, err := os.ReadFile(path)
	check(err)
	m := map[string]string{}
	for _, x := range imageRE.FindAllStringSubmatch(string(b), -1) {
		m[x[1]] = x[2]
	}
	if len(m) == 0 {
		fatal("no digest-pinned images found in " + path)
	}
	return m
}

func buildResult(ver string, images map[string]string, cases []scored, runs []runInfo) *result.Result {
	names := make([]string, 0, len(images))
	for n := range images {
		names = append(names, n)
	}
	sort.Strings(names)
	return &result.Result{
		SchemaVersion: result.SchemaVersion,
		Suite:         "crapi",
		GeneratedAt:   result.Now(),
		Machine:       result.Machine(),
		Authzcov:      result.ParseVersion(ver),
		App: result.App{Name: "crAPI", Version: crapiTag + "@" + crapiCommit,
			ImageDigest: images["crapi/crapi-web"]},
		Cases:   cases,
		Summary: result.Summarize(cases),
		Extra: map[string]any{"runs": runs, "images": images, "image_order": names,
			"note": "tp/fn in honest runs = gap reported yes/no; attack runs = suspicious_allow vs ground truth; tn/fp only meaningful for expected-deny/not-authz cells; one fresh crAPI stack per suite"},
	}
}

func printSummary(res *result.Result, runs []runInfo, cases []scored) {
	fmt.Println("\n== runs ==")
	for _, r := range runs {
		fmt.Printf("%-8s entries=%-3d coverage=%5.1f%% (%d/%d) suspicious_allow=%d\n", r.Name, r.Entries, r.CoveragePct, r.Covered, r.Required, len(r.Suspicious))
	}
	fmt.Println("\n== cases ==")
	for _, c := range cases {
		fmt.Printf("%-12s %-44s %s\n", c.Result, c.ID, c.Reason)
	}
	sb, _ := json.Marshal(res.Summary)
	fmt.Printf("\nsummary: %s\n", sb)
}

// ---- docker compose ----------------------------------------------------------

var projectSeq atomic.Int32

// startCrapi brings up a fresh crAPI stack under a unique compose project and returns its endpoints and
// teardown. The teardown is registered before `up`, so a failure anywhere still removes containers and volumes.
func startCrapi(dir string) (stack, func()) {
	project := fmt.Sprintf("crapieval-%d-%d", os.Getpid(), projectSeq.Add(1))
	if run := os.Getenv("CRAPIEVAL_RUN"); run != "" { // set by run.sh so its trap can find the project
		project = fmt.Sprintf("crapieval-%s-%d-%d", run, os.Getpid(), projectSeq.Add(1))
	}
	compose := func(args ...string) *exec.Cmd {
		return exec.Command("docker", append([]string{"compose", "-p", project, "-f", filepath.Join(dir, "compose.yaml")}, args...)...)
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			if err := downStack(project, compose("down", "-v", "--remove-orphans", "--timeout", "5").Run); err != nil {
				fmt.Fprintln(os.Stderr, "crapieval: WARNING:", err)
				teardownFailed.Store(true)
			}
		})
	}
	addCleanup(stop)
	t0 := time.Now()
	up := compose("up", "-d", "--wait", "--wait-timeout", fmt.Sprint(int(upTimeout.Seconds())))
	var upOut strings.Builder
	up.Stdout, up.Stderr = &upOut, &upOut // progress lines are noise unless it fails
	if err := up.Run(); err != nil {
		fatal(fmt.Sprintf("docker compose up (project %s) failed or timed out after %v: %v\n%s", project, upTimeout, err, lastLines(upOut.String(), 25)))
	}
	st := stack{
		web:  "http://" + composePort(compose, "crapi-web", "80"),
		mail: "http://" + composePort(compose, "mailhog", "8025"),
	}
	c := &http.Client{Timeout: 15 * time.Second}
	if err := waitReady(c, st, readyLimit); err != nil {
		fatal(fmt.Sprintf("crAPI not ready: %v", err))
	}
	fmt.Printf("crAPI up on %s (project %s, %v)\n", st.web, project, time.Since(t0).Round(time.Second))
	return st, stop
}

func composePort(compose func(...string) *exec.Cmd, service, port string) string {
	b, err := compose("port", service, port).Output()
	if err != nil {
		fatal(fmt.Sprintf("docker compose port %s %s: %v", service, port, err))
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		fatal("no published port for " + service)
	}
	return s
}

// waitReady polls until nginx reaches all three crAPI services (an anonymous request must be answered by the
// service with 401, not 502/504 by the proxy) and MailHog answers. Nothing here is recorded and no user is created.
func waitReady(c *http.Client, st stack, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	var last string
	for time.Now().Before(deadline) {
		if ok, why := probeReady(c, st); ok {
			return nil
		} else {
			last = why
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("gave up after %v: %s", limit, last)
}

func probeReady(c *http.Client, st stack) (bool, string) {
	for _, p := range []string{"/identity/api/v2/vehicle/vehicles", "/community/api/v2/community/posts/recent", "/workshop/api/shop/products"} {
		resp, err := c.Get(st.web + p)
		if err != nil {
			return false, err.Error()
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			return false, fmt.Sprintf("%s: status %d, want 401", p, resp.StatusCode)
		}
	}
	resp, err := c.Get(st.mail + "/api/v2/messages?limit=1")
	if err != nil {
		return false, err.Error()
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("mailhog: status %d", resp.StatusCode)
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

var (
	cleanups       []func()
	cleanupsMu     sync.Mutex
	teardownFailed atomic.Bool
)

// downStack runs the compose teardown and returns its error, naming the project so leftovers can be removed.
func downStack(project string, down func() error) error {
	if err := down(); err != nil {
		return fmt.Errorf("docker compose down -v failed for project %s (remove it by hand): %w", project, err)
	}
	return nil
}

// handleSignals runs the cleanups and exits 130 when a signal arrives, so Ctrl-C or SIGTERM still tears down.
func handleSignals(ch <-chan os.Signal, exit func(int)) {
	go func() {
		s := <-ch
		fmt.Fprintln(os.Stderr, "crapieval: caught", s, "- cleaning up")
		runCleanups()
		exit(130)
	}()
}

// addCleanup registers f to run (LIFO, once) on normal return from main and before fatal exits.
func addCleanup(f func()) {
	cleanupsMu.Lock()
	defer cleanupsMu.Unlock()
	cleanups = append(cleanups, f)
}

func runCleanups() {
	for {
		cleanupsMu.Lock()
		if len(cleanups) == 0 {
			cleanupsMu.Unlock()
			return
		}
		f := cleanups[len(cleanups)-1]
		cleanups = cleanups[:len(cleanups)-1]
		cleanupsMu.Unlock()
		f()
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "crapieval:", msg)
	runCleanups() // os.Exit skips deferred calls
	os.Exit(1)
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}
