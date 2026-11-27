// Command scaling measures how `authzcov coverage` scales with HAR size and writes scaling.json
// into -out. Fixtures come from the repo's own benchmark generator (internal/cli/bench_test.go).
//
//	go run ./cmd/scaling -sizes 1000,10000,100000,1000000 -runs 3 -out results
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"authzcoveval/harness"
	"authzcoveval/result"
)

const timeBin = "/usr/bin/time"

func main() {
	sizes := flag.String("sizes", "1000,10000,100000,1000000", "comma-separated HAR entry counts")
	runs := flag.Int("runs", 3, "coverage runs per size")
	out := flag.String("out", "results", "output directory")
	verbose := flag.Bool("v", false, "print every run")
	flag.Parse()
	if err := run(*sizes, *runs, *out, *verbose); err != nil {
		fmt.Fprintln(os.Stderr, "scaling eval:", err)
		os.Exit(1)
	}
}

// Point is the measurement of one HAR size.
type Point struct {
	Entries    int      `json:"entries"`
	HARBytes   int64    `json:"har_bytes"`
	Runs       int      `json:"runs"`
	WallMsMed  float64  `json:"wall_ms"`
	WallMsMin  float64  `json:"wall_ms_min"`
	WallMsMax  float64  `json:"wall_ms_max"`
	PeakRSSMiB *float64 `json:"peak_rss_mib"`
	NsPerEntry float64  `json:"ns_per_entry"`
	Required   int      `json:"required"`
	Covered    int      `json:"covered"`
	Percent    float64  `json:"percent"`
}

func run(sizesArg string, runs int, out string, verbose bool) error {
	sizes, err := parseSizes(sizesArg)
	if err != nil {
		return err
	}
	if runs < 1 {
		return fmt.Errorf("-runs must be >= 1")
	}
	root, err := harness.RepoRoot()
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "scalingeval-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	bin, version, err := harness.Build(root, tmp)
	if err != nil {
		return err
	}
	fmt.Println("authzcov:", version)
	haveTime := false
	if _, err := os.Stat(timeBin); err == nil {
		haveTime = true
	} else {
		fmt.Fprintln(os.Stderr, "warning: "+timeBin+" not found; peak RSS will be null")
	}
	var points []Point
	for _, n := range sizes {
		p, err := measure(root, tmp, bin, n, runs, haveTime, verbose)
		if err != nil {
			return fmt.Errorf("%d entries: %w", n, err)
		}
		rss := "n/a"
		if p.PeakRSSMiB != nil {
			rss = fmt.Sprintf("%.1f MiB", *p.PeakRSSMiB)
		}
		fmt.Printf("%9d entries  %7.1f MB  %9.1f ms  %s  %.0f ns/entry  covered %d/%d\n",
			p.Entries, float64(p.HARBytes)/1e6, p.WallMsMed, rss, p.NsPerEntry, p.Covered, p.Required)
		points = append(points, *p)
	}
	fits := map[string]any{"time_slope": nil, "rss_ratio": nil}
	if len(points) >= 2 {
		fits["time_slope"] = round(slope(points), 3)
		if a, b := points[0].PeakRSSMiB, points[len(points)-1].PeakRSSMiB; a != nil && b != nil && *a > 0 {
			fits["rss_ratio"] = round(*b / *a, 3)
			fits["rss_ratio_sizes"] = []int{points[0].Entries, points[len(points)-1].Entries}
		}
	}
	r := &result.Result{
		SchemaVersion: result.SchemaVersion,
		Suite:         "scaling",
		GeneratedAt:   result.Now(),
		App:           result.App{Name: "synthetic", Version: "bench fixture"},
		Authzcov:      result.ParseVersion(version),
		Machine:       result.Machine(),
		Cases:         []result.Case{},
		Extra: map[string]any{
			"points":  points,
			"fits":    fits,
			"runs":    runs,
			"note":    "machine-dependent timings; wall_ms is the median over runs, peak_rss_mib the maximum",
			"rss_src": map[bool]string{true: timeBin + " -v (Maximum resident set size)", false: "unavailable"}[haveTime],
		},
	}
	r.Summary = result.Summarize(r.Cases)
	path := filepath.Join(out, "scaling.json")
	if err := result.Write(path, r); err != nil {
		return err
	}
	fmt.Printf("time slope (log-log wall_ms vs entries): %v   rss ratio largest/smallest: %v\n", fits["time_slope"], fits["rss_ratio"])
	fmt.Println("wrote", path)
	return nil
}

func parseSizes(s string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 1 {
			return nil, fmt.Errorf("bad size %q in -sizes", f)
		}
		out = append(out, n)
	}
	sort.Ints(out)
	return out, nil
}

func measure(root, tmp, bin string, n, runs int, haveTime, verbose bool) (*Point, error) {
	fx, err := os.MkdirTemp(tmp, "fx-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(fx) }()
	gen := exec.Command("go", "test", "./internal/cli", "-run", "^TestWriteBenchFixture$", "-count=1")
	gen.Dir = root
	gen.Env = append(os.Environ(), "AUTHZCOV_BENCH_FIXTURE_DIR="+fx, "AUTHZCOV_BENCH_ENTRIES="+strconv.Itoa(n))
	if b, err := gen.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("generate fixture: %v\n%s", err, b)
	}
	har := filepath.Join(fx, "bench.har")
	st, err := os.Stat(har)
	if err != nil {
		return nil, err
	}
	p := &Point{Entries: n, HARBytes: st.Size(), Runs: runs}
	var walls []float64
	var maxKB float64
	for i := 0; i < runs; i++ {
		od := filepath.Join(fx, fmt.Sprintf("out%d", i))
		if err := os.Mkdir(od, 0o755); err != nil {
			return nil, err
		}
		args := []string{"coverage", "--spec", filepath.Join(fx, "spec.yaml"), "--har", har,
			"--identities", filepath.Join(fx, "identities.yaml"), "--out", od}
		name := bin
		if haveTime {
			name, args = timeBin, append([]string{"-v", bin}, args...)
		}
		c := exec.Command(name, args...)
		c.Dir = od
		var se strings.Builder
		c.Stderr = &se
		start := time.Now()
		_ = c.Run() // exit 1 = gaps found; a missing coverage.json is the real failure
		wall := float64(time.Since(start).Microseconds()) / 1000
		raw, err := os.ReadFile(filepath.Join(od, "coverage.json"))
		if err != nil {
			return nil, fmt.Errorf("run %d produced no coverage.json: %s", i, tail(se.String()))
		}
		var cov struct {
			Summary struct {
				Required int     `json:"required"`
				Covered  int     `json:"covered"`
				Percent  float64 `json:"percent"`
			} `json:"summary"`
		}
		if err := json.Unmarshal(raw, &cov); err != nil {
			return nil, err
		}
		p.Required, p.Covered, p.Percent = cov.Summary.Required, cov.Summary.Covered, cov.Summary.Percent
		kb := -1.0
		if haveTime {
			if m := rssRE.FindStringSubmatch(se.String()); m != nil {
				kb, _ = strconv.ParseFloat(m[1], 64)
			}
		}
		if kb > maxKB {
			maxKB = kb
		}
		if verbose {
			fmt.Printf("  run %d: %.1f ms, rss %.0f KiB\n", i+1, wall, kb)
		}
		walls = append(walls, wall)
		_ = os.RemoveAll(od)
	}
	sort.Float64s(walls)
	p.WallMsMin, p.WallMsMax = round(walls[0], 1), round(walls[len(walls)-1], 1)
	p.WallMsMed = round(median(walls), 1)
	p.NsPerEntry = round(p.WallMsMed*1e6/float64(n), 0)
	if maxKB > 0 {
		v := round(maxKB/1024, 1)
		p.PeakRSSMiB = &v
	}
	return p, nil
}

var rssRE = regexp.MustCompile(`Maximum resident set size \(kbytes\): (\d+)`)

func tail(s string) string {
	if len(s) > 400 {
		return s[len(s)-400:]
	}
	return s
}

func median(s []float64) float64 {
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

func round(f float64, d int) float64 { p := math.Pow(10, float64(d)); return math.Round(f*p) / p }

// slope is the least-squares slope of ln(wall_ms) against ln(entries).
func slope(ps []Point) float64 {
	var sx, sy, sxx, sxy float64
	for _, p := range ps {
		x, y := math.Log(float64(p.Entries)), math.Log(math.Max(p.WallMsMed, 1e-3))
		sx, sy, sxx, sxy = sx+x, sy+y, sxx+x*x, sxy+x*y
	}
	n := float64(len(ps))
	return (n*sxy - sx*sy) / (n*sxx - sx*sx)
}
