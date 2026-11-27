// Package harness builds authzcov from source and runs `authzcov coverage` for the evals.
package harness

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RepoRoot finds the authzcov module root above the working directory.
func RepoRoot() (string, error) {
	d, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if b, err := os.ReadFile(filepath.Join(d, "go.mod")); err == nil && strings.HasPrefix(string(b), "module authzcov\n") {
			return d, nil
		}
		p := filepath.Dir(d)
		if p == d {
			return "", fmt.Errorf("repo root (module authzcov) not found above the working directory")
		}
		d = p
	}
}

// Build compiles authzcov from root into dir and returns the binary path and its `version` output.
func Build(root, dir string) (bin, version string, err error) {
	gv := strings.TrimSpace(outOr(root, "dev", "git", "describe", "--tags", "--always", "--dirty"))
	gc := strings.TrimSpace(outOr(root, "", "git", "rev-parse", "--short", "HEAD"))
	bin = filepath.Join(dir, "authzcov")
	c := exec.Command("go", "build", "-trimpath", "-ldflags",
		"-X authzcov/internal/cli.version="+gv+" -X authzcov/internal/cli.commit="+gc, "-o", bin, "./cmd/authzcov")
	c.Dir = root
	if b, err := c.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("build authzcov: %v\n%s", err, b)
	}
	b, err := exec.Command(bin, "version").Output()
	if err != nil {
		return "", "", err
	}
	return bin, strings.TrimSpace(string(b)), nil
}

func outOr(dir, def, name string, args ...string) string {
	c := exec.Command(name, args...)
	c.Dir = dir
	b, err := c.Output()
	if err != nil {
		return def
	}
	return string(b)
}

// Cell is one matrix cell of coverage.json.
type Cell struct {
	Endpoint     string         `json:"endpoint"`
	Relationship string         `json:"relationship"`
	Required     bool           `json:"required"`
	Covered      bool           `json:"covered"`
	Statuses     map[string]int `json:"statuses"`
}

// Finding is one coverage.json finding.
type Finding struct {
	Kind         string `json:"kind"`
	Endpoint     string `json:"endpoint"`
	Relationship string `json:"relationship"`
	Message      string `json:"message"`
}

// Endpoint is one coverage.json endpoint.
type Endpoint struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Resource string `json:"resource"`
}

// Coverage is the part of coverage.json the evals read.
type Coverage struct {
	Cells     []Cell     `json:"cells"`
	Findings  []Finding  `json:"findings"`
	Endpoints []Endpoint `json:"endpoints"`
	Inputs    struct {
		HAR []struct {
			Entries int `json:"entries"`
		} `json:"har"`
	} `json:"inputs"`
	Summary struct {
		Required int     `json:"required"`
		Covered  int     `json:"covered"`
		Percent  float64 `json:"percent"`
	} `json:"summary"`
	Table string `json:"-"` // stdout of the run
}

// Entries is the number of HAR entries authzcov read.
func (c *Coverage) Entries() int {
	n := 0
	for _, h := range c.Inputs.HAR {
		n += h.Entries
	}
	return n
}

// Cell returns the cell for (endpoint, relationship).
func (c *Coverage) Cell(endpoint, rel string) (Cell, bool) {
	for _, x := range c.Cells {
		if x.Endpoint == endpoint && x.Relationship == rel {
			return x, true
		}
	}
	return Cell{}, false
}

// Suspicious returns the suspicious_allow finding for (endpoint, relationship).
func (c *Coverage) Suspicious(endpoint, rel string) (Finding, bool) {
	for _, f := range c.Findings {
		if f.Kind == "suspicious_allow" && f.Endpoint == endpoint && f.Relationship == rel {
			return f, true
		}
	}
	return Finding{}, false
}

// Run executes `authzcov coverage` (in dir, so no waivers file is picked up) and parses coverage.json.
// Exit status 1 (gaps found) is not an error; a missing coverage.json is.
func Run(bin, spec, identities, har, dir string) (*Coverage, error) {
	c := exec.Command(bin, "coverage", "--spec", spec, "--identities", identities, "--har", har, "--out", dir)
	c.Dir = dir
	var so, se strings.Builder
	c.Stdout, c.Stderr = &so, &se
	_ = c.Run()
	raw, err := os.ReadFile(filepath.Join(dir, "coverage.json"))
	if err != nil {
		return nil, fmt.Errorf("authzcov produced no coverage.json: %s%s", se.String(), so.String())
	}
	var cov Coverage
	if err := json.Unmarshal(raw, &cov); err != nil {
		return nil, err
	}
	cov.Table = so.String()
	return &cov, nil
}
