// Command tenantshop runs the tenantshop validation suites (mutants and ablation) and writes
// tenantshop-mutants.json and tenantshop-ablation.json into -out.
//
//	go run ./cmd/tenantshop -out results
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"authzcoveval/harness"
	"authzcoveval/result"
	"authzcoveval/tenantshop"
)

func main() {
	out := flag.String("out", "results", "output directory")
	verbose := flag.Bool("v", false, "print every authzcov run")
	flag.Parse()
	if err := run(*out, *verbose); err != nil {
		fmt.Fprintln(os.Stderr, "tenantshop eval:", err)
		os.Exit(1)
	}
}

func run(out string, verbose bool) error {
	root, err := harness.RepoRoot()
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "tenantshopeval-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	logf := func(string, ...any) {}
	if verbose {
		logf = func(f string, a ...any) { fmt.Printf(f+"\n", a...) }
	}
	env, err := tenantshop.NewEnv(root, tmp, logf)
	if err != nil {
		return err
	}
	fmt.Println("authzcov:", env.Version)
	for _, s := range []struct {
		file string
		run  func() (*result.Result, error)
	}{{"tenantshop-mutants.json", env.Mutants}, {"tenantshop-ablation.json", env.Ablation}} {
		r, err := s.run()
		if err != nil {
			return err
		}
		path := filepath.Join(out, s.file)
		if err := result.Write(path, r); err != nil {
			return err
		}
		print(r)
		fmt.Println("wrote", path)
	}
	return nil
}

func print(r *result.Result) {
	fmt.Printf("\n== %s ==\n", r.Suite)
	for _, c := range r.Cases {
		fmt.Printf("%-3s %-70s\n", c.Result, c.ID)
	}
	s := r.Summary
	f := func(p *float64) string {
		if p == nil {
			return "n/a"
		}
		return fmt.Sprint(*p)
	}
	fmt.Printf("tp %d fp %d fn %d tn %d  precision %s recall %s\n", s.TP, s.FP, s.FN, s.TN, f(s.Precision), f(s.Recall))
}
