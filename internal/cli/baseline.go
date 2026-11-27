package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"authzcov/internal/baseline"
	"authzcov/internal/redact"
	"authzcov/internal/report/coveragejson"
	"authzcov/internal/waivers"

	"github.com/spf13/cobra"
)

const (
	defaultWaivers  = ".authzcov/waivers.yaml"
	defaultBaseline = ".authzcov/baseline.json"
	defaultCovJSON  = "authzcov-out/coverage.json"
)

// now is the clock for waiver expiry; tests override it.
var now = time.Now

// today is the UTC calendar date of now() at midnight.
func today() time.Time {
	y, m, d := now().UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// addWaiversFlag registers --waivers and records whether it was given.
func addWaiversFlag(cmd *cobra.Command, dst *string, explicit *bool) {
	cmd.Flags().StringVar(dst, "waivers", defaultWaivers, "waivers.yaml file; the default is used only if it exists")
	prev := cmd.PreRunE
	cmd.PreRunE = func(c *cobra.Command, args []string) error {
		*explicit = c.Flags().Changed("waivers")
		if prev != nil {
			return prev(c, args)
		}
		return nil
	}
}

// loadWaivers loads path when set. A missing default file means no waivers; a
// missing explicit file or an invalid file is a usage error (exit 2).
func loadWaivers(path string, explicit bool) ([]waivers.Waiver, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			return nil, nil
		}
		return nil, usageErr(fmt.Errorf("waivers file: %s", redact.StripControl(err.Error())))
	}
	ws, err := waivers.Load(path, today())
	if err != nil {
		return nil, usageErr(errors.New(redact.StripControl(err.Error())))
	}
	return ws, nil
}

func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Write a coverage baseline and diff a result against it",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newBaselineWriteCmd(), newBaselineDiffCmd())
	return cmd
}

type baselineOpts struct {
	in, out, base   string
	waivers         string
	waiversExplicit bool
}

func newBaselineWriteCmd() *cobra.Command {
	var o baselineOpts
	cmd := &cobra.Command{
		Use:   "write",
		Short: "Write .authzcov/baseline.json from a coverage.json",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.in == "" {
				return usageErr(errors.New("missing --in: pass a coverage.json file"))
			}
			if o.out == "" {
				return usageErr(errors.New("missing --out: pass the baseline file to write"))
			}
			return runBaselineWrite(&o, cmd.ErrOrStderr())
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.in, "in", defaultCovJSON, "coverage.json written by `authzcov coverage`")
	f.StringVar(&o.out, "out", defaultBaseline, "baseline file to write")
	addWaiversFlag(cmd, &o.waivers, &o.waiversExplicit)
	return cmd
}

func newBaselineDiffCmd() *cobra.Command {
	var o baselineOpts
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show how a coverage.json differs from the baseline (exit 0; gating is `check`)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.base == "" {
				return usageErr(errors.New("missing --baseline: pass a baseline.json file"))
			}
			if o.in == "" {
				return usageErr(errors.New("missing --in: pass a coverage.json file"))
			}
			return runBaselineDiff(&o, cmd.OutOrStdout())
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.base, "baseline", defaultBaseline, "baseline.json to compare against")
	f.StringVar(&o.in, "in", defaultCovJSON, "coverage.json written by `authzcov coverage`")
	addWaiversFlag(cmd, &o.waivers, &o.waiversExplicit)
	return cmd
}

// readReport reads a coverage.json and applies waivers when given.
func readReport(path, waiversPath string, explicit bool) (*coveragejson.Report, error) {
	ws, err := loadWaivers(waiversPath, explicit)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path) //nolint:gosec // path is a user-supplied CLI argument
	if err != nil {
		return nil, inputErr(err)
	}
	defer func() { _ = f.Close() }()
	r, err := coveragejson.Read(f)
	if err != nil {
		return nil, inputErr(fmt.Errorf("%s: %w", redact.StripControl(path), err))
	}
	if len(ws) > 0 {
		waivers.Apply(r, ws, today())
	}
	return r, nil
}

func runBaselineWrite(o *baselineOpts, stderr io.Writer) error {
	r, err := readReport(o.in, o.waivers, o.waiversExplicit)
	if err != nil {
		return err
	}
	if err := writeBaseline(o.out, baseline.FromReport(r)); err != nil {
		return &exitError{code: ExitInternal, err: err}
	}
	_, _ = fmt.Fprintf(stderr, "wrote %s\n", redact.StripControl(o.out))
	return nil
}

// writeBaseline writes b to path atomically (temp file + rename).
func writeBaseline(path string, b *baseline.Baseline) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // baseline is committed and meant to be readable
		return fmt.Errorf("create baseline directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".baseline-*.json")
	if err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if err := baseline.Write(tmp, b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write baseline: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil { //nolint:gosec // baseline is committed and meant to be readable
		_ = tmp.Close()
		return fmt.Errorf("write baseline: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	return nil
}

func runBaselineDiff(o *baselineOpts, stdout io.Writer) error {
	r, err := readReport(o.in, o.waivers, o.waiversExplicit)
	if err != nil {
		return err
	}
	f, err := os.Open(o.base) //nolint:gosec // path is a user-supplied CLI argument
	if err != nil {
		return inputErr(err)
	}
	defer func() { _ = f.Close() }()
	old, err := baseline.Read(f)
	if err != nil {
		return inputErr(fmt.Errorf("%s: %w", redact.StripControl(o.base), err))
	}
	d := baseline.Compare(old, baseline.FromReport(r), r)
	return printDiff(stdout, d)
}

func printDiff(w io.Writer, d baseline.Diff) error {
	var err error
	pf := func(format string, a ...any) {
		if err == nil {
			_, err = fmt.Fprintf(w, format, a...)
		}
	}
	strs := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		pf("%s (%d)\n", title, len(items))
		for _, s := range items {
			pf("  %s\n", redact.StripControl(s))
		}
		pf("\n")
	}
	changes := func(title string, items []baseline.Change) {
		if len(items) == 0 {
			return
		}
		pf("%s (%d)\n", title, len(items))
		for _, c := range items {
			was := c.Was
			if was == "" {
				was = "new"
			}
			pf("  %s  %s  %s -> %s\n", redact.StripControl(c.Endpoint), redact.StripControl(c.Relationship),
				redact.StripControl(was), redact.StripControl(c.Now))
		}
		pf("\n")
	}
	strs("new endpoints", d.NewEndpoints)
	changes("new gaps", d.NewGaps)
	changes("regressions", d.Regressions)
	changes("improvements", d.Improvements)
	changes("waived", d.Waived)
	strs("expired waivers", d.Expired)
	strs("removed endpoints", d.Removed)
	pf("coverage %.1f%% -> %.1f%%\n", d.PercentWas, d.PercentNow)
	return err
}
