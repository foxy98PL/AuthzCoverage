package cli

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"authzcov/internal/baseline"
	"authzcov/internal/gate"
	"authzcov/internal/redact"
	"authzcov/internal/waivers"

	"github.com/spf13/cobra"
)

type gateOpts struct {
	in, base        string
	waivers         string
	waiversExplicit bool
	failOn          string
	maxDrop         float64
}

func newGateCmd() *cobra.Command {
	var o gateOpts
	cmd := &cobra.Command{
		Use:   "gate",
		Short: "Fail (exit 1) when coverage got worse than the baseline",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rules, err := gate.ParseRules(o.failOn)
			if err != nil {
				return usageErr(fmt.Errorf("--fail-on: %w", err))
			}
			// Inf would silently disable the drop rule.
			if math.IsNaN(o.maxDrop) || math.IsInf(o.maxDrop, 0) || o.maxDrop < 0 {
				return usageErr(errors.New("--max-drop must be a finite number >= 0"))
			}
			if o.in == "" {
				return usageErr(errors.New("missing --in: pass a coverage.json file"))
			}
			if o.base == "" {
				return usageErr(errors.New("missing --baseline: pass a baseline.json file"))
			}
			return runGate(&o, rules, cmd.OutOrStdout())
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.in, "in", defaultCovJSON, "coverage.json written by `authzcov coverage`")
	f.StringVar(&o.base, "baseline", defaultBaseline, "baseline.json to compare against")
	f.StringVar(&o.failOn, "fail-on", "new-gaps,regressions,drop,expired-waivers", "comma-separated rules that fail the gate")
	f.Float64Var(&o.maxDrop, "max-drop", 0.0, "largest allowed fall in coverage percentage points")
	addWaiversFlag(cmd, &o.waivers, &o.waiversExplicit)
	return cmd
}

func runGate(o *gateOpts, rules []gate.Rule, stdout io.Writer) error {
	ws, err := loadWaivers(o.waivers, o.waiversExplicit)
	if err != nil {
		return err
	}
	r, err := readReport(o.in, "", false)
	if err != nil {
		return err
	}
	if len(ws) > 0 {
		waivers.Apply(r, ws, today())
	}
	f, err := os.Open(o.base) //nolint:gosec // path is a user-supplied CLI argument
	if err != nil {
		return inputErr(fmt.Errorf("%s (create one with: authzcov baseline write)", redact.StripControl(err.Error())))
	}
	defer func() { _ = f.Close() }()
	old, err := baseline.Read(f)
	if err != nil {
		return inputErr(fmt.Errorf("%s: %w (create one with: authzcov baseline write)", redact.StripControl(o.base), err))
	}
	d := baseline.Compare(old, baseline.FromReport(r), r)
	expired := append([]string{}, d.Expired...)
	for _, w := range ws {
		if w.Expired(today()) {
			expired = append(expired, fmt.Sprintf("waiver for %s %s expired on %s", w.Endpoint, w.Relationship, w.ExpiresText))
		}
	}
	res := gate.Evaluate(gate.Input{Diff: d, Expired: expired, Rules: rules, MaxDrop: o.maxDrop})
	if err := printGate(stdout, res); err != nil {
		return &exitError{code: ExitInternal, err: err}
	}
	if !res.Pass {
		return &exitError{code: ExitGate, err: errors.New("gate failed")}
	}
	return nil
}

func printGate(w io.Writer, res gate.Result) error {
	var err error
	pf := func(format string, a ...any) {
		if err == nil {
			_, err = fmt.Fprintf(w, format, a...)
		}
	}
	if res.Pass {
		pf("gate: pass\n")
	} else {
		names := make([]string, len(res.Violations))
		for i, v := range res.Violations {
			names[i] = string(v.Rule)
		}
		pf("gate: FAIL (%s)\n", strings.Join(names, ", "))
	}
	for _, v := range res.Violations {
		if v.Rule == gate.Drop {
			pf("drop\n")
		} else {
			pf("%s (%d)\n", v.Rule, len(v.Items))
		}
		for _, it := range v.Items {
			pf("  %s\n", redact.StripControl(it))
		}
	}
	if res.Pass {
		pf("coverage %.1f%% -> %.1f%%\n", res.PercentWas, res.PercentNow)
	}
	if len(res.Removed) > 0 {
		pf("removed endpoints (%d)\n", len(res.Removed))
		for _, s := range res.Removed {
			pf("  %s\n", redact.StripControl(s))
		}
	}
	if len(res.Ignored) > 0 {
		parts := make([]string, len(res.Ignored))
		for i, v := range res.Ignored {
			n := len(v.Items)
			parts[i] = fmt.Sprintf("%s (%d)", v.Rule, n)
		}
		pf("ignored: %s\n", strings.Join(parts, ", "))
	}
	return err
}
