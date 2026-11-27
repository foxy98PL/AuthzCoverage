package cli

import (
	"fmt"
	"io"
	"os"

	"authzcov/internal/redact"
	"authzcov/internal/report/coveragejson"
	htmlreport "authzcov/internal/report/html"
	"authzcov/internal/report/markdown"
	"authzcov/internal/report/sarif"
	"authzcov/internal/report/table"

	"github.com/spf13/cobra"
)

const (
	formatTable = "table"
	formatJSON  = "json"
	formatMD    = "markdown"
	formatSARIF = "sarif"
	formatHTML  = "html"
)

type reportOpts struct {
	in, format string
}

func newReportCmd() *cobra.Command {
	var o reportOpts
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render a coverage.json again (no HAR, spec or identities needed)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			switch {
			case o.in == "":
				return usageErr(fmt.Errorf("missing --in: pass a coverage.json file"))
			case o.format != formatTable && o.format != formatJSON && o.format != formatMD && o.format != formatSARIF && o.format != formatHTML:
				return usageErr(fmt.Errorf("invalid --format %q: use table, json, markdown, sarif or html", redact.StripControl(o.format)))
			}
			return runReport(&o, cmd.OutOrStdout())
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.in, "in", "", "coverage.json written by `authzcov coverage` (required)")
	f.StringVar(&o.format, "format", formatTable, "output format: table, json, markdown (sized for a PR comment) sarif (GitHub code scanning) or html (self-contained page with filters)")
	return cmd
}

func runReport(o *reportOpts, stdout io.Writer) error {
	f, err := os.Open(o.in) //nolint:gosec // path is a user-supplied CLI argument
	if err != nil {
		return inputErr(err)
	}
	defer func() { _ = f.Close() }()
	r, err := coveragejson.Read(f)
	if err != nil {
		return inputErr(fmt.Errorf("%s: %w", redact.StripControl(o.in), err))
	}
	if o.format == formatJSON {
		if err := coveragejson.Write(stdout, r); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		return nil
	}
	if o.format == formatHTML {
		// Same control-character filter as table/markdown (review KAN-22 F2).
		if err := htmlreport.Render(redact.NewWriter(stdout), r); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		return nil
	}
	if o.format == formatSARIF {
		if err := sarif.Render(stdout, r); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		return nil
	}
	if o.format == formatMD {
		if err := markdown.Render(redact.NewWriter(stdout), r); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		return nil
	}
	m, err := coveragejson.ToMatrix(r)
	if err != nil {
		return inputErr(fmt.Errorf("%s: %w", redact.StripControl(o.in), err))
	}
	if err := table.RenderWith(redact.NewWriter(stdout), m, table.Options{SuspiciousAllows: r.Summary.SuspiciousAllows}); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}
