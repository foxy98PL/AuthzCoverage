package cli

import (
	"fmt"
	"strings"

	"authzcov/internal/redact"

	"github.com/spf13/cobra"
)

// defaultOut is the default --out directory (a variable so tests can redirect it).
var defaultOut = "authzcov-out"

const (
	basePathAuto = "auto"
	basePathNone = "none"
)

type coverageOpts struct {
	spec       string
	hars       []string
	identities string
	strict     bool
	basePath   string
	out        string
	waivers    string // "" disables waivers
	// waiversExplicit is set when --waivers was given: the file must exist.
	waiversExplicit bool
}

func newCoverageCmd() *cobra.Command {
	var o coverageOpts
	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Report endpoint x relationship coverage from recorded traffic (no network)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.validate(); err != nil {
				return usageErr(err)
			}
			return runCoverage(&o, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.spec, "spec", "", "OpenAPI 3.x spec file (required)")
	f.StringArrayVar(&o.hars, "har", nil, "HAR file recorded from tests (repeatable, required)")
	f.StringVar(&o.identities, "identities", "", "identities.yaml file (required)")
	f.StringVar(&o.basePath, "base-path", basePathAuto, `URL prefix in front of spec paths: "auto" (detect per host), "none", or a path like /api`)
	f.StringVar(&o.out, "out", defaultOut, `directory for coverage.json ("" disables writing it)`)
	addWaiversFlag(cmd, &o.waivers, &o.waiversExplicit)
	f.BoolVar(&o.strict, "strict", false, "count an observation only with learned-or-better evidence: caller identity and, for object-level endpoints, owner (inferred ownership does not count)")
	return cmd
}

func (o *coverageOpts) validate() error {
	switch {
	case o.spec == "":
		return fmt.Errorf("missing --spec: pass an OpenAPI 3.x file")
	case len(o.hars) == 0:
		return fmt.Errorf("missing --har: pass at least one HAR file")
	case o.basePath != basePathAuto && o.basePath != basePathNone && !strings.HasPrefix(o.basePath, "/"):
		return fmt.Errorf("invalid --base-path %q: use auto, none, or a path starting with /", redact.StripControl(o.basePath))
	case o.identities == "":
		return fmt.Errorf("missing --identities: pass an identities.yaml file")
	}
	return nil
}
