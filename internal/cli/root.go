// Package cli wires cobra commands and flags. It holds no business logic.
package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newRootCmd(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "authzcov",
		Short:         "Code coverage for API authorization",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	// Flag parse errors are usage errors (exit 2).
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErr(err) })
	root.AddCommand(newBaselineCmd(), newCoverageCmd(), newDiscoverCmd(), newExplainCmd(), newExportCmd(), newGateCmd(), newRedactCmd(), newReportCmd(), newVersionCmd())
	return root
}

// Execute runs the CLI with args and returns the process exit code.
func Execute(args []string, stdout, stderr io.Writer) int {
	root := newRootCmd(stdout, stderr)
	root.SetArgs(args)
	err := root.Execute()
	if err == nil {
		return ExitOK
	}
	_, _ = fmt.Fprintf(stderr, "authzcov: %v\n", err)
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	// Remaining cobra errors (unknown command, bad args) are usage errors.
	return ExitUsage
}
