package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X authzcov/internal/cli.version=...".
var version = "dev"

// commit is set at build time via -ldflags "-X authzcov/internal/cli.commit=..."; empty when unknown.
var commit = ""

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the authzcov version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), versionString())
			return err
		},
	}
}

// versionString is "authzcov <version>", plus " (commit <commit>)" when the build set one.
func versionString() string {
	if commit == "" {
		return "authzcov " + version
	}
	return fmt.Sprintf("authzcov %s (commit %s)", version, commit)
}
