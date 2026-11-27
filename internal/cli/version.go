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
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "authzcov %s\n", version)
			return err
		},
	}
}
