package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

// newFingerprintCmd prints the full SHA-256 of a credential value read from stdin, for the
// token_sha256 / apikey_sha256 keys of identities.yaml (discover only knows 12 hex characters).
// It hashes the same value the ingest hashes: the bare cookie value, API key or bearer token.
func newFingerprintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fingerprint",
		Short: "Print the SHA-256 of a credential read from stdin, for identities.yaml (no network)",
		Long: "Reads one credential value (a cookie value, API key or bearer token, not the header name) from stdin\n" +
			"and prints its 64-hex SHA-256 for token_sha256 in identities.yaml. One trailing newline is ignored.\n" +
			"Example: printf %s \"$API_KEY\" | authzcov fingerprint",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 1<<20))
			if err != nil {
				return err
			}
			v := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
			if v == "" {
				return errors.New("empty credential on stdin")
			}
			sum := sha256.Sum256([]byte(v))
			_, err = cmd.OutOrStdout().Write([]byte(hex.EncodeToString(sum[:]) + "\n"))
			return err
		},
	}
}
