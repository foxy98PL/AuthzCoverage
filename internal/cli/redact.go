package cli

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"authzcov/internal/redact"

	"github.com/spf13/cobra"
)

type redactOpts struct {
	pseudonymize bool
	in, out      string
	keepClaims   []string
	keyFile      string
	force        bool
}

func newRedactCmd() *cobra.Command {
	var o redactOpts
	cmd := &cobra.Command{
		Use:   "redact",
		Short: "Turn a raw HAR recording into a fixture that is safe to commit",
		Long: "redact --pseudonymize rewrites a HAR so no credential, personal data or real host survives,\n" +
			"while coverage of the result stays identical: JWTs are re-signed with a public test key keeping\n" +
			"only --keep-claims, opaque credentials become tok_<hash8>, hosts become h<N>.test.\n" +
			"See docs/redact.md. Review the output before committing it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRedact(&o, cmd.ErrOrStderr())
		},
	}
	f := cmd.Flags()
	f.BoolVar(&o.pseudonymize, "pseudonymize", false, "replace credentials, identifiers and hosts by stable pseudonyms (required)")
	f.StringVar(&o.in, "in", "", "raw HAR file (required)")
	f.StringVar(&o.out, "out", "", "pseudonymised HAR file to write (required)")
	f.StringSliceVar(&o.keepClaims, "keep-claims", []string{"sub"}, "JWT claims kept (with their values) in re-signed tokens")
	f.StringVar(&o.keyFile, "key-file", "", "file with a secret of at least 32 bytes for reproducible output (default: random per run)")
	f.BoolVar(&o.force, "force", false, "overwrite --out if it exists")
	return cmd
}

func (o *redactOpts) validate() error {
	switch {
	case !o.pseudonymize:
		return errors.New("only --pseudonymize is supported")
	case o.in == "":
		return errors.New("missing --in: pass the raw HAR file")
	case o.out == "":
		return errors.New("missing --out: pass the file to write")
	}
	for _, c := range o.keepClaims {
		if c == "" {
			return errors.New("empty claim name in --keep-claims")
		}
	}
	inAbs, err1 := filepath.Abs(o.in)
	outAbs, err2 := filepath.Abs(o.out)
	same := err1 == nil && err2 == nil && inAbs == outAbs
	if !same {
		if a, err := os.Stat(o.in); err == nil {
			if b, err := os.Stat(o.out); err == nil && os.SameFile(a, b) {
				same = true
			}
		}
	}
	if same {
		return errors.New("--out must not be the same file as --in")
	}
	return nil
}

func runRedact(o *redactOpts, stderr io.Writer) error {
	if err := o.validate(); err != nil {
		return usageErr(err)
	}
	if _, err := os.Lstat(o.out); err == nil && !o.force {
		return usageErr(fmt.Errorf("%s exists; pass --force to overwrite", redact.StripControl(o.out)))
	}
	key, err := runKey(o.keyFile)
	if err != nil {
		return err
	}
	p, err := redact.NewPseudonymizer(redact.PseudoOptions{Key: key, KeepClaims: o.keepClaims})
	if err != nil {
		return usageErr(err)
	}
	in, err := os.Open(o.in) //nolint:gosec // user-supplied path by design
	if err != nil {
		return inputErr(fmt.Errorf("open %s: %w", redact.StripControl(o.in), errors.Unwrap(err)))
	}
	defer func() { _ = in.Close() }()

	tmp, err := os.CreateTemp(filepath.Dir(o.out), ".authzcov-redact-*")
	if err != nil {
		return inputErr(fmt.Errorf("create temp file next to %s: %w", redact.StripControl(o.out), errors.Unwrap(err)))
	}
	done := false
	defer func() {
		if !done {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return inputErr(err)
	}
	if err := p.HAR(bufio.NewReader(in), tmp); err != nil {
		return inputErr(fmt.Errorf("%s: %w", redact.StripControl(o.in), err))
	}
	if err := tmp.Sync(); err != nil {
		return inputErr(err)
	}
	if err := tmp.Close(); err != nil {
		return inputErr(err)
	}
	if err := os.Rename(tmp.Name(), o.out); err != nil {
		return inputErr(fmt.Errorf("write %s: %w", redact.StripControl(o.out), errors.Unwrap(err)))
	}
	done = true

	st := p.Stats()
	w := redact.NewWriter(stderr)
	_, _ = fmt.Fprintf(w, "redact: %d entries; tokens re-signed %d, replaced %d; headers masked %d, cookies masked %d; hosts mapped %d; body fields masked %d; emails %d; bodies dropped %d\n",
		st.Entries, st.TokensResigned, st.TokensReplaced, st.HeadersMasked, st.CookiesMasked, st.HostsMapped, st.BodyFields, st.Emails, st.BodiesDropped)
	_, _ = fmt.Fprintf(w, "redact: wrote %s (mode 0600). Review it before committing.\n", o.out)
	return nil
}

// runKey returns the run key: the contents of keyFile, or 32 random bytes.
func runKey(keyFile string) ([]byte, error) {
	if keyFile == "" {
		k := make([]byte, redact.MinPseudoKey)
		if _, err := rand.Read(k); err != nil {
			return nil, fmt.Errorf("random key: %w", err)
		}
		return k, nil
	}
	f, err := os.Open(keyFile) //nolint:gosec // user-supplied path by design
	if err != nil {
		return nil, usageErr(fmt.Errorf("open --key-file: %w", errors.Unwrap(err)))
	}
	defer func() { _ = f.Close() }()
	k, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, usageErr(errors.New("read --key-file failed"))
	}
	if len(k) < redact.MinPseudoKey {
		return nil, usageErr(fmt.Errorf("--key-file must hold at least %d bytes", redact.MinPseudoKey))
	}
	return k, nil
}
