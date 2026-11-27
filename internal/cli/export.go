package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"authzcov/internal/plan"
	"authzcov/internal/redact"
	"authzcov/internal/report/coveragejson"

	"github.com/spf13/cobra"
)

type exportOpts struct {
	plan       bool
	in, out    string
	include    string
	spec       string
	hars       []string
	identities string
	basePath   string
}

func newExportCmd() *cobra.Command {
	var o exportOpts
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the coverage gaps as a probe plan other authorization testers can run",
		Long: "export --plan writes the required-but-missing cells of a coverage.json as a versioned JSON probe plan\n" +
			"(schema/plan.v1.json, docs/plan.md). The plan names attacker identities, never credentials, and carries\n" +
			"only id_hash for objects. With --har, --spec and --identities the pipeline is re-run to add raw example\n" +
			"object IDs; that file contains raw IDs (mode 0600): never commit it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.validate(); err != nil {
				return usageErr(err)
			}
			return runExportPlan(&o, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	f := cmd.Flags()
	f.BoolVar(&o.plan, "plan", false, "export a probe plan (required)")
	f.StringVar(&o.in, "in", "", "coverage.json written by `authzcov coverage` (required)")
	f.StringVar(&o.out, "out", "", "file to write (default: stdout; required with --har)")
	f.StringVar(&o.include, "include", "", `also export waived gaps: "waived"`)
	f.StringVar(&o.spec, "spec", "", "OpenAPI spec, to add raw example IDs (with --har and --identities)")
	f.StringArrayVar(&o.hars, "har", nil, "HAR file, to add raw example IDs (repeatable; the plan then contains raw IDs)")
	f.StringVar(&o.identities, "identities", "", "identities.yaml, to add raw example IDs (with --har and --spec)")
	f.StringVar(&o.basePath, "base-path", basePathAuto, `URL prefix in front of spec paths, as for coverage: "auto", "none", or a path like /api (only with --har)`)
	return cmd
}

func (o *exportOpts) raw() bool { return len(o.hars) > 0 }

func (o *exportOpts) validate() error {
	switch {
	case !o.plan:
		return errors.New("missing --plan: it is the only export supported")
	case o.in == "":
		return errors.New("missing --in: pass a coverage.json file")
	case o.include != "" && o.include != "waived":
		return fmt.Errorf("invalid --include %q: use waived", redact.StripControl(o.include))
	case o.raw() && (o.spec == "" || o.identities == ""):
		return errors.New("--har needs --spec and --identities too (the pipeline is re-run to find raw example IDs)")
	case !o.raw() && (o.spec != "" || o.identities != ""):
		return errors.New("--spec and --identities are only used together with --har")
	case o.raw() && o.out == "":
		return errors.New("a plan with raw object IDs (--har) is only written to a 0600 file: pass --out <file>")
	}
	return validateBasePath(o.basePath)
}

func runExportPlan(o *exportOpts, stdout, stderr io.Writer) error {
	raw, err := os.ReadFile(o.in) //nolint:gosec // path is a user-supplied CLI argument
	if err != nil {
		return inputErr(err)
	}
	if len(raw) > coveragejson.MaxSize {
		return inputErr(fmt.Errorf("%s: larger than %d bytes", redact.StripControl(o.in), coveragejson.MaxSize))
	}
	rep, err := coveragejson.Read(bytes.NewReader(raw))
	if err != nil {
		return inputErr(fmt.Errorf("%s: %w", redact.StripControl(o.in), err))
	}
	opt := plan.Options{IncludeWaived: o.include == "waived"}
	if o.raw() {
		if opt.Raw, err = rawFromPipeline(o, rep, stderr); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(stderr, "warning: the plan contains raw object IDs from the recording; never commit or share it")
	}
	p := plan.Build(rep, opt)
	sum := sha256.Sum256(raw)
	p.Source.CoverageSHA256 = hex.EncodeToString(sum[:])
	p.GeneratedAt = clock()().UTC().Format("2006-01-02T15:04:05Z")

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(p); err != nil {
		return fmt.Errorf("encode plan: %w", err)
	}
	if o.out == "" { // raw-ID plans never get here: validate requires --out
		_, err := stdout.Write(buf.Bytes())
		return err
	}
	mode := os.FileMode(0o644)
	if o.raw() {
		mode = 0o600
	}
	if err := writeFileAtomic(o.out, buf.Bytes(), mode); err != nil {
		return &exitError{code: ExitInternal, err: err}
	}
	_, _ = fmt.Fprintf(stderr, "wrote %s (%d probes)\n", redact.StripControl(o.out), len(p.Probes))
	return nil
}

// rawFromPipeline re-runs the coverage pipeline (the same analyze function as
// `authzcov coverage`) to resolve raw object IDs, tenant path parameters and
// declared identities. coverage.json stays the source of the gaps.
func rawFromPipeline(o *exportOpts, rep *coveragejson.Report, stderr io.Writer) (*plan.Raw, error) {
	a, err := analyze(&coverageOpts{spec: o.spec, hars: o.hars, identities: o.identities, basePath: o.basePath}, stderr)
	if err != nil {
		return nil, err
	}
	for _, in := range []struct{ name, path, want string }{
		{"--spec", o.spec, rep.Inputs.Spec.SHA256}, {"--identities", o.identities, rep.Inputs.Identities.SHA256},
	} {
		if sum, err := fileSHA256(in.path); err == nil && sum != in.want {
			_, _ = fmt.Fprintf(stderr, "warning: %s differs from the file coverage.json was built from; example IDs may not match\n", in.name)
		}
	}
	if !sameStrings(harSHA256s(o.hars), harRecorded(rep)) {
		_, _ = fmt.Fprintln(stderr, "warning: --har files differ from the HAR files coverage.json was built from; example IDs may not match")
	}
	r := &plan.Raw{IDs: map[string]string{}, TenantParams: map[string]bool{}}
	for _, ob := range a.objects {
		r.IDs[ob.Resource+"/"+coveragejson.ObjectHash(ob.Resource, ob.ID)] = ob.ID
	}
	for p := range a.cfg.TenantParams {
		r.TenantParams[p] = true
	}
	for _, id := range a.cfg.Identities {
		r.Declared = append(r.Declared, coveragejson.Identity{Name: id.Name, Role: id.Role, Rank: a.cfg.Roles[id.Role], Tenant: id.Tenant})
	}
	return r, nil
}

// harSHA256s returns the sorted hashes of the given files; an unreadable file
// contributes "" so it never matches.
func harSHA256s(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		sum, _ := fileSHA256(p)
		out = append(out, sum)
	}
	slices.Sort(out)
	return out
}

func harRecorded(rep *coveragejson.Report) []string {
	out := make([]string, 0, len(rep.Inputs.HAR))
	for _, h := range rep.Inputs.HAR {
		out = append(out, h.SHA256)
	}
	slices.Sort(out)
	return out
}

func sameStrings(a, b []string) bool { return slices.Equal(a, b) }

// writeFileAtomic writes data to path via a temp file and rename with the
// given permission bits (the temp file is created 0600, so raw-ID output is
// never briefly readable by others).
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".plan-*.json")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Chmod(mode); err != nil { //nolint:gosec // 0644 only for plans without raw IDs
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
