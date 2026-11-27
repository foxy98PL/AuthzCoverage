package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"authzcov/internal/basepath"
	"authzcov/internal/match"
	"authzcov/internal/redact"
	"authzcov/internal/spec"
)

func newExplainCmd() *cobra.Command {
	var specFile, base string
	cmd := &cobra.Command{
		Use:   "explain --spec <file> [--base-path /p] 'METHOD /path'",
		Short: "Show which spec endpoint a request would match, and why (no network)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if specFile == "" {
				return usageErr(fmt.Errorf("missing --spec: pass an OpenAPI 3.x file"))
			}
			if base != "" && base != basePathNone && !strings.HasPrefix(base, "/") {
				return usageErr(fmt.Errorf("invalid --base-path %q: use a path starting with /", redact.StripControl(base)))
			}
			method, path, err := parseRequestArg(args)
			if err != nil {
				return usageErr(err)
			}
			endpoints, err := spec.Load(specFile)
			if err != nil {
				return inputErr(err)
			}
			trie, _, err := buildTrie(endpoints, specFile)
			if err != nil {
				return inputErr(err)
			}
			runExplain(cmd.OutOrStdout(), trie, method, path, base)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&specFile, "spec", "", "OpenAPI 3.x spec file (required)")
	f.StringVar(&base, "base-path", "", "URL prefix to strip from the request path before matching, e.g. /api")
	return cmd
}

func parseRequestArg(args []string) (method, path string, err error) {
	if len(args) != 1 {
		return "", "", fmt.Errorf(`expected one argument "METHOD /path", got %d`, len(args))
	}
	f := strings.Fields(args[0])
	if len(f) != 2 || !strings.HasPrefix(f[1], "/") || strings.ContainsFunc(f[0], func(r rune) bool { return r < 'A' || (r > 'Z' && r < 'a') || r > 'z' }) {
		return "", "", fmt.Errorf(`invalid request %q: want "METHOD /path"`, redact.StripControl(args[0]))
	}
	return strings.ToUpper(f[0]), f[1], nil
}

func runExplain(w io.Writer, trie *match.Trie, method, path, base string) {
	if base != "" && base != basePathNone {
		if rest, ok := basepath.Strip(path, base); ok {
			path = rest
		} else {
			_, _ = fmt.Fprintf(w, "note: path is not under base path %q; matching it unchanged\n", redact.StripControl(base))
		}
	}
	e := trie.Explain(method, path)
	_, _ = fmt.Fprintf(w, "request: %s %s\n", method, redact.StripControl(path))
	segs := make([]string, len(e.Segments))
	for i, s := range e.Segments {
		segs[i] = fmt.Sprintf("%q", redact.StripControl(s))
	}
	_, _ = fmt.Fprintf(w, "segments: %s\n", strings.Join(segs, " "))
	_, _ = fmt.Fprintln(w, "candidates:")
	if len(e.Candidates) == 0 {
		_, _ = fmt.Fprintln(w, "  (none)")
	}
	for _, c := range e.Candidates {
		marker := " "
		if c.Op == e.Result.Op {
			marker = "*"
		}
		ok := "no"
		if c.MethodOK {
			ok = "yes"
		}
		_, _ = fmt.Fprintf(w, "%s %s  literals=%d  method=%s\n", marker, redact.StripControl(c.Op.ID), c.Literals, ok)
	}
	if e.Result.Op != nil {
		names := make([]string, 0, len(e.Result.Params))
		for k := range e.Result.Params {
			names = append(names, k)
		}
		sort.Strings(names)
		parts := make([]string, len(names))
		for i, k := range names {
			parts[i] = fmt.Sprintf("%s=%q", k, redact.StripControl(e.Result.Params[k]))
		}
		if len(parts) == 0 {
			parts = []string{"(none)"}
		}
		_, _ = fmt.Fprintf(w, "params: %s\n", strings.Join(parts, " "))
	}
	_, _ = fmt.Fprintf(w, "reason: %s\n", redact.StripControl(e.Reason))
}
