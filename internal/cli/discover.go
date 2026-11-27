package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"authzcov/internal/config"
	"authzcov/internal/identity"
	"authzcov/internal/ingest/har"
	"authzcov/internal/model"
	"authzcov/internal/redact"
)

type discoverOpts struct {
	hars       []string
	identities string
	write      string
	force      bool
}

func newDiscoverCmd() *cobra.Command {
	var o discoverOpts
	cmd := &cobra.Command{
		Use:   "discover --har f.har [--har ...] [--identities existing.yaml] [--write out.yaml] [--force]",
		Short: "Propose an identities.yaml skeleton from the credentials seen in HAR files (no network)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if len(o.hars) == 0 {
				return usageErr(errors.New("missing --har: pass at least one HAR file"))
			}
			if o.force && o.write == "" {
				return usageErr(errors.New("--force only makes sense with --write"))
			}
			return runDiscover(&o, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&o.hars, "har", nil, "HAR file recorded from tests (repeatable, required)")
	f.StringVar(&o.identities, "identities", "", "existing identities.yaml whose credentials section tells where credentials live")
	f.StringVar(&o.write, "write", "", "write the skeleton to this file instead of stdout")
	f.BoolVar(&o.force, "force", false, "overwrite the --write file if it exists")
	return cmd
}

// principal is everything seen for one credential fingerprint.
type principal struct {
	kind, fp string
	n        int
	claims   map[string]any
}

// keyClaims are the JWT claims worth showing next to a principal.
var keyClaims = []string{"sub", "iss", "role", "roles", "scope", "tenant", "tenant_id", "org", "org_id", "basic_user"}

func runDiscover(o *discoverOpts, stdout, stderr io.Writer) error {
	specs := []identity.CredSpec{
		{Type: "bearer", Header: "Authorization", Schemes: []string{"Bearer", "Token"}},
		{Type: "basic"},
		{Type: "apikey", Header: "X-API-Key"},
	}
	if o.identities != "" {
		cfg, err := config.Load(o.identities)
		if err != nil {
			return usageErr(err)
		}
		specs = credSpecs(cfg)
	}
	var hs har.Stats
	xs, err := readHARs(o.hars, identity.NewExtractor(specs), &hs)
	if err != nil {
		return inputErr(err)
	}
	ps := collectPrincipals(xs)
	_, _ = fmt.Fprintf(stderr, "discover: %d principals from %d requests\n", len(ps), len(xs))
	out := renderSkeleton(ps, len(o.hars))

	if o.write == "" {
		if _, err := io.WriteString(redact.NewWriter(stdout), out); err != nil {
			return fmt.Errorf("write skeleton: %w", err)
		}
		return nil
	}
	if err := writeSkeleton(o.write, out, o.force); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stderr, "discover: wrote %s\n", redact.StripControl(o.write))
	return nil
}

func writeSkeleton(path, content string, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o644) //nolint:gosec // the skeleton holds no secrets; world-readable is intended
	if errors.Is(err, fs.ErrExist) {
		return usageErr(fmt.Errorf("%s: file exists; pass --force", redact.StripControl(path)))
	}
	if err != nil {
		return usageErr(fmt.Errorf("write %s: %w", redact.StripControl(path), err))
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", redact.StripControl(path), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", redact.StripControl(path), err)
	}
	return nil
}

func collectPrincipals(xs []*model.Exchange) []*principal {
	by := map[string]*principal{}
	for _, x := range xs {
		if x.Cred.Kind == identity.KindNone {
			continue
		}
		key := x.Cred.Kind + "/" + x.Cred.Fingerprint
		p := by[key]
		if p == nil {
			p = &principal{kind: x.Cred.Kind, fp: x.Cred.Fingerprint, claims: x.Cred.Claims}
			by[key] = p
		}
		p.n++
	}
	out := make([]*principal, 0, len(by))
	for _, p := range by {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].fp != out[j].fp {
			return out[i].fp < out[j].fp
		}
		return out[i].kind < out[j].kind
	})
	return out
}

// entry is one proposed identity: either active (match != "") or commented out.
type entry struct {
	name, key, match string
	fps              []string
	n                int
	claims           []string
}

var badNameChars = regexp.MustCompile(`[^a-z0-9._-]+`)

func sanitiseName(s string) string {
	s = badNameChars.ReplaceAllString(strings.ToLower(s), "-")
	s = strings.TrimLeft(s, "._-")
	if len(s) > 59 { // leave room for a -NN dedup suffix
		s = s[:59]
	}
	s = strings.TrimRight(s, "-")
	if s == "" {
		s = "user"
	}
	if s == "anonymous" || strings.HasPrefix(s, "unknown-") {
		s = "id-" + s
	}
	return s
}

func claimString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, t != ""
	case json.Number:
		return t.String(), true
	case bool:
		return strconv.FormatBool(t), true
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := claimString(e); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ","), len(parts) > 0
	}
	return "", false
}

func claimSummary(p *principal) []string {
	var out []string
	for _, k := range keyClaims {
		if s, ok := claimString(p.claims[k]); ok {
			s = redact.StripControl(s)
			if len(s) > 60 {
				s = s[:60] + "..."
			}
			out = append(out, k+"="+s)
		}
	}
	return out
}

func renderSkeleton(ps []*principal, nHAR int) string {
	type group struct {
		kind, key string
		ps        []*principal
	}
	groups := map[string]*group{}
	var others []*principal
	for _, p := range ps {
		var kind, key string
		switch p.kind {
		case identity.KindBearer:
			kind = "jwt"
			key, _ = claimString(p.claims["sub"])
		case identity.KindBasic:
			kind = "basic_user"
			key, _ = claimString(p.claims["basic_user"])
		}
		if key == "" {
			others = append(others, p)
			continue
		}
		g := groups[kind+"\x00"+key]
		if g == nil {
			g = &group{kind: kind, key: key}
			groups[kind+"\x00"+key] = g
		}
		g.ps = append(g.ps, p)
	}
	gs := make([]*group, 0, len(groups))
	for _, g := range groups {
		gs = append(gs, g)
	}
	sort.Slice(gs, func(i, j int) bool {
		bi, bj := sanitiseName(gs[i].key), sanitiseName(gs[j].key)
		if bi != bj {
			return bi < bj
		}
		if gs[i].kind != gs[j].kind {
			return gs[i].kind < gs[j].kind
		}
		return gs[i].key < gs[j].key
	})

	used := map[string]bool{}
	var entries []entry
	for _, g := range gs {
		base := sanitiseName(g.key)
		name := base
		for i := 2; used[name]; i++ {
			name = base + "-" + strconv.Itoa(i)
		}
		used[name] = true
		e := entry{name: name, key: g.key}
		if g.kind == "jwt" {
			e.match = "{jwt: {sub: " + strconv.Quote(g.key) + "}}"
		} else {
			e.match = "{basic_user: " + strconv.Quote(g.key) + "}"
		}
		for _, p := range g.ps {
			e.fps = append(e.fps, p.fp)
			e.n += p.n
		}
		sort.Strings(e.fps)
		e.claims = claimSummary(g.ps[0])
		entries = append(entries, e)
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	var b strings.Builder
	fmt.Fprintf(&b, "# generated by authzcov discover from %d HAR file(s) — review names and roles before use\n", nHAR)
	b.WriteString("version: 1\n")
	b.WriteString("# Roles and ranks: a higher rank means more privilege. Rename and extend to match your app.\n")
	b.WriteString("roles: {user: 10, admin: 100}\n")
	b.WriteString("identities:\n")
	if len(entries) == 0 {
		b.WriteString("  # warning: no JWT subject or basic-auth user was found in the traffic, so this is a placeholder.\n")
		b.WriteString("  # Replace it with real identities (token_sha256, jwt, basic_user or login via learn_tokens).\n")
		b.WriteString("  - {name: change-me, role: user, match: {login: change-me}}\n")
	}
	for _, e := range entries {
		fmt.Fprintf(&b, "  # %s: fingerprint(s) %s, %d request(s)\n", redact.StripControl(e.name), strings.Join(e.fps, ", "), e.n)
		if len(e.claims) > 0 {
			fmt.Fprintf(&b, "  # claims: %s\n", strings.Join(e.claims, " "))
		}
		fmt.Fprintf(&b, "  - {name: %s, role: user, match: %s}\n", e.name, e.match)
	}
	for _, p := range others {
		fmt.Fprintf(&b, "  # %s credential, fingerprint %s, %d request(s)", redact.StripControl(p.kind), p.fp, p.n)
		if cl := claimSummary(p); len(cl) > 0 {
			b.WriteString("; claims: " + strings.Join(cl, " "))
		}
		b.WriteString("\n")
		b.WriteString("  # Only 12 hex characters of the SHA-256 are known here, so fill in the full hash\n")
		b.WriteString("  # (sha256sum of the credential value) or use learn_tokens with a login request instead:\n")
		fmt.Fprintf(&b, "  # - {name: change-me-%s, role: user, match: {token_sha256: \"<64 hex chars; starts with %s>\"}}\n", p.fp, p.fp)
	}
	return b.String()
}
