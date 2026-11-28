// Package items turns an `export --plan` document into concrete, ordered probe
// items. Raw object IDs are used only when the plan says contains_raw_ids; an
// ID is never guessed, and never appears in a Reason or an error.
package items

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"authzcov/internal/plan"
)

// Item is one probe resolved to a concrete request path.
type Item struct {
	ProbeID          string `json:"probe_id"`
	Method           string `json:"method"`
	Path             string `json:"path"`
	AttackerIdentity string `json:"attacker_identity"`
	Expect           string `json:"expect"`
	Executable       bool   `json:"executable"`
	Reason           string `json:"reason,omitempty"`
}

// Load parses a plan and returns its items sorted by probe ID.
func Load(r io.Reader) ([]Item, error) {
	var p plan.Plan
	if err := json.NewDecoder(r).Decode(&p); err != nil {
		return nil, errors.New("items: plan is not valid JSON of the expected shape")
	}
	if p.PlanVersion != plan.Version {
		return nil, fmt.Errorf("items: unsupported plan_version %d (want %d)", p.PlanVersion, plan.Version)
	}
	out := make([]Item, 0, len(p.Probes))
	for _, pr := range p.Probes {
		out = append(out, build(pr, p.ContainsRawIDs))
	}
	sort.SliceStable(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out, nil
}

// less is a total order over every Item field, so output does not depend on
// input order even when probe IDs repeat.
func less(a, b Item) bool {
	switch {
	case a.ProbeID != b.ProbeID:
		return a.ProbeID < b.ProbeID
	case a.Method != b.Method:
		return a.Method < b.Method
	case a.Path != b.Path:
		return a.Path < b.Path
	case a.AttackerIdentity != b.AttackerIdentity:
		return a.AttackerIdentity < b.AttackerIdentity
	case a.Expect != b.Expect:
		return a.Expect < b.Expect
	case a.Executable != b.Executable:
		return !a.Executable
	}
	return a.Reason < b.Reason
}

// literalTraversal reports a literal template segment that is "." or contains "..".
func literalTraversal(tmpl string) bool {
	for _, seg := range strings.Split(tmpl, "/") {
		var lit strings.Builder
		for in, i := false, 0; i < len(seg); i++ {
			switch c := seg[i]; {
			case c == '{':
				in = true
			case c == '}':
				in = false
			case !in:
				lit.WriteByte(c)
			}
		}
		if l := lit.String(); l == "." || strings.Contains(l, "..") {
			return true
		}
	}
	return false
}

func build(pr plan.Probe, rawOK bool) Item {
	it := Item{ProbeID: pr.ID, Method: pr.Method, Path: pr.PathTemplate, Expect: pr.Expect}
	if pr.Attacker != nil {
		it.AttackerIdentity = pr.Attacker.Identity
	}
	switch {
	case pr.Waived:
		it.Reason = "probe is waived"
	case it.AttackerIdentity == "":
		it.Reason = "no attacker identity"
	case literalTraversal(pr.PathTemplate):
		it.Reason = "path template has a . or .. segment"
	case pr.Object != nil && (pr.Object.Param == "" || !strings.Contains(pr.PathTemplate, "{"+pr.Object.Param+"}")):
		it.Reason = "object param is empty or not in path template"
	case pr.Object != nil && !rawOK:
		it.Reason = "plan holds no raw IDs (hash-only); re-run export with --har"
	case pr.Object != nil && pr.Object.ID == "":
		it.Reason = "object has no raw id"
	default:
		vals := map[string]string{}
		for k, v := range pr.PathParams {
			vals[k] = v
		}
		if pr.Object != nil {
			vals[pr.Object.Param] = pr.Object.ID
		}
		path, missing := substitute(pr.PathTemplate, vals)
		if missing != "" {
			it.Reason = "unresolved path parameter " + missing
		} else {
			it.Path, it.Executable = path, true
		}
	}
	return it
}

// substitute fills {name} segments; it returns the first unresolved name.
func substitute(tmpl string, vals map[string]string) (string, string) {
	var b strings.Builder
	for {
		i := strings.IndexByte(tmpl, '{')
		if i < 0 {
			b.WriteString(tmpl)
			return b.String(), ""
		}
		j := strings.IndexByte(tmpl[i:], '}')
		if j < 0 {
			return "", "(malformed template)"
		}
		name := tmpl[i+1 : i+j]
		v, ok := vals[name]
		if !ok || v == "" {
			return "", name
		}
		b.WriteString(tmpl[:i])
		b.WriteString(escape(v))
		tmpl = tmpl[i+j+1:]
	}
}

func escape(v string) string {
	if v == "." || v == ".." {
		return strings.ReplaceAll(v, ".", "%2E")
	}
	return url.PathEscape(v)
}
