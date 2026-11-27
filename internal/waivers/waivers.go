// Package waivers loads waivers.yaml (schema authzcov.waivers/v1), validates it
// with line-numbered errors, and applies it to a coverage report. A waiver
// marks a required, uncovered endpoint x relationship cell as accepted until
// its expiry date. Nothing here reads the clock: callers pass today in.
package waivers

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// SchemaV1 is the value of the schema key.
const SchemaV1 = "authzcov.waivers/v1"

// MaxSize is the largest waivers file Load will read.
const MaxSize = 1 << 20

const (
	minReason  = 10
	maxReason  = 500
	maxDays    = 365
	dateLayout = "2006-01-02"
)

// Requirable lists the relationships a waiver may name.
var Requirable = []string{"owner", "same_role_other_user", "lower_role", "other_tenant", "anonymous"}

// Waiver is one validated waiver.
type Waiver struct {
	Endpoint     string    // exact endpoint ID or a pattern where * matches any run of characters
	Relationship string    // one of Requirable
	Reason       string    // trimmed, 10-500 characters
	Expires      time.Time // date, UTC midnight
	ExpiresText  string    // YYYY-MM-DD as written
	Line         int       // line of the waiver in the file
}

// Error is a validation error: "file:line: message".
type Error struct {
	File string
	Line int
	Msg  string
}

func (e *Error) Error() string {
	if e.Line > 0 {
		return e.File + ":" + strconv.Itoa(e.Line) + ": " + e.Msg
	}
	return e.File + ": " + e.Msg
}

// Load reads and parses path, rejecting files larger than MaxSize.
func Load(path string, today time.Time) ([]Waiver, error) {
	fh, err := os.Open(path) //nolint:gosec // path is the user's own --waivers flag
	if err != nil {
		return nil, fmt.Errorf("read waivers file %s: %w", path, err)
	}
	defer func() { _ = fh.Close() }()
	data, err := io.ReadAll(io.LimitReader(fh, MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read waivers file %s: %w", path, err)
	}
	if len(data) > MaxSize {
		return nil, &Error{File: path, Msg: fmt.Sprintf("file is larger than %d bytes", MaxSize)}
	}
	return Parse(data, path, today)
}

type parser struct {
	file  string
	today time.Time
}

func (p *parser) err(n *yaml.Node, format string, args ...any) *Error {
	e := &Error{File: p.file, Msg: fmt.Sprintf(format, args...)}
	if n != nil {
		e.Line = n.Line
	}
	return e
}

// Parse validates data (named name in errors) and returns the waivers in file
// order. today is the UTC date used for the 365-day limit.
func Parse(data []byte, name string, today time.Time) ([]Waiver, error) {
	y, m, d := today.UTC().Date()
	p := &parser{file: name, today: time.Date(y, m, d, 0, 0, 0, 0, time.UTC)}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, p.err(nil, "file is empty; see docs for the waivers.yaml format")
		}
		msg, _, _ := strings.Cut(err.Error(), "\n")
		return nil, p.err(nil, "invalid yaml: %s", msg)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, p.err(&extra, "multiple yaml documents are not allowed; keep one document")
	}
	if e := p.noAnchors(&doc); e != nil {
		return nil, e
	}
	if len(doc.Content) == 0 {
		return nil, p.err(nil, "file is empty; see docs for the waivers.yaml format")
	}
	root := doc.Content[0]
	var list *yaml.Node
	switch root.Kind {
	case yaml.SequenceNode:
		list = root
	case yaml.MappingNode:
		f, e := p.fields(root, "schema", "waivers")
		if e != nil {
			return nil, e
		}
		sn, ok := f["schema"]
		if !ok {
			return nil, p.err(root, "missing schema: set schema: %s (or use a bare list of waivers)", SchemaV1)
		}
		if sn.Kind != yaml.ScalarNode || sn.Value != SchemaV1 {
			return nil, p.err(sn, "unsupported schema; this build reads %s", SchemaV1)
		}
		list, ok = f["waivers"]
		if !ok {
			return nil, p.err(root, "missing waivers: list")
		}
		if list.Kind == yaml.ScalarNode && list.Tag == "!!null" {
			return []Waiver{}, nil
		}
		if list.Kind != yaml.SequenceNode {
			return nil, p.err(list, "waivers must be a list")
		}
	default:
		return nil, p.err(root, "must be a mapping with schema and waivers, or a list of waivers")
	}
	out := make([]Waiver, 0, len(list.Content))
	seen := map[[2]string]int{}
	for _, item := range list.Content {
		w, e := p.waiver(item)
		if e != nil {
			return nil, e
		}
		k := [2]string{w.Endpoint, w.Relationship}
		if first, dup := seen[k]; dup {
			return nil, p.err(item, "duplicate waiver for %q %s (first at line %d)", w.Endpoint, w.Relationship, first)
		}
		seen[k] = item.Line
		out = append(out, w)
	}
	return out, nil
}

func (p *parser) noAnchors(n *yaml.Node) *Error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return p.err(n, "yaml anchors and aliases are not allowed")
	}
	for _, c := range n.Content {
		if e := p.noAnchors(c); e != nil {
			return e
		}
	}
	return nil
}

func (p *parser) fields(n *yaml.Node, allowed ...string) (map[string]*yaml.Node, *Error) {
	if n.Kind != yaml.MappingNode {
		return nil, p.err(n, "must be a mapping")
	}
	out := map[string]*yaml.Node{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			return nil, p.err(k, "keys must be plain strings")
		}
		known := false
		for _, a := range allowed {
			known = known || a == k.Value
		}
		if !known {
			return nil, p.err(k, "unknown key %q; allowed keys: %s", k.Value, strings.Join(allowed, ", "))
		}
		if _, dup := out[k.Value]; dup {
			return nil, p.err(k, "duplicate key %q", k.Value)
		}
		out[k.Value] = v
	}
	return out, nil
}

func (p *parser) waiver(item *yaml.Node) (Waiver, *Error) {
	f, e := p.fields(item, "endpoint", "relationship", "reason", "expires")
	if e != nil {
		return Waiver{}, e
	}
	str := func(key string) (string, *yaml.Node, *Error) {
		n, ok := f[key]
		if !ok {
			return "", nil, p.err(item, "missing %s: every waiver needs endpoint, relationship, reason and expires", key)
		}
		if n.Kind != yaml.ScalarNode {
			return "", nil, p.err(n, "%s must be a scalar value", key)
		}
		return strings.TrimSpace(n.Value), n, nil
	}
	w := Waiver{Line: item.Line}
	ep, n, e := str("endpoint")
	if e != nil {
		return w, e
	}
	if ep == "" {
		return w, p.err(n, "endpoint must not be empty")
	}
	w.Endpoint = ep
	rel, n, e := str("relationship")
	if e != nil {
		return w, e
	}
	ok := false
	for _, r := range Requirable {
		ok = ok || r == rel
	}
	if !ok {
		return w, p.err(n, "invalid relationship %q; use one of %s", rel, strings.Join(Requirable, ", "))
	}
	w.Relationship = rel
	reason, n, e := str("reason")
	if e != nil {
		return w, e
	}
	if c := utf8.RuneCountInString(reason); c < minReason || c > maxReason {
		return w, p.err(n, "reason must be %d-%d characters (got %d)", minReason, maxReason, c)
	}
	w.Reason = reason
	exp, n, e := str("expires")
	if e != nil {
		return w, e
	}
	t, err := time.Parse(dateLayout, exp)
	if err != nil {
		return w, p.err(n, "invalid expires %q; use a date like 2027-03-31 (YYYY-MM-DD)", exp)
	}
	if t.After(p.today.AddDate(0, 0, maxDays)) {
		return w, p.err(n, "expires %s is more than %d days away; pick a date on or before %s",
			exp, maxDays, p.today.AddDate(0, 0, maxDays).Format(dateLayout))
	}
	w.Expires, w.ExpiresText = t, exp
	return w, nil
}

// Expired reports whether the waiver's last valid day is before today.
func (w Waiver) Expired(today time.Time) bool {
	y, m, d := today.UTC().Date()
	return w.Expires.Before(time.Date(y, m, d, 0, 0, 0, 0, time.UTC))
}

// Match reports whether pattern matches s. A * matches any run of characters
// (including none); everything else matches literally.
func Match(pattern, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case p < len(pattern) && pattern[p] == s[i]:
			p++
			i++
		case star >= 0:
			mark++
			i, p = mark, star+1
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
