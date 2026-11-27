// Package baseline stores the coverage state of every required cell as
// baseline.json (schema authzcov.baseline/v1) and compares a current result
// against it. The file has no timestamps and no tool version, so rewriting it
// from an unchanged result is byte-identical. Nothing here reads the clock.
package baseline

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"authzcov/internal/report/coveragejson"
)

// SchemaV1 is the value of Baseline.Schema.
const SchemaV1 = "authzcov.baseline/v1"

// MaxSize caps what Read accepts.
const MaxSize = 64 << 20

// Cell states.
const (
	Covered = "covered"
	Missing = "missing"
	Waived  = "waived"
)

// Summary counts the required cells in the baseline.
type Summary struct {
	Required int `json:"required"`
	Covered  int `json:"covered"`
}

// Baseline is the whole baseline.json. Cells maps endpoint ID -> relationship
// -> state; encoding/json sorts the keys.
type Baseline struct {
	Schema     string                       `json:"schema"`
	SpecSHA256 string                       `json:"spec_sha256"`
	Summary    Summary                      `json:"summary"`
	Cells      map[string]map[string]string `json:"cells"`
}

// FromReport records the state of every required cell of r.
func FromReport(r *coveragejson.Report) *Baseline {
	b := &Baseline{Schema: SchemaV1, SpecSHA256: r.Inputs.Spec.SHA256, Cells: map[string]map[string]string{}}
	for _, c := range r.Cells {
		if !c.Required {
			continue
		}
		state := Missing
		switch {
		case c.Covered:
			state = Covered
			b.Summary.Covered++
		case c.Waiver != nil:
			state = Waived
		}
		b.Summary.Required++
		if b.Cells[c.Endpoint] == nil {
			b.Cells[c.Endpoint] = map[string]string{}
		}
		b.Cells[c.Endpoint][c.Relationship] = state
	}
	return b
}

// Percent is covered/(required-waived)*100, derived from the cell states.
func (b *Baseline) Percent() float64 {
	required, covered, waived := 0, 0, 0
	for _, rels := range b.Cells {
		for _, s := range rels {
			required++
			switch s {
			case Covered:
				covered++
			case Waived:
				waived++
			}
		}
	}
	return coveragejson.Percent(covered, required, waived)
}

// Write serialises b as indented JSON with a trailing newline.
func Write(w io.Writer, b *Baseline) error {
	if b.Cells == nil {
		c := *b
		c.Cells = map[string]map[string]string{}
		b = &c
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(b); err != nil {
		return fmt.Errorf("encode baseline.json: %w", err)
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// Read decodes a baseline.json, rejecting other schemas and unknown states.
func Read(r io.Reader) (*Baseline, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read baseline.json: %w", err)
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("baseline.json exceeds the %d MiB limit", MaxSize>>20)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var b Baseline
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("invalid baseline.json: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid baseline.json: trailing data after the JSON document")
	}
	if b.Schema != SchemaV1 {
		return nil, fmt.Errorf("unsupported baseline.json schema %q (this build reads %q)", b.Schema, SchemaV1)
	}
	for ep, rels := range b.Cells {
		for rel, s := range rels {
			if s != Covered && s != Missing && s != Waived {
				return nil, fmt.Errorf("baseline.json: %q %s: unknown state %q", ep, rel, s)
			}
		}
	}
	if b.Cells == nil {
		b.Cells = map[string]map[string]string{}
	}
	return &b, nil
}

// Change is one cell whose state is reported by Compare. Was is empty for a
// cell the baseline did not have.
type Change struct{ Endpoint, Relationship, Was, Now string }

// Diff is the result of Compare. Every slice is sorted (endpoint,
// relationship) and non-nil.
type Diff struct {
	NewEndpoints []string // in current, not in baseline
	NewGaps      []Change // missing cells on new endpoints, or new required cells on known ones
	Removed      []string // in baseline, not in current (never a failure)
	Regressions  []Change // covered or waived -> missing
	Improvements []Change // missing or waived -> covered
	Waived       []Change // cells whose current state is waived
	Expired      []string // messages of waiver_expired warnings in the current report
	PercentWas   float64
	PercentNow   float64
}

// Compare diffs cur against old. curReport supplies the expired-waiver
// warnings and may be nil.
func Compare(old, cur *Baseline, curReport *coveragejson.Report) Diff {
	d := Diff{NewEndpoints: []string{}, NewGaps: []Change{}, Removed: []string{}, Regressions: []Change{},
		Improvements: []Change{}, Waived: []Change{}, Expired: []string{},
		PercentWas: old.Percent(), PercentNow: cur.Percent()}
	for ep, rels := range cur.Cells {
		oldRels, known := old.Cells[ep]
		if !known {
			d.NewEndpoints = append(d.NewEndpoints, ep)
		}
		for rel, now := range rels {
			was := oldRels[rel] // "" when absent
			ch := Change{ep, rel, was, now}
			if now == Waived {
				d.Waived = append(d.Waived, ch)
			}
			switch {
			case was == "":
				if now == Missing {
					d.NewGaps = append(d.NewGaps, ch)
				}
			case now == Missing && was != Missing:
				d.Regressions = append(d.Regressions, ch)
			case now == Covered && was != Covered:
				d.Improvements = append(d.Improvements, ch)
			}
		}
	}
	for ep := range old.Cells {
		if _, ok := cur.Cells[ep]; !ok {
			d.Removed = append(d.Removed, ep)
		}
	}
	if curReport != nil {
		for _, w := range curReport.Warnings {
			if w.Code == "waiver_expired" {
				d.Expired = append(d.Expired, w.Message)
			}
		}
	}
	slices.Sort(d.NewEndpoints)
	slices.Sort(d.Removed)
	slices.Sort(d.Expired)
	for _, s := range [][]Change{d.NewGaps, d.Regressions, d.Improvements, d.Waived} {
		slices.SortFunc(s, func(a, b Change) int {
			return cmp.Or(strings.Compare(a.Endpoint, b.Endpoint), strings.Compare(a.Relationship, b.Relationship))
		})
	}
	return d
}
