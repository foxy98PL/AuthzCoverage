package coveragejson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"authzcov/internal/matrix"
	"authzcov/internal/model"
)

// MaxSize caps what Read accepts.
const MaxSize = 256 << 20

// Write serialises r as indented JSON with a trailing newline. Nil slices are
// written as [] (r is normalised in place).
func Write(w io.Writer, r *Report) error {
	normalize(r)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode coverage.json: %w", err)
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func normalize(r *Report) {
	r.Inputs.HAR = nonNil(r.Inputs.HAR)
	r.Inputs.BasePath.Hosts = nonNil(r.Inputs.BasePath.Hosts)
	r.Identities = nonNil(r.Identities)
	for i := range r.Identities {
		r.Identities[i].Fingerprints = nonNil(r.Identities[i].Fingerprints)
	}
	r.Endpoints = nonNil(r.Endpoints)
	r.Cells = nonNil(r.Cells)
	r.Objects = nonNil(r.Objects)
	r.Findings = nonNil(r.Findings)
	r.Warnings = nonNil(r.Warnings)
}

// Read decodes a coverage.json and rejects any schema other than SchemaV1.
// Unknown fields are accepted: v1 may gain fields.
func Read(rd io.Reader) (*Report, error) {
	dec := json.NewDecoder(io.LimitReader(rd, MaxSize))
	var r Report
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("invalid coverage.json: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid coverage.json: trailing data after the JSON document")
	}
	if r.Schema != SchemaV1 {
		return nil, fmt.Errorf("unsupported coverage.json schema %q (this build reads %q)", r.Schema, SchemaV1)
	}
	normalize(&r)
	return &r, nil
}

// ToMatrix rebuilds the matrix the table renderer needs. Cells that were not
// emitted (not required, never observed) are absent, which the table shows as
// "-". The percentage is recomputed from the counts, not taken from the rounded
// JSON value.
func ToMatrix(r *Report) (*matrix.Matrix, error) {
	m := &matrix.Matrix{Cells: map[string][]*model.CoverageCell{}}
	known := map[string]bool{}
	for _, e := range r.Endpoints {
		var kind model.EndpointKind
		switch e.Kind {
		case "object":
			kind = model.ObjectLevel
		case "function":
			kind = model.FunctionLevel
		default:
			return nil, fmt.Errorf("endpoint %q: unknown kind %q", e.ID, e.Kind)
		}
		if known[e.ID] {
			return nil, fmt.Errorf("duplicate endpoint %q", e.ID)
		}
		known[e.ID] = true
		m.Endpoints = append(m.Endpoints, &model.Endpoint{
			ID: e.ID, Method: e.Method, Template: e.Template, ObjectParam: e.ObjectParam,
			Resource: e.Resource, Kind: kind, SpecFile: e.SpecFile, SpecLine: e.SpecLine,
		})
	}
	rels := map[string]bool{}
	for _, rel := range model.Relationships() {
		rels[string(rel)] = true
	}
	for _, c := range r.Cells {
		if !known[c.Endpoint] {
			return nil, fmt.Errorf("cell references unknown endpoint %q", c.Endpoint)
		}
		if !rels[c.Relationship] {
			return nil, fmt.Errorf("cell %q: unknown relationship %q", c.Endpoint, c.Relationship)
		}
		cc := &model.CoverageCell{
			Endpoint: c.Endpoint, Rel: model.Relationship(c.Relationship), Required: c.Required, Covered: c.Covered,
			Statuses: map[int]int{}, Identities: c.Identities, Evidence: c.Evidence,
		}
		for s, n := range c.Statuses {
			code, err := strconv.Atoi(s)
			if err != nil {
				return nil, fmt.Errorf("cell %q: bad status %q", c.Endpoint, s)
			}
			cc.Statuses[code] = n
		}
		if c.Covered {
			conf, ok := parseConf(c.MinConfidence)
			if !ok {
				return nil, fmt.Errorf("cell %q/%s: bad min_confidence %q", c.Endpoint, c.Relationship, c.MinConfidence)
			}
			cc.MinConf = conf
		}
		m.Cells[c.Endpoint] = append(m.Cells[c.Endpoint], cc)
	}
	m.Summary = matrix.Summary{
		Required: r.Summary.Required, Covered: r.Summary.Covered, Gaps: r.Summary.Gaps,
	}
	if r.Summary.Required > 0 {
		m.Summary.Percent = 100 * float64(r.Summary.Covered) / float64(r.Summary.Required)
	}
	return m, nil
}

func parseConf(s string) (model.Confidence, bool) {
	for _, c := range []model.Confidence{model.ConfUnknown, model.ConfInferred, model.ConfLearned, model.ConfDeclared} {
		if c.String() == s {
			return c, true
		}
	}
	return 0, false
}
