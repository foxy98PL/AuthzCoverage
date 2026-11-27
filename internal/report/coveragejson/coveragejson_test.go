package coveragejson

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"authzcov/internal/matrix"
	"authzcov/internal/model"
	"authzcov/internal/ownership"
	"authzcov/internal/report/table"
	"authzcov/internal/suspicious"
)

var (
	alice = &model.Identity{Name: "alice", Role: "user", Rank: 10, Tenant: "A", Subject: "alice"}
	bob   = &model.Identity{Name: "bob", Role: "user", Rank: 10, Tenant: "A"}
	anon  = &model.Identity{Name: "anonymous", Anonymous: true}
	unk   = &model.Identity{Name: "unknown-abcd1234"}

	getBook = &model.Endpoint{ID: "GET /books/{id}", Method: "GET", Template: "/books/{id}", Params: []string{"id"},
		ObjectParam: "id", Resource: "books", Kind: model.ObjectLevel, SpecFile: "spec.yml", SpecLine: 7}
	getMe = &model.Endpoint{ID: "GET /me", Method: "GET", Template: "/me", Kind: model.FunctionLevel, SpecFile: "spec.yml", SpecLine: 3}
)

func ob(ep *model.Endpoint, id *model.Identity, conf model.Confidence, owner *model.Identity, status int, src, fp string) *model.Observation {
	o := &model.Observation{
		Endpoint: ep, Identity: id, IDConf: conf, Owner: owner, OwnerConf: model.ConfLearned,
		X: &model.Exchange{Source: src, Status: status, Cred: model.Credential{Fingerprint: fp}},
	}
	switch {
	case id.Anonymous:
		o.Rel = model.RelAnonymous
	case ep.Kind == model.FunctionLevel:
		o.Rel = model.RelOwner
	case owner != nil && owner.Name == id.Name:
		o.Rel = model.RelOwner
	default:
		o.Rel = model.RelSameRoleOtherUser
	}
	return o
}

func fixedNow() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 999, time.FixedZone("x", 3600)) }

func sample() Input {
	eps := []*model.Endpoint{getMe, getBook}
	obs := []*model.Observation{
		ob(getBook, alice, model.ConfDeclared, alice, 200, "t.har#1", "fp-bbb"),
		ob(getBook, anon, model.ConfDeclared, alice, 401, "t.har#2", ""),
		ob(getBook, unk, model.ConfUnknown, alice, 200, "t.har#3", "fp-ccc"),
		ob(getMe, bob, model.ConfDeclared, nil, 200, "t.har#4", "fp-aaa"),
		ob(getMe, alice, model.ConfDeclared, nil, 200, "t.har#5", "fp-bbb"),
	}
	return Input{
		Matrix:  matrix.Build(eps, obs, false),
		Obs:     obs,
		Objects: []ownership.Object{{Resource: "books", ID: "SECRET-ID-42", Owner: alice, Conf: model.ConfLearned, Source: ownership.SourceCreate}},
		Inputs: Inputs{
			Spec: FileRef{Path: "spec.yml", SHA256: "aa"}, HAR: []HARFile{{Path: "t.har", SHA256: "bb", Entries: 5}},
			Identities: FileRef{Path: "ids.yaml", SHA256: "cc"},
			BasePath: BasePath{Mode: BasePathModeAuto, Hosts: []HostChoice{
				{Host: "z.example", Prefix: "/z", Matched: 1, Total: 1}, {Host: "a.example", Prefix: "/api", Matched: 4, Total: 5}}},
		},
		Roles:      map[string]int{"user": 10, "member": 10, "admin": 100},
		Declared:   []model.Identity{*alice, *bob, {Name: "carol", Role: "admin", Tenant: "A"}},
		Warnings:   []Warning{{WarnConfig, "zzz"}},
		Unmatched:  []Shape{{"POST /nope", 2}, {"GET /a/<id>", 1}},
		MethodMiss: []Shape{{"DELETE /me", 3}},
		Ambiguous:  map[string]int{"GET /me": 2},
		Tool:       Tool{Name: "authzcov", Version: "dev"},
		Now:        fixedNow,
	}
}

func TestBuildBasics(t *testing.T) {
	r := Build(sample())
	if r.Schema != "authzcov.coverage/v1" {
		t.Errorf("schema = %q", r.Schema)
	}
	if r.GeneratedAt != "2026-01-02T02:04:05Z" {
		t.Errorf("generated_at = %q", r.GeneratedAt)
	}
	if r.Inputs.Evidence != "refs" {
		t.Errorf("evidence = %q", r.Inputs.Evidence)
	}
	bp := r.Inputs.BasePath
	if bp.Value != "/api" || bp.MatchedRatio != 0.83 || bp.Hosts[0].Host != "a.example" {
		t.Errorf("base_path = %+v", bp)
	}
	// identities: sorted by name, unknown/anonymous roles, fingerprints sorted unique.
	var names []string
	for _, id := range r.Identities {
		names = append(names, id.Name)
	}
	if !slices.Equal(names, []string{"alice", "anonymous", "bob", "unknown-abcd1234"}) {
		t.Fatalf("identities = %v", names)
	}
	a, an, u := r.Identities[0], r.Identities[1], r.Identities[3]
	if a.Requests != 2 || !slices.Equal(a.Fingerprints, []string{"fp-bbb"}) {
		t.Errorf("alice = %+v", a)
	}
	if an.Role != "anonymous" || an.Rank != 0 || an.Fingerprints == nil || len(an.Fingerprints) != 0 {
		t.Errorf("anonymous = %+v", an)
	}
	if u.Role != "unknown" || u.Rank != -1 {
		t.Errorf("unknown = %+v", u)
	}
	// endpoints
	if r.Endpoints[0].ID != "GET /books/{id}" || r.Endpoints[0].Requests != 3 || r.Endpoints[0].MinAllowedRole != nil {
		t.Errorf("endpoint 0 = %+v", r.Endpoints[0])
	}
	if mr := r.Endpoints[1].MinAllowedRole; mr == nil || mr.Role != "member" || mr.Confidence != "inferred" {
		t.Errorf("min_allowed_role = %+v (want alphabetically first role with rank 10)", mr)
	}
	// warnings sorted by code then message.
	var codes []string
	for _, w := range r.Warnings {
		codes = append(codes, w.Code)
	}
	if !slices.Equal(codes, []string{"config", "single_identity_role"}) {
		t.Errorf("warnings = %+v", r.Warnings)
	}
}

func TestSummaryAndFindings(t *testing.T) {
	r := Build(sample())
	var kinds []string
	for _, f := range r.Findings {
		kinds = append(kinds, f.Kind+" "+f.Endpoint)
	}
	// gaps first (sorted), then unmatched, ambiguous, undocumented_method.
	last := slices.IndexFunc(r.Findings, func(f Finding) bool { return f.Kind != KindGap })
	if last <= 0 {
		t.Fatalf("findings = %v", kinds)
	}
	tail := kinds[last:]
	want := []string{"unmatched_request GET /a/<id>", "unmatched_request POST /nope", "ambiguous_match GET /me", "undocumented_method DELETE /me"}
	if !slices.Equal(tail, want) {
		t.Errorf("non-gap findings = %v, want %v", tail, want)
	}
	s := r.Summary
	if s.Gaps != last || s.Required-s.Covered != s.Gaps || s.UnmatchedReqs != 3 || s.AmbiguousMatches != 2 || s.Waived != 0 {
		t.Errorf("summary = %+v, gaps findings = %d", s, last)
	}
	for _, f := range r.Findings {
		sum := sha256.Sum256([]byte(f.Kind + "|" + f.Endpoint + "|" + f.Relationship))
		if f.Fingerprint != hex.EncodeToString(sum[:])[:16] {
			t.Errorf("fingerprint %s for %s/%s/%s", f.Fingerprint, f.Kind, f.Endpoint, f.Relationship)
		}
		if f.Kind == KindGap && (f.Severity != "error" || f.Relationship == "") {
			t.Errorf("gap = %+v", f)
		}
	}
	for _, f := range r.Findings {
		if f.Kind == KindGap && f.Endpoint == "GET /me" && f.Relationship == "lower_role" &&
			f.Message != "GET /me was never called as lower_role" {
			t.Errorf("message = %q", f.Message)
		}
	}
}

func TestCellsSortedAndEmitted(t *testing.T) {
	r := Build(sample())
	rel := map[string]int{}
	for i, x := range model.Relationships() {
		rel[string(x)] = i
	}
	for i := 1; i < len(r.Cells); i++ {
		a, b := r.Cells[i-1], r.Cells[i]
		if a.Endpoint > b.Endpoint || (a.Endpoint == b.Endpoint && rel[a.Relationship] >= rel[b.Relationship]) {
			t.Errorf("cells out of order: %v then %v", a, b)
		}
	}
	for _, c := range r.Cells {
		if !c.Required && len(c.Statuses) == 0 {
			t.Errorf("cell should not be emitted: %+v", c)
		}
		if c.Covered != (c.MinConfidence != "") {
			t.Errorf("min_confidence iff covered: %+v", c)
		}
	}
	// The unknown caller shows up as an observed, non-required unknown cell.
	found := false
	for _, c := range r.Cells {
		if c.Endpoint == "GET /books/{id}" && c.Relationship == "same_role_other_user" && c.Statuses["200"] == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("observed cell missing: %+v", r.Cells)
	}
}

func TestSlicesNeverNull(t *testing.T) {
	r := Build(Input{Now: fixedNow})
	var buf bytes.Buffer
	if err := Write(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "null") {
		t.Errorf("null in output:\n%s", buf.String())
	}
	for _, k := range []string{`"har": []`, `"hosts": []`, `"identities": []`, `"endpoints": []`, `"cells": []`, `"objects": []`, `"findings": []`, `"warnings": []`} {
		if !strings.Contains(buf.String(), k) {
			t.Errorf("missing %s", k)
		}
	}
	// A zero Report also normalises.
	buf.Reset()
	if err := Write(&buf, &Report{Schema: SchemaV1}); err != nil || strings.Contains(buf.String(), "null") {
		t.Errorf("zero report: %v\n%s", err, buf.String())
	}
}

func TestObjectsHashOnly(t *testing.T) {
	r := Build(sample())
	sum := sha256.Sum256([]byte("books/SECRET-ID-42"))
	if len(r.Objects) != 1 || r.Objects[0].IDHash != hex.EncodeToString(sum[:])[:8] || r.Objects[0].Owner != "alice" ||
		r.Objects[0].Confidence != "learned" || r.Objects[0].Source != "create" {
		t.Fatalf("objects = %+v", r.Objects)
	}
	var buf bytes.Buffer
	if err := Write(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "SECRET-ID-42") {
		t.Error("raw object ID leaked into coverage.json")
	}
}

func TestPercentMatchesTable(t *testing.T) {
	// 1 of 16 required cells: 6.25 -> both table and JSON must say the same.
	var eps []*model.Endpoint
	for i := range 4 {
		eps = append(eps, &model.Endpoint{ID: fmt.Sprintf("GET /o%d/{id}", i), Method: "GET", Template: fmt.Sprintf("/o%d/{id}", i),
			ObjectParam: "id", Resource: "o", Kind: model.ObjectLevel})
	}
	obs := []*model.Observation{ob(eps[0], alice, model.ConfDeclared, alice, 200, "t#1", "")}
	m := matrix.Build(eps, obs, true) // 4 required each (owner, same_role, other_tenant, anon)
	r := Build(Input{Matrix: m, Obs: obs, Now: fixedNow})
	if r.Summary.Required != 16 || r.Summary.Covered != 1 {
		t.Fatalf("summary = %+v", r.Summary)
	}
	var tb bytes.Buffer
	if err := table.Render(&tb, m); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("(%.1f%%)", r.Summary.Percent)
	if !strings.Contains(tb.String(), want) {
		t.Errorf("table lacks %s:\n%s", want, tb.String())
	}
	if Percent(0, 0, 0) != 0 || Percent(1, 3, 0) != 33.3 || Percent(2, 3, 0) != 66.7 || Percent(1, 2, 1) != 100 {
		t.Error("Percent rounding")
	}
}

func TestRoundTripAndTable(t *testing.T) {
	in := sample()
	r := Build(in)
	var b1 bytes.Buffer
	if err := Write(&b1, r); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(b1.String(), "}\n") || !strings.HasPrefix(b1.String(), "{\n  \"schema\": \"authzcov.coverage/v1\"") {
		t.Errorf("format:\n%.200s", b1.String())
	}
	r2, err := Read(bytes.NewReader(b1.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var b2 bytes.Buffer
	if err := Write(&b2, r2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1.Bytes(), b2.Bytes()) {
		t.Errorf("round trip differs:\n%s\n---\n%s", b1.String(), b2.String())
	}
	m, err := ToMatrix(r2)
	if err != nil {
		t.Fatal(err)
	}
	var t1, t2 bytes.Buffer
	if err := table.Render(&t1, in.Matrix); err != nil {
		t.Fatal(err)
	}
	if err := table.Render(&t2, m); err != nil {
		t.Fatal(err)
	}
	if t1.String() != t2.String() {
		t.Errorf("table differs:\n%s\nvs\n%s", t1.String(), t2.String())
	}
}

func TestReadRejects(t *testing.T) {
	for name, in := range map[string]string{
		"wrong schema": `{"schema":"authzcov.coverage/v2"}`,
		"no schema":    `{}`,
		"garbage":      `not json`,
		"empty":        ``,
		"trailing":     `{"schema":"authzcov.coverage/v1"} {}`,
	} {
		if _, err := Read(strings.NewReader(in)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	_, err := Read(strings.NewReader(`{"schema":"x"}`))
	if err == nil || !strings.Contains(err.Error(), `"x"`) || !strings.Contains(err.Error(), SchemaV1) {
		t.Errorf("error should name both schemas: %v", err)
	}
	// Unknown fields are allowed.
	if _, err := Read(strings.NewReader(`{"schema":"authzcov.coverage/v1","future":1}`)); err != nil {
		t.Errorf("unknown field rejected: %v", err)
	}
}

func TestToMatrixRejectsBadCells(t *testing.T) {
	base := func() *Report {
		return &Report{Schema: SchemaV1, Endpoints: []Endpoint{{ID: "GET /x", Kind: "function"}}}
	}
	for name, mut := range map[string]func(*Report){
		"unknown endpoint": func(r *Report) { r.Cells = []Cell{{Endpoint: "GET /y", Relationship: "owner"}} },
		"bad relationship": func(r *Report) { r.Cells = []Cell{{Endpoint: "GET /x", Relationship: "zzz"}} },
		"bad status": func(r *Report) {
			r.Cells = []Cell{{Endpoint: "GET /x", Relationship: "owner", Statuses: map[string]int{"x": 1}}}
		},
		"bad confidence": func(r *Report) {
			r.Cells = []Cell{{Endpoint: "GET /x", Relationship: "owner", Covered: true, MinConfidence: "?"}}
		},
		"bad kind": func(r *Report) { r.Endpoints[0].Kind = "weird" },
	} {
		r := base()
		mut(r)
		if _, err := ToMatrix(r); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestBuildDoesNotNeedClock(t *testing.T) {
	if got := Build(Input{}).GeneratedAt; got != "1970-01-01T00:00:00Z" {
		t.Errorf("nil Now: generated_at = %q", got)
	}
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := Build(Input{Now: func() time.Time { return fixed }}).GeneratedAt; got != "2026-01-02T03:04:05Z" {
		t.Errorf("injected Now: generated_at = %q", got)
	}
}

// checkShape walks a document against a schema: every document key must be
// declared in "properties" and every "required" key must be present.
func checkShape(t *testing.T, root, sch map[string]any, doc any, path string) {
	t.Helper()
	for {
		ref, ok := sch["$ref"].(string)
		if !ok {
			break
		}
		name, found := strings.CutPrefix(ref, "#/$defs/")
		if !found {
			t.Fatalf("%s: unsupported $ref %q", path, ref)
		}
		defs, _ := root["$defs"].(map[string]any)
		next, ok := defs[name].(map[string]any)
		if !ok {
			t.Fatalf("%s: unknown $ref %q", path, ref)
		}
		sch = next
	}
	switch d := doc.(type) {
	case map[string]any:
		props, _ := sch["properties"].(map[string]any)
		if props == nil {
			return // free-form object (e.g. additionalProperties)
		}
		for k, v := range d {
			ps, ok := props[k].(map[string]any)
			if !ok {
				t.Errorf("%s.%s: not declared in schema", path, k)
				continue
			}
			checkShape(t, root, ps, v, path+"."+k)
		}
		req, _ := sch["required"].([]any)
		for _, r := range req {
			if _, ok := d[r.(string)]; !ok {
				t.Errorf("%s: required key %q missing", path, r)
			}
		}
	case []any:
		items, ok := sch["items"].(map[string]any)
		if !ok {
			return
		}
		for i, v := range d {
			checkShape(t, root, items, v, fmt.Sprintf("%s[%d]", path, i))
		}
	}
}

func TestGoldensMatchSchema(t *testing.T) {
	sb, err := os.ReadFile("../../../schema/coverage.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(sb, &root); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob("../../../testdata/golden/*.coverage.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden files: %v", err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			b, err := os.ReadFile(f) //nolint:gosec // test path
			if err != nil {
				t.Fatal(err)
			}
			var doc any
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			checkShape(t, root, root, doc, "$")
		})
	}
}

// Review KAN-24 F3: the waiver shape inside a cell.
func TestCellWaiverJSONShape(t *testing.T) {
	with, err := json.Marshal(Cell{Endpoint: "GET /a", Relationship: "owner", Required: true,
		Waiver: &CellWaiver{Reason: "Accepted for now", Expires: "2027-01-01"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(with), `"waiver":{"reason":"Accepted for now","expires":"2027-01-01"}`) {
		t.Errorf("with waiver: %s", with)
	}
	without, _ := json.Marshal(Cell{Endpoint: "GET /a", Relationship: "owner"})
	if strings.Contains(string(without), "waiver") {
		t.Errorf("without waiver: %s", without)
	}
}

func TestSuspiciousFindings(t *testing.T) {
	in := sample()
	in.Suspicious = []suspicious.Allow{{Endpoint: "GET /book/{id}", Relationship: "other_tenant", Message: "m", Evidence: []string{"t.har#1"}, Count: 1}}
	r := Build(in)
	if r.Summary.SuspiciousAllows != 1 {
		t.Errorf("summary = %d", r.Summary.SuspiciousAllows)
	}
	var f *Finding
	firstOther := -1
	for i := range r.Findings {
		if r.Findings[i].Kind == KindSuspiciousAllow {
			f = &r.Findings[i]
		} else if r.Findings[i].Kind != KindGap && firstOther < 0 {
			firstOther = i
		}
	}
	if f == nil || f.Severity != "warning" || f.Fingerprint != Fingerprint(KindSuspiciousAllow, "GET /book/{id}", "other_tenant") ||
		f.Message != "m" || len(f.Evidence) != 1 {
		t.Fatalf("finding = %+v", f)
	}
	for i, g := range r.Findings {
		if g.Kind == KindSuspiciousAllow && i > 0 && r.Findings[i-1].Kind != KindGap {
			t.Errorf("suspicious_allow not right after gaps")
		}
	}
	if Build(sample()).Summary.SuspiciousAllows != 0 {
		t.Error("expected 0 without input")
	}
}
