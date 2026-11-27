package plan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authzcov/internal/report/coveragejson"
)

func idn(name, role string, rank int, tenant string) coveragejson.Identity {
	return coveragejson.Identity{Name: name, Role: role, Rank: rank, Tenant: tenant}
}

// fixture: owner ann (user, OrgA) owns order o1; others around her.
func fixture(rels ...string) *coveragejson.Report {
	r := &coveragejson.Report{
		GeneratedAt: "2026-01-01T00:00:00Z",
		Identities: []coveragejson.Identity{
			idn("unknown-1", "unknown", -1, ""), idn("anonymous", "anonymous", 0, ""),
			idn("zed", "admin", 100, "OrgA"), idn("ann", "user", 10, "OrgA"), idn("amy", "user", 10, "OrgA"),
			idn("ben", "user", 10, "OrgB"), idn("intern", "guest", 1, "OrgA"), idn("root", "admin", 100, "*"),
		},
		Endpoints: []coveragejson.Endpoint{
			{ID: "GET /orgs/{orgId}/orders/{id}", Method: "GET", Template: "/orgs/{orgId}/orders/{id}", Kind: "object", Resource: "orders", ObjectParam: "id"},
			{ID: "GET /admin", Method: "GET", Template: "/admin", Kind: "function", MinAllowedRole: &coveragejson.MinAllowed{Role: "user"}},
		},
		Objects: []coveragejson.Object{{Resource: "orders", IDHash: "aaaaaaaa", Owner: "ann", Tenant: "OrgA"}},
	}
	for _, rel := range rels {
		r.Cells = append(r.Cells,
			coveragejson.Cell{Endpoint: "GET /orgs/{orgId}/orders/{id}", Relationship: rel, Required: true},
			coveragejson.Cell{Endpoint: "GET /admin", Relationship: rel, Required: true})
	}
	return r
}

func TestAttackerPerRelationship(t *testing.T) {
	obj := map[string]string{
		"owner": "ann", "same_role_other_user": "amy", "other_tenant": "ben", "lower_role": "intern",
		"higher_role": "root", "anonymous": "anonymous",
	}
	// Function-level (min role user): owner = rank 10, lower = below, higher = above.
	fn := map[string]string{
		"owner": "amy", "lower_role": "intern", "higher_role": "root", "anonymous": "anonymous",
	}
	for rel := range obj {
		p := Build(fixture(rel), Options{})
		if len(p.Probes) != 2 {
			t.Fatalf("%s: %d probes", rel, len(p.Probes))
		}
		byEp := map[string]Probe{}
		for _, pr := range p.Probes {
			byEp[pr.Endpoint] = pr
		}
		if got := byEp["GET /orgs/{orgId}/orders/{id}"]; got.Attacker == nil || got.Attacker.Identity != obj[rel] {
			t.Errorf("object-level %s: attacker %+v, want %s", rel, got.Attacker, obj[rel])
		}
		got := byEp["GET /admin"]
		if want, ok := fn[rel]; ok {
			if got.Attacker == nil || got.Attacker.Identity != want {
				t.Errorf("function-level %s: attacker %+v, want %s", rel, got.Attacker, want)
			}
		}
	}
}

func TestAttackerNeverUnknownOrWildcardTenantAsOther(t *testing.T) {
	r := fixture("other_tenant")
	r.Identities = []coveragejson.Identity{idn("ann", "user", 10, "OrgA"), idn("root", "admin", 100, "*"), idn("unknown-2", "unknown", -1, "OrgZ")}
	p := Build(r, Options{})
	for _, pr := range p.Probes {
		if pr.Attacker != nil {
			t.Errorf("%s: want null attacker, got %+v", pr.Endpoint, pr.Attacker)
		}
		if pr.Note == "" {
			t.Errorf("%s: null attacker needs a note", pr.Endpoint)
		}
	}
}

func TestNoteWhenNoObject(t *testing.T) {
	r := fixture("same_role_other_user")
	r.Objects = nil
	for _, pr := range Build(r, Options{}).Probes {
		if pr.Endpoint == "GET /orgs/{orgId}/orders/{id}" && (pr.Attacker != nil || pr.Note != NoteNoObject) {
			t.Errorf("%+v", pr)
		}
	}
}

func TestGapSelectionAndWaivers(t *testing.T) {
	r := fixture()
	ep := "GET /orgs/{orgId}/orders/{id}"
	r.Cells = []coveragejson.Cell{
		{Endpoint: ep, Relationship: "owner", Required: true, Covered: true},
		{Endpoint: ep, Relationship: "other_tenant", Required: true},
		{Endpoint: ep, Relationship: "anonymous", Required: true, Waiver: &coveragejson.CellWaiver{Reason: "r", Expires: "2027-01-01"}},
		{Endpoint: ep, Relationship: "lower_role", Required: false},
		{Endpoint: ep, Relationship: "same_role_other_user", Required: false, Statuses: map[string]int{"403": 1}},
	}
	rels := func(o Options) string {
		var out []string
		for _, p := range Build(r, o).Probes {
			out = append(out, p.Relationship+fmt.Sprint(p.Waived))
		}
		return strings.Join(out, ",")
	}
	if got := rels(Options{}); got != "other_tenantfalse" {
		t.Errorf("default = %s", got)
	}
	if got := rels(Options{IncludeWaived: true}); got != "other_tenantfalse,anonymoustrue" {
		t.Errorf("include waived = %s", got)
	}
}

func TestRawIDsAndTenantParams(t *testing.T) {
	r := fixture("owner")
	raw := &Raw{IDs: map[string]string{"orders/aaaaaaaa": "ord-1"}, TenantParams: map[string]bool{"orgId": true}}
	p := Build(r, Options{Raw: raw})
	if !p.ContainsRawIDs {
		t.Error("contains_raw_ids")
	}
	for _, pr := range p.Probes {
		if pr.Object != nil && (pr.Object.ID != "ord-1" || pr.PathParams["orgId"] != "OrgA") {
			t.Errorf("%+v %+v", pr.Object, pr.PathParams)
		}
	}
	if q := Build(r, Options{}); q.ContainsRawIDs {
		t.Error("no raw => false")
	}
}

func TestDeclaredIdentitiesOnlyFillGaps(t *testing.T) {
	r := fixture("other_tenant")
	r.Identities = []coveragejson.Identity{idn("ann", "user", 10, "OrgA")}
	raw := &Raw{Declared: []coveragejson.Identity{idn("ann", "user", 10, ""), idn("carl", "user", 10, "OrgC")}}
	for _, pr := range Build(r, Options{Raw: raw}).Probes {
		if pr.Endpoint == "GET /orgs/{orgId}/orders/{id}" && (pr.Attacker == nil || pr.Attacker.Identity != "carl") {
			t.Errorf("%+v", pr.Attacker)
		}
	}
}

// shape mirrors the key check of the coverage.json schema test: every key must
// be declared, every required key present, enums respected.
func shape(t *testing.T, root, sch map[string]any, doc any, path string) {
	t.Helper()
	for {
		ref, ok := sch["$ref"].(string)
		if !ok {
			break
		}
		name := strings.TrimPrefix(ref, "#/$defs/")
		next, ok := root["$defs"].(map[string]any)[name].(map[string]any)
		if !ok {
			t.Fatalf("%s: bad $ref %q", path, ref)
		}
		sch = next
	}
	if alts, ok := sch["oneOf"].([]any); ok { // attacker: null or object
		if doc == nil {
			return
		}
		shape(t, root, alts[1].(map[string]any), doc, path)
		return
	}
	if en, ok := sch["enum"].([]any); ok {
		for _, e := range en {
			if e == doc {
				return
			}
		}
		t.Errorf("%s: %v not in enum %v", path, doc, en)
		return
	}
	switch d := doc.(type) {
	case map[string]any:
		props, _ := sch["properties"].(map[string]any)
		if props == nil {
			return
		}
		for k, v := range d {
			ps, ok := props[k].(map[string]any)
			if !ok {
				t.Errorf("%s.%s: not declared in schema", path, k)
				continue
			}
			shape(t, root, ps, v, path+"."+k)
		}
		req, _ := sch["required"].([]any)
		for _, r := range req {
			if _, ok := d[r.(string)]; !ok {
				t.Errorf("%s: required key %q missing", path, r)
			}
		}
	case []any:
		if items, ok := sch["items"].(map[string]any); ok {
			for i, v := range d {
				shape(t, root, items, v, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
}

func TestGoldenPlansMatchSchema(t *testing.T) {
	sb, err := os.ReadFile("../../schema/plan.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(sb, &root); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob("../../testdata/golden/*.plan.json")
	if err != nil || len(files) < 2 {
		t.Fatalf("golden plans: %v %v", files, err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f) //nolint:gosec // fixed test path
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		shape(t, root, root, doc, filepath.Base(f))
	}
	// Raw ids and waived flag are declared too.
	p := Build(fixture("owner"), Options{Raw: &Raw{IDs: map[string]string{"orders/aaaaaaaa": "x"}, TenantParams: map[string]bool{"orgId": true}}, IncludeWaived: true})
	b, _ := json.Marshal(p)
	var doc map[string]any
	_ = json.Unmarshal(b, &doc)
	shape(t, root, root, doc, "raw")
}
