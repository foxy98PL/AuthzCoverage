package config

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const tenBase = `version: 1
roles: {user: 10}
identities:
  - {name: alice, role: user, match: {jwt: {sub: alice}}}
`

func TestParseTenancyFeatures(t *testing.T) {
	y := tenBase + `jwt: {subject: sub, tenant: claims.org_id}
tenancy:
  tenant_params: {orgId: name}
requirements:
  overrides:
    - {endpoint: "GET /orgs/{orgId}/repos/{repo}", object_param: orgId}
ownership:
  learn_from_lists:
    - match: {method: GET, path: /books/v1}
      resource: books
      ids_from: {response_json: "books[].book_title"}
`
	f, err := Parse([]byte(y), "ids.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if f.JWTSubject != "sub" || f.JWTTenant != "claims.org_id" {
		t.Errorf("jwt = %q %q", f.JWTSubject, f.JWTTenant)
	}
	if !reflect.DeepEqual(f.TenantParams, map[string]string{"orgId": "name"}) {
		t.Errorf("tenant params = %v", f.TenantParams)
	}
	wantOv := []Override{{Endpoint: "GET /orgs/{orgId}/repos/{repo}", ObjectParam: "orgId", Line: 10}}
	if !reflect.DeepEqual(f.Overrides, wantOv) {
		t.Errorf("overrides = %+v", f.Overrides)
	}
	wantL := []ListRule{{Method: "GET", Path: "/books/v1", Resource: "books", IDsFromResponseJSON: "books[].book_title", Line: 13}}
	if !reflect.DeepEqual(f.Ownership.LearnFromLists, wantL) {
		t.Errorf("lists = %+v", f.Ownership.LearnFromLists)
	}
}

func TestHasTenantsSources(t *testing.T) {
	tests := []struct {
		name, extra string
		want        bool
	}{
		{"none", "", false},
		{"identity tenant", "", false}, // replaced below
		{"tenant param", "tenancy: {tenant_params: {orgId: name}}\n", true},
		{"jwt tenant", "jwt: {tenant: org_id}\n", true},
		{"jwt subject only", "jwt: {subject: sub}\n", false},
		{"empty tenancy", "tenancy: {}\n", false},
	}
	for _, tc := range tests {
		y := tenBase + tc.extra
		if tc.name == "identity tenant" {
			y = strings.Replace(y, "role: user,", "role: user, tenant: acme,", 1)
			tc.want = true
		}
		f, err := Parse([]byte(y), "x.yaml")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if f.HasTenants() != tc.want {
			t.Errorf("%s: HasTenants = %v", tc.name, f.HasTenants())
		}
	}
}

func TestParseTenancyErrors(t *testing.T) {
	tests := []struct {
		name, extra string
		line        int
		path, msg   string
	}{
		{"tenant param value", "tenancy:\n  tenant_params: {orgId: id}\n", 6, "tenancy.tenant_params.orgId", `only "name"`},
		{"tenant param empty", "tenancy:\n  tenant_params: {orgId: ''}\n", 6, "tenancy.tenant_params.orgId", "empty"},
		{"tenancy unknown key", "tenancy:\n  tenants: {}\n", 6, "tenancy", `unknown key "tenants"`},
		{"jwt tenant bad", "jwt: {tenant: 'a..b'}\n", 5, "jwt.tenant", "dot path"},
		{"jwt tenant deep", "jwt: {tenant: a.b.c.d.e.f}\n", 5, "jwt.tenant", "depth"},
		{"override missing param", "requirements:\n  overrides:\n    - {endpoint: 'GET /a/{x}'}\n", 7, "requirements.overrides[0].object_param", "required"},
		{"override missing endpoint", "requirements:\n  overrides:\n    - {object_param: x}\n", 7, "requirements.overrides[0].endpoint", "required"},
		{"override bad endpoint", "requirements:\n  overrides:\n    - {endpoint: '/a/{x}', object_param: x}\n", 7, "requirements.overrides[0].endpoint", "endpoint ID"},
		{"override unknown key", "requirements:\n  overrides:\n    - {endpoint: 'GET /a/{x}', object_param: x, ignore: true}\n", 7, "requirements.overrides[0]", `unknown key "ignore"`},
		{"override duplicate", "requirements:\n  overrides:\n    - {endpoint: 'GET /a/{x}', object_param: x}\n    - {endpoint: 'GET /a/{x}', object_param: x}\n", 8, "requirements.overrides[1].endpoint", "duplicate"},
		{"override not list", "requirements:\n  overrides: {}\n", 6, "requirements.overrides", "list"},
		{"requirements unknown key", "requirements:\n  roles: {}\n", 6, "requirements", `unknown key "roles"`},
		{"list bad method", listY("match: {method: get, path: /b}", "books", "{response_json: a}"), 7, "ownership.learn_from_lists[0].match.method", "upper-case"},
		{"list bad path", listY("match: {method: GET, path: b}", "books", "{response_json: a}"), 7, "ownership.learn_from_lists[0].match.path", `start with "/"`},
		{"list missing resource", "ownership:\n  learn_from_lists:\n    - match: {method: GET, path: /b}\n      ids_from: {response_json: a}\n", 7, "ownership.learn_from_lists[0].resource", "required"},
		{"list missing ids_from", "ownership:\n  learn_from_lists:\n    - match: {method: GET, path: /b}\n      resource: books\n", 7, "ownership.learn_from_lists[0].ids_from", "required"},
		{"list path bad", listY("match: {method: GET, path: /b}", "books", "{response_json: 'a[]b'}"), 9, "ownership.learn_from_lists[0].ids_from.response_json", "every element"},
		{"list path empty segment", listY("match: {method: GET, path: /b}", "books", "{response_json: 'a..b'}"), 9, "ownership.learn_from_lists[0].ids_from.response_json", "every element"},
		{"list ids_from key", listY("match: {method: GET, path: /b}", "books", "{request_json: a}"), 9, "ownership.learn_from_lists[0].ids_from", `unknown key "request_json"`},
		{"lists not list", "ownership:\n  learn_from_lists: {}\n", 6, "ownership.learn_from_lists", "list"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tenBase+tc.extra), "ids.yaml")
			var ce *Error
			if !errors.As(err, &ce) {
				t.Fatalf("err = %v, want *Error", err)
			}
			if ce.Line != tc.line || ce.Path != tc.path || !strings.Contains(ce.Msg, tc.msg) {
				t.Errorf("got line=%d path=%q msg=%q; want line=%d path=%q msg~%q", ce.Line, ce.Path, ce.Msg, tc.line, tc.path, tc.msg)
			}
		})
	}
}

func listY(match, resource, ids string) string {
	return "ownership:\n  learn_from_lists:\n    - " + match + "\n      resource: " + resource + "\n      ids_from: " + ids + "\n"
}

func TestListPathsAccepted(t *testing.T) {
	for _, p := range []string{"items[].id", "data.items[].id", "[].id", "ids[]", "a.b", "g[].i[].id", "[]"} {
		y := tenBase + listY("match: {method: GET, path: /b}", "books", "{response_json: '"+p+"'}")
		if _, err := Parse([]byte(y), "x.yaml"); err != nil {
			t.Errorf("%q rejected: %v", p, err)
		}
	}
}

func TestParseListExclusive(t *testing.T) {
	rule := func(extra string) string {
		return tenBase + "ownership:\n  learn_from_lists:\n    - match: {method: GET, path: /v}\n      resource: v\n      ids_from: {response_json: \"[].id\"}\n" + extra
	}
	f, err := Parse([]byte(rule("      exclusive: true\n")), "ids.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !f.Ownership.LearnFromLists[0].Exclusive {
		t.Error("exclusive: true not parsed")
	}
	f, err = Parse([]byte(rule("      exclusive: false\n")), "ids.yaml")
	if err != nil || f.Ownership.LearnFromLists[0].Exclusive {
		t.Errorf("exclusive false: %v %+v", err, f)
	}
	f, err = Parse([]byte(rule("")), "ids.yaml")
	if err != nil || f.Ownership.LearnFromLists[0].Exclusive {
		t.Errorf("default: %v", err)
	}
	_, err = Parse([]byte(rule("      exclusive: yes please\n")), "ids.yaml")
	if err == nil || !strings.Contains(err.Error(), "ids.yaml:") || !strings.Contains(err.Error(), "exclusive") {
		t.Errorf("non-bool err = %v", err)
	}
	_, err = Parse([]byte(rule("      exclusiv: true\n")), "ids.yaml")
	if err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Errorf("unknown key err = %v", err)
	}
}
