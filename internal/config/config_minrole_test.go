package config

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const minRoleBase = `version: 1
roles: {customer: 10, admin: 100, anonymous: 0}
identities:
  - {name: alice, role: customer, match: {jwt: {sub: alice}}}
`

func TestParseMinRole(t *testing.T) {
	y := minRoleBase + `requirements:
  overrides:
    - {endpoint: "GET /orgs/{orgId}/customers", min_role: admin}
    - {endpoint: "GET /orgs/{orgId}/repos/{repo}", object_param: orgId, min_role: customer}
    - {endpoint: "GET /orgs/{orgId}/x", object_param: orgId}
`
	f, err := Parse([]byte(y), "ids.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := []Override{
		{Endpoint: "GET /orgs/{orgId}/customers", MinRole: "admin", Line: 7},
		{Endpoint: "GET /orgs/{orgId}/repos/{repo}", ObjectParam: "orgId", MinRole: "customer", Line: 8},
		{Endpoint: "GET /orgs/{orgId}/x", ObjectParam: "orgId", Line: 9},
	}
	if !reflect.DeepEqual(f.Overrides, want) {
		t.Errorf("overrides = %+v", f.Overrides)
	}
}

func TestParseMinRoleErrors(t *testing.T) {
	tests := []struct {
		name, extra string
		line        int
		path, msg   string
	}{
		{"unknown role", "requirements:\n  overrides:\n    - {endpoint: \"GET /a\", min_role: boss}\n", 7, "requirements.overrides[0].min_role", `"boss"`},
		{"empty role", "requirements:\n  overrides:\n    - {endpoint: \"GET /a\", min_role: \"\"}\n", 7, "requirements.overrides[0].min_role", "must not be empty"},
		{"not a string", "requirements:\n  overrides:\n    - {endpoint: \"GET /a\", min_role: [admin]}\n", 7, "requirements.overrides[0].min_role", "scalar"},
		{"anonymous", "requirements:\n  overrides:\n    - {endpoint: \"GET /a\", min_role: anonymous}\n", 7, "requirements.overrides[0].min_role", "security: []"},
		{"neither key", "requirements:\n  overrides:\n    - {endpoint: \"GET /a\"}\n", 7, "requirements.overrides[0].object_param", "min_role"},
		{"second entry bad role", "requirements:\n  overrides:\n    - {endpoint: \"GET /a\", min_role: admin}\n    - {endpoint: \"GET /b\", min_role: nope}\n", 8, "requirements.overrides[1].min_role", `"nope"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(minRoleBase+tc.extra), "ids.yaml")
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
