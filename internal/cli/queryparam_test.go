package cli

import (
	"strings"
	"testing"

	"authzcov/internal/testutil/hartest"
)

const queryObjSpec = `openapi: 3.0.3
info: {title: q, version: "1"}
paths:
  /items/{id}:
    get:
      parameters:
        - {name: id, in: path, required: true, schema: {type: string}}
        - {name: uid, in: query, schema: {type: string}}
      responses: {"200": {description: ok}}
  /search:
    get:
      parameters:
        - {name: uid, in: query, schema: {type: string}}
      responses: {"200": {description: ok}}
`

func queryIDs(ov string) string {
	return `version: 1
roles: {user: 10}
identities:
  - {name: alice, role: user, match: {jwt: {sub: alice}}}
  - {name: bob, role: user, match: {jwt: {sub: bob}}}
resources: {uid: users}
ownership:
  self_params: {uid: subject}
requirements:
  overrides:
` + ov
}

const searchOV = "    - {endpoint: \"GET /search\", object_param: uid}\n"

func TestQueryObjectParam(t *testing.T) {
	a := hartest.Bearer(hartest.JWT(t, "alice", nil))
	const row = "GET     /search"
	tests := []struct {
		name, query, owner string
	}{
		{"single value", "?uid=alice", "ok"},
		{"absent", "", "GAP"},
		{"empty", "?uid=", "GAP"},
		{"repeated", "?uid=alice&uid=alice", "GAP"},
		{"comma list", "?uid=alice,bob", "GAP"},
		{"array syntax", "?uid[]=alice", "GAP"},
		{"encoded comma", "?uid=alice%2Cbob", "GAP"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			es := []hartest.Entry{{Method: "GET", URL: base + "/search" + tc.query, Status: 200, Headers: a}}
			code, out, errs := runInline(t, queryObjSpec, queryIDs(searchOV), es)
			if code != ExitOK || cells(t, out, row)["OWNER"] != tc.owner {
				t.Fatalf("exit %d owner %q want %q\n%s%s", code, cells(t, out, row)["OWNER"], tc.owner, out, errs)
			}
		})
	}
}

func TestQueryObjectParamNoLeak(t *testing.T) {
	a := hartest.Bearer(hartest.JWT(t, "alice", nil))
	es := []hartest.Entry{{Method: "GET", URL: base + "/search?uid=alice&access_token=TOPSECRET", Status: 200, Headers: a}}
	code, out, errs := runInline(t, queryObjSpec, queryIDs(searchOV), es)
	if code != ExitOK || strings.Contains(out+errs, "TOPSECRET") {
		t.Fatalf("exit %d leak?\n%s%s", code, out, errs)
	}
}

func TestQueryObjectParamErrors(t *testing.T) {
	ov := "    - {endpoint: \"GET /search\", object_param: nope}\n"
	code, out, errs := runInline(t, queryObjSpec, queryIDs(ov), nil)
	if code != ExitUsage || out != "" || !strings.Contains(errs, "ids.yaml:") ||
		!strings.Contains(errs, `object_param "nope"`) || !strings.Contains(errs, "path parameters") || !strings.Contains(errs, "query parameters: uid") {
		t.Fatalf("exit %d out %q err %q", code, out, errs)
	}
}

func TestQueryObjectParamPathWins(t *testing.T) {
	// uid on /items/{id} is query-only; id is a path param and stays the object.
	a := hartest.Bearer(hartest.JWT(t, "alice", nil))
	ov := "    - {endpoint: \"GET /items/{id}\", object_param: uid}\n"
	es := []hartest.Entry{{Method: "GET", URL: base + "/items/x1?uid=alice", Status: 200, Headers: a}}
	code, out, errs := runInline(t, queryObjSpec, queryIDs(ov), es)
	if code != ExitOK || cells(t, out, "GET     /items/{id}")["OWNER"] != "ok" {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
}

const queryLearnSpec = `openapi: 3.0.3
info: {title: q, version: "1"}
paths:
  /users:
    get:
      responses: {"200": {description: ok}}
  /search:
    get:
      parameters:
        - {name: uid, in: query, schema: {type: string}}
      responses: {"200": {description: ok}}
  /find:
    get:
      parameters:
        - {name: uid, in: query, schema: {type: string}}
      responses: {"200": {description: ok}}
`

const queryLearnIDs = `version: 1
roles: {user: 10}
identities:
  - {name: alice, role: user, match: {jwt: {sub: alice}}}
  - {name: bob, role: user, match: {jwt: {sub: bob}}}
RES
ownership:
  learn_from_lists:
    - match: {method: GET, path: /users}
      resource: users
      exclusive: true
      ids_from: {response_json: "[].id"}
requirements:
  overrides:
    - {endpoint: "GET /search", object_param: uid}
    - {endpoint: "GET /find", object_param: uid}
`

// KAN-104 F1: a learned owner resolves a query object through resources.
func TestQueryObjectLearnedOwner(t *testing.T) {
	a := hartest.Bearer(hartest.JWT(t, "alice", nil))
	es := []hartest.Entry{
		{Method: "GET", URL: base + "/users", Status: 200, Headers: a, RespJSON: `[{"id":"u1"}]`},
		{Method: "GET", URL: base + "/search?uid=u1", Status: 200, Headers: a},
	}
	ids := strings.Replace(queryLearnIDs, "RES", "resources: {uid: users}", 1)
	code, out, errs := runInline(t, queryLearnSpec, ids, es)
	if code != ExitOK || cells(t, out, "GET     /search")["OWNER"] != "ok" {
		t.Fatalf("exit %d owner %q\n%s%s", code, cells(t, out, "GET     /search")["OWNER"], out, errs)
	}
}

// KAN-104 F1: without a resources mapping Resource stays "", so the same
// value on two endpoints must not collide into a known owner.
func TestQueryObjectEmptyResourceNoCollision(t *testing.T) {
	a := hartest.Bearer(hartest.JWT(t, "alice", nil))
	b := hartest.Bearer(hartest.JWT(t, "bob", nil))
	es := []hartest.Entry{
		{Method: "GET", URL: base + "/users", Status: 200, Headers: a, RespJSON: `[{"id":"u1"}]`},
		{Method: "GET", URL: base + "/search?uid=u1", Status: 200, Headers: a},
		{Method: "GET", URL: base + "/find?uid=u1", Status: 200, Headers: b},
	}
	code, out, errs := runInline(t, queryLearnSpec, strings.Replace(queryLearnIDs, "RES\n", "", 1), es)
	for _, r := range []string{"GET     /search", "GET     /find"} {
		if code != ExitOK || cells(t, out, r)["OWNER"] == "ok" {
			t.Fatalf("exit %d %s owner %q\n%s%s", code, r, cells(t, out, r)["OWNER"], out, errs)
		}
	}
}

// KAN-104 F2: a query object param cannot be tenant-scoped.
func TestQueryObjectTenantParamRejected(t *testing.T) {
	ids := queryIDs(searchOV) + "tenancy:\n  tenant_params: {uid: name}\n"
	a := hartest.Bearer(hartest.JWT(t, "alice", nil))
	es := []hartest.Entry{{Method: "GET", URL: base + "/search?uid=alice", Status: 200, Headers: a}}
	code, out, errs := runInline(t, queryObjSpec, ids, es)
	if code != ExitUsage || out != "" || !strings.Contains(errs, "ids.yaml:") || !strings.Contains(errs, "tenant_params") {
		t.Fatalf("exit %d out %q err %q", code, out, errs)
	}
}

// KAN-104 F3: whitespace and control characters are not a single plain value.
// The caller's subject equals the value, so only the value check yields GAP.
func TestQueryObjectValueRejectsWhitespace(t *testing.T) {
	for _, tc := range []struct{ sub, q string }{
		{"al ice", "al%20ice"}, {"a\x00b", "a%00b"}, {"a\tb", "a%09b"}, {"a\nb", "a%0Ab"},
	} {
		ids := strings.Replace(queryIDs(searchOV), "{name: alice, role: user, match: {jwt: {sub: alice}}}",
			"{name: alice, role: user, match: {jwt: {sub: \""+strings.NewReplacer("\x00", "\\0", "\t", "\\t", "\n", "\\n").Replace(tc.sub)+"\"}}}", 1)
		a := hartest.Bearer(hartest.JWT(t, tc.sub, nil))
		es := []hartest.Entry{{Method: "GET", URL: base + "/search?uid=" + tc.q, Status: 200, Headers: a}}
		code, out, errs := runInline(t, queryObjSpec, ids, es)
		if code != ExitOK || cells(t, out, "GET     /search")["OWNER"] != "GAP" {
			t.Fatalf("%q: exit %d\n%s%s", tc.q, code, out, errs)
		}
	}
}
