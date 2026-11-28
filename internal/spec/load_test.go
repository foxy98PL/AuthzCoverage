package spec

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"authzcov/internal/model"
)

func specPath(name string) string { return filepath.Join("..", "..", "testdata", "specs", name) }

func TestLoadVAmPI(t *testing.T) {
	eps, err := Load(specPath("vampi.yml"))
	if err != nil {
		t.Fatal(err)
	}
	F, O := model.FunctionLevel, model.ObjectLevel
	want := []struct {
		id       string
		params   []string
		objParam string
		resource string
		kind     model.EndpointKind
		line     int
	}{
		{"DELETE /users/v1/{username}", []string{"username"}, "username", "v1", O, 263},
		{"GET /", nil, "", "", F, 34},
		{"GET /books/v1", nil, "", "", F, 486},
		{"GET /books/v1/{book_title}", []string{"book_title"}, "book_title", "v1", O, 585},
		{"GET /createdb", nil, "", "", F, 16},
		{"GET /me", nil, "", "", F, 215},
		{"GET /users/v1", nil, "", "", F, 62},
		{"GET /users/v1/_debug", nil, "", "", F, 88},
		{"GET /users/v1/{username}", []string{"username"}, "username", "v1", O, 263},
		{"POST /books/v1", nil, "", "", F, 486},
		{"POST /users/v1/login", nil, "", "", F, 162},
		{"POST /users/v1/register", nil, "", "", F, 120},
		{"PUT /users/v1/{username}/email", []string{"username"}, "username", "v1", O, 366},
		{"PUT /users/v1/{username}/password", []string{"username"}, "username", "v1", O, 426},
	}
	if len(eps) != len(want) {
		var ids []string
		for _, e := range eps {
			ids = append(ids, e.ID)
		}
		t.Fatalf("got %d endpoints, want %d:\n%s", len(eps), len(want), strings.Join(ids, "\n"))
	}
	for i, w := range want {
		e := eps[i]
		if e.ID != w.id || !reflect.DeepEqual(e.Params, w.params) || e.ObjectParam != w.objParam ||
			e.Resource != w.resource || e.Kind != w.kind || e.SpecLine != w.line {
			t.Errorf("[%d] got %+v\nwant %+v", i, *e, w)
		}
		if e.Method+" "+e.Template != e.ID || e.SpecFile != specPath("vampi.yml") {
			t.Errorf("[%d] inconsistent ID/method/template/file: %+v", i, *e)
		}
	}
}

func TestLoadEdgeCases(t *testing.T) {
	tests := []struct {
		file    string
		wantErr error  // nil => success
		wantMsg string // substring of the error
		wantIDs []string
	}{
		{file: "dup_param_names.yml", wantErr: ErrDuplicate, wantMsg: "GET /a/{x} and GET /a/{y}"},
		{file: "dup_trailing_slash.yml", wantErr: ErrDuplicate, wantMsg: "GET /a and GET /a/"},
		{file: "ref_external_file.yml", wantErr: ErrExternalRef, wantMsg: "other.yml"},
		{file: "ref_remote.yml", wantErr: ErrExternalRef, wantMsg: "127.0.0.1"},
		{file: "partial_segment.yml", wantErr: ErrUnsupported, wantMsg: "/files/{name}.json"},
		{file: "swagger2.yml", wantErr: ErrUnsupported, wantMsg: "Swagger 2.0 is not supported"},
		{file: "does_not_exist.yml", wantMsg: "does_not_exist.yml"},
		{file: "minimal.json", wantIDs: []string{"DELETE /items/{id}", "GET /items"}},
		{file: "multi_param_31.yml", wantIDs: []string{"GET /health", "GET /orgs/{org}/repos/{repo}", "GET /{entity}/me"}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			eps, err := Load(specPath(tt.file))
			if tt.wantErr == nil && tt.wantMsg == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				var ids []string
				for _, e := range eps {
					ids = append(ids, e.ID)
				}
				if !reflect.DeepEqual(ids, tt.wantIDs) {
					t.Fatalf("ids = %v, want %v", ids, tt.wantIDs)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error, got %d endpoints", len(eps))
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want errors.Is %v", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("err = %q, want substring %q", err, tt.wantMsg)
			}
		})
	}
}

func TestEndpointFields(t *testing.T) {
	eps, err := Load(specPath("multi_param_31.yml"))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]*model.Endpoint{}
	for _, e := range eps {
		byID[e.ID] = e
	}
	tests := []struct {
		id, objParam, resource string
		params                 []string
		kind                   model.EndpointKind
	}{
		{"GET /orgs/{org}/repos/{repo}", "repo", "repos", []string{"org", "repo"}, model.ObjectLevel},
		{"GET /{entity}/me", "entity", "", []string{"entity"}, model.ObjectLevel},
		{"GET /health", "", "", nil, model.FunctionLevel},
	}
	for _, tt := range tests {
		e := byID[tt.id]
		if e == nil {
			t.Fatalf("missing %s", tt.id)
		}
		if e.ObjectParam != tt.objParam || e.Resource != tt.resource || !reflect.DeepEqual(e.Params, tt.params) || e.Kind != tt.kind {
			t.Errorf("%s: got %+v", tt.id, *e)
		}
	}
}

func TestJSONSpecLines(t *testing.T) {
	eps, err := Load(specPath("minimal.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"GET /items": 5, "DELETE /items/{id}": 6}
	for _, e := range eps {
		if e.SpecLine != want[e.ID] {
			t.Errorf("%s: line %d, want %d", e.ID, e.SpecLine, want[e.ID])
		}
	}
}

func TestLoadDeterministic(t *testing.T) {
	first, err := Load(specPath("vampi.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for range 20 { // map iteration order varies between runs
		again, err := Load(specPath("vampi.yml"))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatal("Load output differs between runs")
		}
	}
}

func TestPathLinesBadInput(t *testing.T) {
	for _, in := range []string{"", "- a\n- b\n", "paths: [1]\n", ":\n\t:"} {
		if got := pathLines([]byte(in)); len(got) != 0 {
			t.Errorf("pathLines(%q) = %v, want empty", in, got)
		}
	}
}

func TestAuthRequired(t *testing.T) {
	tests := []struct {
		name   string
		global string
		op     string
		want   bool
	}{
		{"global only", "security: [{bearer: []}]\n", "", true},
		{"none anywhere", "", "", false},
		{"op overrides global with security", "security: [{bearer: []}]\n", "      security: [{key: []}]\n", true},
		{"op empty list is public", "security: [{bearer: []}]\n", "      security: []\n", false},
		{"op empty requirement object is public", "security: [{bearer: []}]\n", "      security: [{}]\n", false},
		{"optional auth among alternatives is public", "", "      security: [{bearer: []}, {}]\n", false},
		{"op only", "", "      security: [{bearer: []}]\n", true},
		{"global empty list", "security: []\n", "", false},
		{"global empty object", "security: [{}]\n", "", false},
		{"global empty list, op requires", "security: []\n", "      security: [{bearer: []}]\n", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := "openapi: 3.0.3\ninfo: {title: t, version: '1'}\n" + tc.global +
				"components:\n  securitySchemes:\n    bearer: {type: http, scheme: bearer}\n    key: {type: apiKey, in: header, name: X-K}\n" +
				"paths:\n  /x:\n    get:\n" + tc.op + "      responses: {'200': {description: ok}}\n"
			eps, err := parse([]byte(doc), "t.yaml")
			if err != nil {
				t.Fatal(err)
			}
			if len(eps) != 1 || eps[0].AuthRequired != tc.want {
				t.Fatalf("AuthRequired = %v, want %v", eps[0].AuthRequired, tc.want)
			}
		})
	}
}

func TestQueryParamsRecorded(t *testing.T) {
	const doc = `openapi: 3.0.3
info: {title: q, version: "1"}
paths:
  /items/{id}:
    parameters:
      - {name: shared, in: query, schema: {type: string}}
      - {name: hdr, in: header, schema: {type: string}}
      - {name: id, in: path, required: true, schema: {type: string}}
    get:
      parameters:
        - {name: uid, in: query, schema: {type: string}}
      responses: {"200": {description: ok}}
    delete:
      responses: {"200": {description: ok}}
`
	p := filepath.Join(t.TempDir(), "s.yml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	eps, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, e := range eps {
		got[e.ID] = e.QueryParams
		if !reflect.DeepEqual(e.Params, []string{"id"}) || e.ObjectParam != "id" {
			t.Errorf("%s: path params changed: %v %q", e.ID, e.Params, e.ObjectParam)
		}
	}
	want := map[string][]string{
		"GET /items/{id}":    {"shared", "uid"},
		"DELETE /items/{id}": {"shared"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("QueryParams = %v, want %v", got, want)
	}
}
