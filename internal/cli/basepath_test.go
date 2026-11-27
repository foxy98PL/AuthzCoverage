package cli

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authzcov/internal/model"
	"authzcov/internal/testutil/hartest"
)

const clinicSpec = `openapi: 3.0.3
info: {title: clinic, version: "1"}
paths:
  /api/owners:
    get: {responses: {"200": {description: ok}}}
  /api/owners/{ownerId}:
    parameters:
      - {name: ownerId, in: path, required: true, schema: {type: string}}
    get: {responses: {"200": {description: ok}}}
`

const clinicIDs = "../../testdata/identities/vampi.yaml"

func clinicFixture(t *testing.T, prefix string) (specPath, harPath string, es []hartest.Entry) {
	t.Helper()
	dir := t.TempDir()
	specPath = filepath.Join(dir, "clinic.yml")
	if err := os.WriteFile(specPath, []byte(clinicSpec), 0o600); err != nil {
		t.Fatal(err)
	}
	a := hartest.Bearer(hartest.JWT(t, "alice", nil))
	es = []hartest.Entry{
		{Method: "GET", URL: base + prefix + "/api/owners", Status: 200, Headers: a},
		{Method: "GET", URL: base + prefix + "/api/owners/7", Status: 200, Headers: a},
		{Method: "GET", URL: base + prefix + "/api/v2/coupons/101", Status: 404, Headers: a},
		{Method: "GET", URL: base + prefix + "/api/v2/coupons/102", Status: 404, Headers: a},
		{Method: "GET", URL: base + prefix + "/api/v2/coupons/103", Status: 404, Headers: a},
	}
	harPath = hartest.WriteHAR(t, dir, "c.har", es...)
	return specPath, harPath, es
}

func runArgs(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Execute(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestBasePath(t *testing.T) {
	specPath, harPath, _ := clinicFixture(t, "/petclinic")
	tests := []struct {
		name    string
		extra   []string
		want    int
		inErr   []string
		inOut   []string
		notInEr []string
	}{
		{"auto default", nil, ExitOK,
			[]string{`base path for localhost:5000: "/petclinic" (matched 2/5, 40.0%)`, "unmatched requests by shape:", "  3  GET /api/v2/coupons/<id>"},
			[]string{"/api/owners/{ownerId}"}, nil},
		{"auto explicit", []string{"--base-path", "auto"}, ExitOK, []string{`"/petclinic"`}, []string{"/api/owners"}, nil},
		{"explicit prefix", []string{"--base-path", "/petclinic"}, ExitOK, []string{`"/petclinic" (matched 2/5`}, []string{"/api/owners/{ownerId}"}, nil},
		{"explicit with trailing slash", []string{"--base-path", "/petclinic/"}, ExitOK, nil, []string{"/api/owners"}, nil},
		{"none matches nothing", []string{"--base-path", "none"}, ExitInput, []string{`"" (matched 0/5`, "no recorded request matched", "hosts without matches 1"}, nil, []string{"unmatched requests by shape"}},
		{"wrong explicit prefix", []string{"--base-path", "/other"}, ExitInput, []string{"no recorded request matched"}, nil, nil},
		{"invalid", []string{"--base-path", "petclinic"}, ExitUsage, []string{"invalid --base-path"}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"coverage", "--spec", specPath, "--har", harPath, "--identities", clinicIDs}, tt.extra...)
			code, out, errs := runArgs(args...)
			if code != tt.want {
				t.Fatalf("exit = %d, want %d; stderr=%s", code, tt.want, errs)
			}
			for _, s := range tt.inErr {
				if !strings.Contains(errs, s) {
					t.Errorf("stderr missing %q:\n%s", s, errs)
				}
			}
			for _, s := range tt.notInEr {
				if strings.Contains(errs, s) {
					t.Errorf("stderr has %q:\n%s", s, errs)
				}
			}
			for _, s := range tt.inOut {
				if !strings.Contains(out, s) {
					t.Errorf("stdout missing %q:\n%s", s, out)
				}
			}
		})
	}
}

func TestAutoBasePathCoversEndpoints(t *testing.T) {
	specPath, harPath, _ := clinicFixture(t, "/petclinic")
	code, out, errs := runArgs("coverage", "--spec", specPath, "--har", harPath, "--identities", clinicIDs)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(errs, "matched 2,") {
		t.Errorf("want 2 matched exchanges:\n%s", errs)
	}
	for _, ep := range []string{"/api/owners "} {
		found := false
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, ep) && strings.Contains(l, "ok") {
				found = true
			}
		}
		if !found {
			t.Errorf("endpoint %q not covered in:\n%s", ep, out)
		}
	}
}

func TestHARZipEndToEnd(t *testing.T) {
	specPath, harPath, _ := clinicFixture(t, "/petclinic")
	raw, err := os.ReadFile(harPath) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatal(err)
	}
	zp := filepath.Join(t.TempDir(), "run.har.zip")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"trace/1.har", "readme.txt"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		content := raw
		if name == "readme.txt" {
			content = []byte("not a har")
		}
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zp, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runArgs("coverage", "--spec", specPath, "--har", zp, "--identities", clinicIDs)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "/api/owners/{ownerId}") || !strings.Contains(errs, "kept 5, matched 2") {
		t.Fatalf("stdout:\n%s\nstderr:\n%s", out, errs)
	}
}

func TestShapeOfAndGrouping(t *testing.T) {
	tests := map[string]string{
		"/a/101": "GET /a/<id>",
		"/a/123e4567-e89b-12d3-a456-426614174000": "GET /a/<id>",
		"/a/deadbeef":          "GET /a/<id>",
		"/a/deadbee":           "GET /a/deadbee",
		"/a/abcdefghij1234567": "GET /a/<id>",
		"/a/abcdefghijklmnopq": "GET /a/abcdefghijklmnopq",
		"/a/x1":                "GET /a/x1",
		"/a%0A/1":              "GET /a%0A/<id>",
		"/":                    "GET /",
	}
	for path, want := range tests {
		if got := shapeOf(&model.Exchange{Method: "get", Path: path}); got != want {
			t.Errorf("shapeOf(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestUnmatchedTruncation(t *testing.T) {
	var xs []*model.Exchange
	for i := 0; i < 23; i++ {
		xs = append(xs, &model.Exchange{Method: "GET", Path: "/seg" + string(rune('a'+i)) + "/1"})
	}
	xs = append(xs, &model.Exchange{Method: "GET", Path: "/sega/2"}) // count 2 sorts first
	var b bytes.Buffer
	writeUnmatched(&b, xs)
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 1+20+1 || lines[1] != "  2  GET /sega/<id>" || lines[len(lines)-1] != "  ... and 3 more shapes" {
		t.Fatalf("got:\n%s", b.String())
	}
}

func TestExplainCommand(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		want  int
		inOut []string
		inErr string
	}{
		{"literal beats param", []string{"explain", "--spec", vampi, "GET /users/v1/_debug"}, ExitOK,
			[]string{"segments: \"users\" \"v1\" \"_debug\"", "* GET /users/v1/_debug  literals=3  method=yes", "  GET /users/v1/{username}  literals=2  method=yes", "params: (none)", `reason: literal "_debug" beats parameter {username} at segment 3`}, ""},
		{"method miss", []string{"explain", "--spec", vampi, "PATCH /books/v1"}, ExitOK,
			[]string{"method=no", "reason: path matches but method PATCH is not defined (allowed: GET, POST)"}, ""},
		{"no match exits 0", []string{"explain", "--spec", vampi, "GET /zzz/yyy/xxx"}, ExitOK, []string{"(none)", "no template matches this path"}, ""},
		{"param binding", []string{"explain", "--spec", vampi, "GET /users/v1/alice"}, ExitOK, []string{`params: username="alice"`}, ""},
		{"base path", []string{"explain", "--spec", vampi, "--base-path", "/gw", "GET /gw/books/v1"}, ExitOK, []string{"request: GET /books/v1"}, ""},
		{"bad arg", []string{"explain", "--spec", vampi, "justone"}, ExitUsage, nil, "invalid request"},
		{"no arg", []string{"explain", "--spec", vampi}, ExitUsage, nil, "expected one argument"},
		{"two args", []string{"explain", "--spec", vampi, "GET", "/x"}, ExitUsage, nil, "expected one argument"},
		{"no leading slash", []string{"explain", "--spec", vampi, "GET x"}, ExitUsage, nil, "invalid request"},
		{"missing spec", []string{"explain", "GET /x"}, ExitUsage, nil, "missing --spec"},
		{"bad base path", []string{"explain", "--spec", vampi, "--base-path", "gw", "GET /x"}, ExitUsage, nil, "invalid --base-path"},
		{"spec error", []string{"explain", "--spec", "nope.yml", "GET /x"}, ExitInput, nil, "nope.yml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errs := runArgs(tt.args...)
			if code != tt.want {
				t.Fatalf("exit = %d, want %d; stderr=%s", code, tt.want, errs)
			}
			for _, s := range tt.inOut {
				if !strings.Contains(out, s) {
					t.Errorf("stdout missing %q:\n%s", s, out)
				}
			}
			if !strings.Contains(errs, tt.inErr) {
				t.Errorf("stderr = %q, want %q", errs, tt.inErr)
			}
		})
	}
}

func TestBasePathLineStripsControlBytes(t *testing.T) {
	specPath, _, _ := clinicFixture(t, "")
	a := hartest.Bearer(hartest.JWT(t, "alice", nil))
	pfx := "/pet%1Bclinic"
	es := []hartest.Entry{
		{Method: "GET", URL: base + pfx + "/api/owners", Status: 200, Headers: a},
		{Method: "GET", URL: base + pfx + "/api/owners/7", Status: 200, Headers: a},
	}
	harPath := hartest.WriteHAR(t, t.TempDir(), "c.har", es...)
	_, _, errs := runArgs("coverage", "--spec", specPath, "--har", harPath, "--identities", clinicIDs)
	if !strings.Contains(errs, "base path for") {
		t.Fatalf("no base path line:\n%q", errs)
	}
	for _, b := range []byte(errs) {
		if b < 0x20 && b != '\n' && b != '\t' {
			t.Fatalf("control byte %#x in stderr: %q", b, errs)
		}
	}
}

func TestHARZipBombEndToEnd(t *testing.T) {
	specPath, _, _ := clinicFixture(t, "")
	bomb := `{"log":{"entries":[],"pad":"` + strings.Repeat(" ", 200000) + `"}}`
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("bomb.har")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(bomb)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zp := filepath.Join(t.TempDir(), "bomb.har.zip")
	if err := os.WriteFile(zp, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs := runArgs("coverage", "--spec", specPath, "--har", zp, "--identities", clinicIDs)
	if code != ExitInput || !strings.Contains(errs, "decompressed size limit exceeded") {
		t.Fatalf("exit %d: %s", code, errs)
	}
}

func TestExplainLiteralBeatsParamInline(t *testing.T) {
	const spec = `openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /api/orders:
    get: {responses: {"200": {description: ok}}}
  /api/orders/{id}:
    parameters:
      - {name: id, in: path, required: true, schema: {type: string}}
    get: {responses: {"200": {description: ok}}}
    delete: {responses: {"200": {description: ok}}}
  /api/{entity}/123:
    parameters:
      - {name: entity, in: path, required: true, schema: {type: string}}
    get: {responses: {"200": {description: ok}}}
`
	sp := filepath.Join(t.TempDir(), "s.yml")
	if err := os.WriteFile(sp, []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runArgs("explain", "--spec", sp, "GET /api/orders/123")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, s := range []string{"* GET /api/orders/{id}", "  GET /api/{entity}/123", `params: id="123"`, `literal "orders" beats parameter {entity}`} {
		if !strings.Contains(out, s) {
			t.Errorf("stdout missing %q:\n%s", s, out)
		}
	}
}
