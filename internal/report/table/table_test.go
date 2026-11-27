package table

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"authzcov/internal/matrix"
	"authzcov/internal/model"
)

func ob(ep *model.Endpoint, rel model.Relationship, status int) *model.Observation {
	return &model.Observation{
		Endpoint: ep, Rel: rel, Identity: &model.Identity{Name: "u"},
		IDConf: model.ConfDeclared, OwnerConf: model.ConfDeclared,
		X: &model.Exchange{Status: status, Source: "a.har#1"},
	}
}

func render(t *testing.T, m *matrix.Matrix) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, m); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestGolden(t *testing.T) {
	ep := &model.Endpoint{ID: "GET /books/v1/{book_title}", Method: "GET", Template: "/books/v1/{book_title}", Kind: model.ObjectLevel}
	fn := &model.Endpoint{ID: "GET /users", Method: "GET", Template: "/users", Kind: model.FunctionLevel}
	m := matrix.Build([]*model.Endpoint{fn, ep}, []*model.Observation{
		ob(ep, model.RelOwner, 200),
		ob(ep, model.RelAnonymous, 401),
		ob(fn, model.RelOwner, 200),
		ob(fn, model.RelAnonymous, 200),
		ob(fn, model.RelAnonymous, 401),
	}, false)
	want := "ENDPOINT                        OWNER  SAME_ROLE  LOWER  ANON\n" +
		"GET     /books/v1/{book_title}  ok     GAP        -      ok 401\n" +
		"GET     /users                  ok     -          GAP    ok 200,401\n" +
		"\n" +
		"required 6  covered 4 (66.7%)  gaps 2\n"
	if got := render(t, m); got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestHiddenAndShownColumns(t *testing.T) {
	ep := &model.Endpoint{ID: "GET /b/{id}", Method: "GET", Template: "/b/{id}", Kind: model.ObjectLevel}
	out := render(t, matrix.Build([]*model.Endpoint{ep}, nil, false))
	if strings.Contains(out, "OTHER_TENANT") || strings.Contains(out, "LOWER") || strings.Contains(out, "HIGHER") || strings.Contains(out, "UNKNOWN") {
		t.Fatalf("hidden columns shown:\n%s", out)
	}
	out = render(t, matrix.Build([]*model.Endpoint{ep}, nil, true))
	if !strings.Contains(out, "OTHER_TENANT") {
		t.Fatalf("missing column:\n%s", out)
	}
}

func TestStatusSuffix(t *testing.T) {
	tests := []struct {
		statuses map[int]int
		want     string
	}{
		{map[int]int{200: 3, 204: 1}, "ok"},
		{map[int]int{401: 1}, "ok 401"},
		{map[int]int{401: 2, 200: 1}, "ok 200,401"},
		{map[int]int{500: 1, 200: 1, 403: 1}, "ok 200,403,500"},
	}
	for _, tc := range tests {
		c := &model.CoverageCell{Required: true, Covered: true, Statuses: tc.statuses}
		if got := cellText(c); got != tc.want {
			t.Errorf("%v: got %q want %q", tc.statuses, got, tc.want)
		}
	}
	if cellText(&model.CoverageCell{Required: true}) != "GAP" || cellText(&model.CoverageCell{Covered: true}) != "-" || cellText(nil) != "-" {
		t.Fatal("GAP / - rules")
	}
}

func TestControlCharsStripped(t *testing.T) {
	ep := &model.Endpoint{ID: "x", Method: "GET", Template: "/a\x1b[31m/b\x07", Kind: model.FunctionLevel}
	out := render(t, matrix.Build([]*model.Endpoint{ep}, nil, false))
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Fatalf("control chars leaked: %q", out)
	}
}

func TestZeroEndpoints(t *testing.T) {
	want := "ENDPOINT\n\nrequired 0  covered 0 (0.0%)  gaps 0\n"
	if got := render(t, matrix.Build(nil, nil, true)); got != want {
		t.Fatalf("got %q", got)
	}
	if got := render(t, nil); got != want {
		t.Fatalf("nil matrix: got %q", got)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestWriteError(t *testing.T) {
	ep := &model.Endpoint{ID: "x", Method: "GET", Template: "/a", Kind: model.FunctionLevel}
	if err := Render(failWriter{}, matrix.Build([]*model.Endpoint{ep}, nil, false)); err == nil {
		t.Fatal("expected error")
	}
}

func TestInferredMarker(t *testing.T) {
	ep := &model.Endpoint{ID: "GET /books/v1/{book_title}", Method: "GET", Template: "/books/v1/{book_title}", Kind: model.ObjectLevel}
	inf := ob(ep, model.RelOwner, 200)
	inf.OwnerConf = model.ConfInferred
	anon := ob(ep, model.RelAnonymous, 401)
	anon.OwnerConf = model.ConfInferred
	m := matrix.Build([]*model.Endpoint{ep}, []*model.Observation{inf, anon, ob(ep, model.RelSameRoleOtherUser, 200)}, false)
	want := "ENDPOINT                        OWNER  SAME_ROLE  ANON\n" +
		"GET     /books/v1/{book_title}  ok~    ok         ok 401\n" +
		"\n" +
		"required 3  covered 3 (100.0%)  gaps 0\n" +
		"~ covered only by inferred ownership evidence\n"
	if got := render(t, m); got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
	// No footer without an inferred cell shown.
	out := render(t, matrix.Build([]*model.Endpoint{ep}, []*model.Observation{ob(ep, model.RelOwner, 200)}, false))
	if strings.Contains(out, "~") {
		t.Fatalf("unexpected marker:\n%s", out)
	}
}

func TestSuspiciousFooter(t *testing.T) {
	ep := &model.Endpoint{ID: "GET /a/{id}", Method: "GET", Template: "/a/{id}", Kind: model.ObjectLevel}
	m := matrix.Build([]*model.Endpoint{ep}, []*model.Observation{ob(ep, model.RelOwner, 200)}, false)
	var b bytes.Buffer
	if err := RenderWith(&b, m, Options{SuspiciousAllows: 2}); err != nil {
		t.Fatal(err)
	}
	want := "! 2 suspicious allow(s): run \"authzcov report --format markdown\" for details\n"
	if !strings.HasSuffix(b.String(), "\n"+want) {
		t.Errorf("got %q", b.String())
	}
	if strings.Contains(render(t, m), "suspicious") {
		t.Error("Render must not print the footer")
	}
	b.Reset()
	_ = RenderWith(&b, m, Options{})
	if strings.Contains(b.String(), "suspicious") {
		t.Error("zero count must not print the footer")
	}
}
