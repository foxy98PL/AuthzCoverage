package basepath

import (
	"math/rand"
	"reflect"
	"testing"

	"authzcov/internal/match"
	"authzcov/internal/model"
)

func trie(t *testing.T) *match.Trie {
	t.Helper()
	tr := match.New()
	for _, r := range [][2]string{{"GET", "/api/owners"}, {"GET", "/api/owners/{ownerId}"}, {"GET", "/health"}} {
		if err := tr.Add(r[0], r[1], r[0]+" "+r[1]); err != nil {
			t.Fatal(err)
		}
	}
	return tr
}

func ex(host, path string) *model.Exchange {
	return &model.Exchange{Method: "GET", Host: host, Path: path}
}

func TestStrip(t *testing.T) {
	tests := []struct {
		path, prefix, want string
		ok                 bool
	}{
		{"/a/b", "", "/a/b", true},
		{"/a/b", "/a", "/b", true},
		{"/a/b", "/a/", "/b", true},
		{"/a", "/a", "/", true},
		{"/ab/c", "/a", "", false},
		{"/x", "/a", "", false},
		{"/a/b/c", "/a/b", "/c", true},
	}
	for _, tt := range tests {
		got, ok := Strip(tt.path, tt.prefix)
		if got != tt.want || ok != tt.ok {
			t.Errorf("Strip(%q,%q) = %q,%v want %q,%v", tt.path, tt.prefix, got, ok, tt.want, tt.ok)
		}
	}
}

func TestDetect(t *testing.T) {
	xs := []*model.Exchange{
		ex("gw:80", "/petclinic/api/owners"),
		ex("gw:80", "/petclinic/api/owners/7"),
		ex("gw:80", "/petclinic/api/owners/8"),
		ex("gw:80", "/health"),
		ex("direct:80", "/api/owners"),
		ex("direct:80", "/api/owners/1"),
		ex("other:80", "/nothing/here"),
		ex("deep:80", "/a/b/c/api/owners"),
		ex("deep:80", "/a/b/c/api/owners/2"),
		ex("tie:80", "/api/owners"),
	}
	want := []Choice{
		{"deep:80", "/a/b/c", 2, 2},
		{"direct:80", "", 2, 2},
		{"gw:80", "/petclinic", 3, 4},
		{"other:80", "", 0, 1},
		{"tie:80", "", 1, 1},
	}
	got := Detect(xs, trie(t))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	rng := rand.New(rand.NewSource(7)) //nolint:gosec // fixed seed for reproducible shuffles
	for i := 0; i < 20; i++ {
		rng.Shuffle(len(xs), func(i, j int) { xs[i], xs[j] = xs[j], xs[i] })
		if g := Detect(xs, trie(t)); !reflect.DeepEqual(g, want) {
			t.Fatalf("shuffle %d: got %+v", i, g)
		}
	}
}

func TestDetectEmptyAndTooDeep(t *testing.T) {
	if got := Detect(nil, trie(t)); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
	// five leading segments exceeds the 4-segment limit: nothing matches.
	got := Detect([]*model.Exchange{ex("h", "/a/b/c/d/e/api/owners")}, trie(t))
	if got[0].Matched != 0 || got[0].Prefix != "" {
		t.Fatalf("got %+v", got)
	}
}
