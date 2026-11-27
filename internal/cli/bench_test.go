package cli

import (
	"bytes"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authzcov/internal/testutil/hartest"
)

// End-to-end benchmark of `coverage` on a synthetic 10,000-entry HAR (KAN-73).
// The generator only runs from the benchmark and the tests below, so a plain
// `go test ./...` stays fast.

const benchEntries = 10000

var benchResources = []string{"users", "orders", "items", "invoices", "tickets", "comments", "files", "notes"}

// benchParam returns the path parameter name for a resource ("orders" -> "orderId").
func benchParam(res string) string { return strings.TrimSuffix(res, "s") + "Id" }

// benchSpec builds an OpenAPI spec with 8 resources x 5 operations plus 4
// organisation-scoped project operations (44 operations).
func benchSpec() string {
	var b strings.Builder
	b.WriteString("openapi: 3.0.3\ninfo: {title: bench, version: \"1\"}\npaths:\n")
	op := func(method string) string {
		return "    " + method + ":\n      responses: {\"200\": {description: ok}}\n"
	}
	for _, res := range benchResources {
		p := benchParam(res)
		fmt.Fprintf(&b, "  /%s:\n%s%s", res, op("get"), op("post"))
		fmt.Fprintf(&b, "  /%s/{%s}:\n    parameters: [{name: %s, in: path, required: true, schema: {type: string}}]\n%s%s%s",
			res, p, p, op("get"), op("put"), op("delete"))
	}
	b.WriteString("  /orgs/{orgId}/projects:\n    parameters: [{name: orgId, in: path, required: true, schema: {type: string}}]\n" + op("get") + op("post"))
	b.WriteString("  /orgs/{orgId}/projects/{projectId}:\n    parameters: [{name: orgId, in: path, required: true, schema: {type: string}}, {name: projectId, in: path, required: true, schema: {type: string}}]\n" + op("get") + op("delete"))
	return b.String()
}

type benchID struct{ name, role, tenant string }

var benchIdentities = []benchID{
	{"alice", "user", "acme"}, {"bob", "user", "acme"},
	{"carol", "user", "globex"}, {"dave", "user", "globex"},
	{"erin", "admin", "acme"}, {"frank", "admin", "globex"},
}

func benchIdentitiesYAML() string {
	var b strings.Builder
	b.WriteString("version: 1\nroles: {user: 10, admin: 100}\njwt: {subject: sub}\nidentities:\n")
	for _, i := range benchIdentities {
		fmt.Fprintf(&b, "  - {name: %s, role: %s, tenant: %s, match: {jwt: {sub: %s}}}\n", i.name, i.role, i.tenant, i.name)
	}
	b.WriteString("resources: {")
	for i, res := range benchResources {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s: %s", benchParam(res), res)
	}
	b.WriteString(", projectId: projects}\ntenancy:\n  tenant_params: {orgId: name}\nownership:\n  learn_from_create:\n")
	for _, res := range benchResources {
		fmt.Fprintf(&b, "    - {match: {method: POST, path: /%s}, resource: %s, id_from: {request_json: id}}\n", res, res)
	}
	b.WriteString("    - {match: {method: POST, path: \"/orgs/{orgId}/projects\"}, resource: projects, id_from: {request_json: id}}\n")
	return b.String()
}

// benchHAR builds a deterministic HAR with exactly benchEntries entries.
func benchHAR(t testing.TB) []hartest.Entry {
	t.Helper()
	const host = "http://localhost:8080"
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // deterministic fixture generator, not security
	tok := make([]string, len(benchIdentities))
	for i, id := range benchIdentities {
		tok[i] = hartest.JWT(t, id.name, nil)
	}
	auth := func(i int) map[string]string { return hartest.Bearer(tok[i]) }

	type obj struct {
		res, id string
		owner   int
	}
	var objs []obj
	es := make([]hartest.Entry, 0, benchEntries)
	create := func(owner int, res string) {
		id := fmt.Sprintf("%s-%d", res, len(objs))
		objs = append(objs, obj{res, id, owner})
		url := host + "/" + res
		if res == "projects" {
			url = host + "/orgs/" + benchIdentities[owner].tenant + "/projects"
		}
		es = append(es, hartest.Entry{Method: "POST", URL: url, Status: 201, Headers: auth(owner),
			ReqJSON: `{"id":"` + id + `","name":"n"}`, RespJSON: `{"id":"` + id + `"}`})
	}
	all := append(append([]string{}, benchResources...), "projects")
	for owner := range benchIdentities {
		for _, res := range all {
			for range 2 {
				create(owner, res)
			}
		}
	}
	path := func(o obj) string {
		if o.res == "projects" {
			return host + "/orgs/" + benchIdentities[o.owner].tenant + "/projects/" + o.id
		}
		return host + "/" + o.res + "/" + o.id
	}
	for len(es) < benchEntries {
		o := objs[rng.IntN(len(objs))]
		who := rng.IntN(len(benchIdentities))
		r := rng.IntN(100)
		switch {
		case r < 3:
			es = append(es, hartest.Entry{Method: "GET", URL: fmt.Sprintf("%s/unknown/%d/path", host, rng.IntN(1000)), Status: 404, Headers: auth(who)})
		case r < 4:
			es = append(es, hartest.Entry{Method: "GET", URL: fmt.Sprintf("%s/static/app-%d.js", host, rng.IntN(50)), Status: 200, RespMIME: "application/javascript", RespJSON: "x"})
		case r < 10:
			create(who, all[rng.IntN(len(all))])
		case r < 20:
			es = append(es, hartest.Entry{Method: "GET", URL: path(o), Status: 401})
		case r < 40: // owner reads
			es = append(es, hartest.Entry{Method: "GET", URL: path(o), Status: 200, Headers: auth(o.owner), RespJSON: `{"id":"` + o.id + `"}`})
		case r < 55: // owner writes
			m := []string{"PUT", "DELETE"}[rng.IntN(2)]
			if o.res == "projects" && m == "PUT" {
				m = "DELETE"
			}
			es = append(es, hartest.Entry{Method: m, URL: path(o), Status: 200, Headers: auth(o.owner), ReqJSON: `{"name":"x"}`})
		case r < 80: // cross-user reads, mostly denied
			st := 403
			if rng.IntN(10) == 0 {
				st = 200
			}
			es = append(es, hartest.Entry{Method: "GET", URL: path(o), Status: st, Headers: auth(who)})
		default: // lists
			res := all[rng.IntN(len(all))]
			url := host + "/" + res
			if res == "projects" {
				url = host + "/orgs/" + benchIdentities[who].tenant + "/projects"
			}
			es = append(es, hartest.Entry{Method: "GET", URL: url, Status: 200, Headers: auth(who), RespJSON: `[]`})
		}
	}
	return es[:benchEntries]
}

// writeBenchFixture writes spec.yaml, bench.har and identities.yaml into dir.
func writeBenchFixture(t testing.TB, dir string) (spec, har, ids string) {
	t.Helper()
	spec = filepath.Join(dir, "spec.yaml")
	ids = filepath.Join(dir, "identities.yaml")
	if err := os.WriteFile(spec, []byte(benchSpec()), 0o600); err != nil { //nolint:gosec // dir is a test temp dir
		t.Fatal(err)
	}
	if err := os.WriteFile(ids, []byte(benchIdentitiesYAML()), 0o600); err != nil { //nolint:gosec // dir is a test temp dir
		t.Fatal(err)
	}
	har = hartest.WriteHAR(t, dir, "bench.har", benchHAR(t)...)
	return spec, har, ids
}

func benchArgs(spec, har, ids, out string) []string {
	return []string{"coverage", "--spec", spec, "--har", har, "--identities", ids, "--out", out}
}

func BenchmarkCoverage10k(b *testing.B) {
	dir := b.TempDir()
	spec, har, ids := writeBenchFixture(b, dir)
	args := benchArgs(spec, har, ids, filepath.Join(dir, "out"))
	var errb bytes.Buffer
	if code := Execute(args, io.Discard, &errb); code != ExitOK {
		b.Fatalf("exit %d: %s", code, errb.String())
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		Execute(args, io.Discard, io.Discard)
	}
	b.ReportMetric(benchEntries, "entries/op")
}

func TestCoverage10kUnder5s(t *testing.T) {
	if os.Getenv("AUTHZCOV_BENCH") != "1" {
		t.Skip("set AUTHZCOV_BENCH=1 to run")
	}
	dir := t.TempDir()
	spec, har, ids := writeBenchFixture(t, dir)
	var errb bytes.Buffer
	start := time.Now()
	code := Execute(benchArgs(spec, har, ids, filepath.Join(dir, "out")), io.Discard, &errb)
	d := time.Since(start)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	t.Logf("coverage on %d entries took %v", benchEntries, d)
	if d >= 5*time.Second {
		t.Fatalf("took %v, want < 5s", d)
	}
}

// TestWriteBenchFixture lets scripts/bench.sh obtain the fixture for a binary run.
func TestWriteBenchFixture(t *testing.T) {
	dir := os.Getenv("AUTHZCOV_BENCH_FIXTURE_DIR")
	if dir == "" {
		t.Skip("set AUTHZCOV_BENCH_FIXTURE_DIR to write the benchmark fixture")
	}
	writeBenchFixture(t, dir)
}
