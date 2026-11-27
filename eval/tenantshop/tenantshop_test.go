package tenantshop

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authzcoveval/harness"
	"authzcoveval/result"

	"tenantshop/record"
)

var env *Env

func TestMain(m *testing.M) {
	os.Setenv("SOURCE_DATE_EPOCH", "0")
	code := func() int {
		root, err := harness.RepoRoot()
		if err != nil {
			println(err.Error())
			return 1
		}
		tmp, err := os.MkdirTemp("", "tenantshoptest-")
		if err != nil {
			println(err.Error())
			return 1
		}
		defer os.RemoveAll(tmp)
		env, err = NewEnv(root, tmp, nil)
		if err != nil {
			println(err.Error())
			return 1
		}
		return m.Run()
	}()
	os.Exit(code)
}

// Every required object-level cell except owner (the owner session covers those) has exactly one
// attacker step. Exempt: same_role_other_user on tenant-scoped endpoints (resource "orgs"): the
// object is a tenant, which has no owner to be "same role as".
func TestFullScriptCoversRequiredCells(t *testing.T) {
	cov, err := env.Record("fixed", record.FullScript())
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, s := range record.FullScript() {
		if s.Cell != "" {
			have[s.Cell] = true
		}
	}
	kind := map[string]harness.Endpoint{}
	for _, e := range cov.Endpoints {
		kind[e.ID] = e
	}
	used := map[string]bool{}
	for _, c := range cov.Cells {
		k := c.Endpoint + "|" + c.Relationship
		e := kind[c.Endpoint]
		if !c.Required || e.Kind != "object" || c.Relationship == "owner" {
			continue
		}
		if c.Relationship == "same_role_other_user" && e.Resource == "orgs" {
			continue
		}
		used[k] = true
		if !have[k] {
			t.Errorf("required cell %s has no attacker step", k)
		}
		if len(c.Statuses) == 0 {
			t.Errorf("required cell %s was not observed", k)
		}
	}
	for c := range have {
		if !used[c] {
			t.Errorf("attacker step %s matches no required cell", c)
		}
	}
}

func TestMutants(t *testing.T) {
	res, err := env.Mutants()
	if err != nil {
		t.Fatal(err)
	}
	if err := result.Validate(res); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range res.Cases {
		got[c.ID] = c.Result
	}
	for id, want := range map[string]string{"fixed/no-alarm": "tn", "seeded/get-tenant": "tp", "mutant/get-tenant": "tp",
		"mutant/delete-owner": "tp", "mutant/customers-tenant": "tp"} {
		if got[id] != want {
			t.Errorf("%s = %q, want %q", id, got[id], want)
		}
	}
	if res.Summary.FP != 0 {
		t.Errorf("false alarms: %+v", res.Summary)
	}
}

func TestAblationIsolatesOneCell(t *testing.T) {
	res, err := env.Ablation()
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.FN != 0 || res.Summary.FP != 0 || res.Summary.TP < 12 {
		t.Errorf("ablation not clean: %+v", res.Summary)
	}
	for _, c := range res.Cases {
		if c.Result == result.TP && (len(c.Flagged) != 1 || len(c.Expected) != 1 || c.Flagged[0] != c.Expected[0]) {
			t.Errorf("%s: %+v", c.ID, c)
		}
	}
}

func TestResultsDeterministic(t *testing.T) {
	var files [2][2][]byte
	for i := range files {
		for j, run := range []func() (*result.Result, error){env.Mutants, env.Ablation} {
			r, err := run()
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(t.TempDir(), "r.json")
			if err := result.Write(p, r); err != nil {
				t.Fatal(err)
			}
			files[i][j], _ = os.ReadFile(p)
			if bytes.Contains(files[i][j], []byte("Bearer ")) || strings.Contains(string(files[i][j]), "eyJ") {
				t.Error("result file contains a token")
			}
		}
	}
	if !bytes.Equal(files[0][0], files[1][0]) || !bytes.Equal(files[0][1], files[1][1]) {
		t.Error("two runs differ")
	}
}
