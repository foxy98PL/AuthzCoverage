package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authzcov/internal/ownership"
	"authzcov/internal/report/coveragejson"
	"authzcov/internal/testutil/hartest"
)

const (
	tenantshopSpecFx = "../../e2e/apps/tenantshop/shop/openapi.yaml"
	tenantshopIDsFx  = "../../e2e/apps/tenantshop/identities.yaml"
)

// tenantshopEntries is a small tenantshop-like recording: tokens carry org_id,
// orders are created with server-generated IDs.
func tenantshopEntries(t *testing.T) []hartest.Entry {
	t.Helper()
	tok := func(sub, org string) map[string]string {
		return hartest.Bearer(hartest.JWT(t, sub, map[string]any{"org_id": org}))
	}
	b := base + "/orgs/OrgA/orders"
	return []hartest.Entry{
		{Method: "POST", URL: b, Status: 201, Headers: tok("ann", "OrgA"), ReqJSON: `{"item":"x"}`, RespJSON: `{"id":"ord-7f3a"}`},
		{Method: "GET", URL: b + "/ord-7f3a", Status: 200, Headers: tok("ann", "OrgA")},
		{Method: "GET", URL: b + "/ord-7f3a", Status: 200, Headers: tok("adminA", "OrgA")},
		{Method: "GET", URL: b + "/ord-7f3a", Status: 403, Headers: tok("ben", "OrgB")},
		{Method: "GET", URL: b + "/ord-7f3a", Status: 401},
		{Method: "PUT", URL: b + "/ord-7f3a", Status: 200, Headers: tok("ann", "OrgA"), ReqJSON: `{"item":"y"}`},
		{Method: "GET", URL: b, Status: 200, Headers: tok("ann", "OrgA")},
		{Method: "GET", URL: base + "/orgs/OrgA/customers", Status: 200, Headers: tok("adminA", "OrgA")},
		{Method: "GET", URL: base + "/orgs/OrgA/customers", Status: 403, Headers: tok("ann", "OrgA")},
		{Method: "GET", URL: base + "/me", Status: 200, Headers: tok("amy", "OrgA")},
	}
}

type exportCase struct {
	name, spec, ids string
	es              func(*testing.T) []hartest.Entry
}

var exportCases = []exportCase{
	{"tenants-fixture", "", "", tenantsEntries},
	{"tenantshop-fixture", tenantshopSpecFx, tenantshopIDsFx, tenantshopEntries},
}

// exportRun runs coverage then export --plan in a fresh directory and returns
// the plan text, the directory and the coverage.json path.
func exportRun(t *testing.T, tc exportCase, es []hartest.Entry, extra ...string) (plan, dir string) {
	t.Helper()
	spec, ids := tc.spec, tc.ids
	if tc.name == "tenants-fixture" {
		spec, ids = writeFile(t, "tenants.yml", tenantsSpec), writeFile(t, "ids.yaml", tenantsIDs)
	}
	cov := runCoverageIn(t, spec, ids, es)
	args := append([]string{"export", "--plan", "--in", filepath.Join(cov.dir, "out", "coverage.json")}, extra...)
	code, out, errs := runCLI(t, args...)
	if code != ExitOK {
		t.Fatalf("export exit = %d; stderr=%s", code, errs)
	}
	return out, cov.dir
}

func TestGoldenPlan(t *testing.T) {
	goldenAbs, err := filepath.Abs(goldenDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range exportCases {
		t.Run(tc.name, func(t *testing.T) {
			es := tc.es(t)
			out, _ := exportRun(t, tc, es)
			checkGolden(t, filepath.Join(goldenAbs, tc.name+".plan.json"), out)
			// A reversed HAR changes only the coverage hash (har sha and evidence refs).
			rev, _ := exportRun(t, tc, reverse(es))
			if a, b := stripSource(t, out), stripSource(t, rev); a != b {
				t.Errorf("reversed HAR changes the plan:\n%s\nvs\n%s", a, b)
			}
		})
	}
}

func stripSource(t *testing.T, plan string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(plan), &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "source")
	b, _ := json.Marshal(m)
	return string(b)
}

type probeDoc struct {
	ContainsRaw bool `json:"contains_raw_ids"`
	Probes      []struct {
		Endpoint, Relationship, Expect, Note string
		Waived                               bool
		Attacker                             *struct{ Identity, Role, Tenant string }
		Object                               *struct{ Resource, Param, ID, Owner, Tenant string }
		PathParams                           map[string]string `json:"path_params"`
	}
}

func parsePlan(t *testing.T, s string) probeDoc {
	t.Helper()
	var d probeDoc
	dec := json.NewDecoder(strings.NewReader(s))
	if err := dec.Decode(&d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestPlanTenantshopProbes(t *testing.T) {
	out, _ := exportRun(t, exportCases[1], tenantshopEntries(t))
	d := parsePlan(t, out)
	if d.ContainsRaw {
		t.Error("contains_raw_ids must be false without --har")
	}
	found := map[string]bool{}
	for _, p := range d.Probes {
		found[p.Endpoint+"|"+p.Relationship] = true
		if p.Object != nil && p.Object.ID != "" {
			t.Errorf("raw id without --har: %+v", p)
		}
		if p.Endpoint == "GET /orgs/{orgId}/orders/{orderId}" && p.Relationship == "other_tenant" {
			t.Errorf("covered cell exported: %+v", p)
		}
		if p.Endpoint == "PUT /orgs/{orgId}/orders/{orderId}" {
			switch p.Relationship {
			case "other_tenant":
				if p.Attacker == nil || p.Attacker.Tenant == "OrgA" || p.Expect != "deny" || p.Object.Owner != "ann" || p.Object.Tenant != "OrgA" {
					t.Errorf("other_tenant probe: %+v attacker=%+v obj=%+v", p, p.Attacker, p.Object)
				}
			case "same_role_other_user":
				if p.Attacker == nil || p.Attacker.Role != "customer" || p.Attacker.Identity == "ann" || p.Attacker.Tenant != "OrgA" {
					t.Errorf("same_role_other_user attacker: %+v", p.Attacker)
				}
			case "lower_role":
				// ann (customer) owns the object and no identity ranks below customer.
				if p.Attacker != nil || p.Note == "" {
					t.Errorf("lower_role: want null attacker with note, got %+v", p)
				}
			case "anonymous":
				if p.Attacker == nil || p.Attacker.Identity != "anonymous" {
					t.Errorf("anonymous attacker: %+v", p.Attacker)
				}
			}
		}
	}
	if !found["PUT /orgs/{orgId}/orders/{orderId}|other_tenant"] {
		t.Errorf("expected PUT other_tenant gap; got %v", found)
	}
}

func TestPlanNoCredentials(t *testing.T) {
	es := tenantshopEntries(t)
	// Credential carriers other than Authorization: cookie, API-key header, query token.
	const cookieVal, apiKeyVal, queryVal = "sessid-4c1e9d7a2b", "apikey-91f3b6e0aa", "qtok-5d2f8c3e71" //nolint:gosec // synthetic test values
	es = append(es,
		hartest.Entry{Method: "GET", URL: base + "/me", Status: 200, Headers: map[string]string{"Cookie": "session=" + cookieVal}},
		hartest.Entry{Method: "GET", URL: base + "/me", Status: 200, Headers: map[string]string{"X-API-Key": apiKeyVal}},
		hartest.Entry{Method: "GET", URL: base + "/me?access_token=" + queryVal, Status: 200},
	)
	cov := runCoverageIn(t, tenantshopSpecFx, tenantshopIDsFx, es)
	covPath := filepath.Join(cov.dir, "out", "coverage.json")
	var rep coveragejson.Report
	if err := json.Unmarshal([]byte(cov.json), &rep); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{
		nil, {"--include", "waived"},
		{"--har", "t.har", "--spec", "spec.yml", "--identities", "ids.yaml", "--out", "raw-nocred.json"},
	} {
		code, out, errs := runCLI(t, append([]string{"export", "--plan", "--in", covPath}, extra...)...)
		if code != ExitOK {
			t.Fatalf("exit %d: %s", code, errs)
		}
		if out == "" {
			b, err := os.ReadFile(filepath.Join(cov.dir, "raw-nocred.json")) //nolint:gosec // test path
			if err != nil {
				t.Fatal(err)
			}
			out = string(b)
		}
		var secrets []string
		for _, e := range es {
			if a := e.Headers["Authorization"]; a != "" {
				secrets = append(secrets, strings.TrimPrefix(a, "Bearer "), a)
			}
		}
		for _, id := range rep.Identities {
			secrets = append(secrets, id.Fingerprints...)
		}
		secrets = append(secrets, cookieVal, apiKeyVal, queryVal, "access_token", "X-API-Key", "Cookie", "Bearer ", "eyJ", "Authorization", "fingerprint", "password")
		for _, s := range secrets {
			if s != "" && strings.Contains(out, s) {
				t.Errorf("plan (%v) contains credential material %q", extra, s)
			}
		}
	}
}

func TestPlanRawIDsOnlyWithHAR(t *testing.T) {
	es := tenantshopEntries(t)
	cov := runCoverageIn(t, tenantshopSpecFx, tenantshopIDsFx, es)
	covPath := filepath.Join(cov.dir, "out", "coverage.json")

	// Without --har: no raw id, flag false, readable file.
	plain := filepath.Join(cov.dir, "plain.json")
	if code, _, errs := runCLI(t, "export", "--plan", "--in", covPath, "--out", plain); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	b, _ := os.ReadFile(plain) //nolint:gosec // test path
	if d := parsePlan(t, string(b)); d.ContainsRaw || strings.Contains(string(b), `"id": "`+"ord-7f3a") {
		t.Errorf("plain plan has raw ids: %s", b)
	}
	if st, _ := os.Stat(plain); st.Mode().Perm() != 0o644 {
		t.Errorf("plain plan mode = %v", st.Mode().Perm())
	}

	// With --har: raw ids, flag true, 0600, warning on stderr.
	raw := filepath.Join(cov.dir, "raw.json")
	code, _, errs := runCLI(t, "export", "--plan", "--in", covPath, "--out", raw,
		"--har", "t.har", "--spec", "spec.yml", "--identities", "ids.yaml")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(errs, "raw object IDs") {
		t.Errorf("no raw-id warning on stderr: %s", errs)
	}
	st, err := os.Stat(raw)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("raw plan mode = %v, want 0600", st.Mode().Perm())
	}
	b, _ = os.ReadFile(raw) //nolint:gosec // test path
	d := parsePlan(t, string(b))
	if !d.ContainsRaw {
		t.Error("contains_raw_ids must be true with --har")
	}
	withID := 0
	for _, p := range d.Probes {
		if p.Object != nil && p.Object.ID != "" {
			withID++
			if p.Object.ID != "ord-7f3a" || p.PathParams["orgId"] != "OrgA" {
				t.Errorf("bad raw probe: %+v %+v", p.Object, p.PathParams)
			}
		}
	}
	if withID == 0 {
		t.Errorf("no probe got a raw id:\n%s", b)
	}

	// An existing, wider file is replaced by a 0600 one (atomic write).
	if err := os.WriteFile(raw, []byte("x"), 0o644); err != nil { //nolint:gosec // test
		t.Fatal(err)
	}
	if code, _, errs := runCLI(t, "export", "--plan", "--in", covPath, "--out", raw,
		"--har", "t.har", "--spec", "spec.yml", "--identities", "ids.yaml"); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if st, _ := os.Stat(raw); st.Mode().Perm() != 0o600 {
		t.Errorf("overwritten raw plan mode = %v", st.Mode().Perm())
	}
}

func TestPlanWaivers(t *testing.T) {
	es := tenantshopEntries(t)
	dir := t.TempDir()
	wf := filepath.Join(dir, "waivers.yaml")
	exp := time.Now().AddDate(0, 0, 30).Format("2006-01-02")
	if err := os.WriteFile(wf, []byte(`schema: authzcov.waivers/v1
waivers:
  - {endpoint: "PUT /orgs/{orgId}/orders/{orderId}", relationship: other_tenant, reason: "covered by the contract test suite", expires: "`+exp+`"}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOURCE_DATE_EPOCH", fixedEpoch)
	cov := runCoverageIn(t, tenantshopSpecFx, tenantshopIDsFx, es, "--waivers", wf)
	covPath := filepath.Join(cov.dir, "out", "coverage.json")
	has := func(out string) (present, waived bool) {
		for _, p := range parsePlan(t, out).Probes {
			if p.Endpoint == "PUT /orgs/{orgId}/orders/{orderId}" && p.Relationship == "other_tenant" {
				return true, p.Waived
			}
		}
		return false, false
	}
	_, out, _ := runCLI(t, "export", "--plan", "--in", covPath)
	if present, _ := has(out); present {
		t.Error("waived gap exported by default")
	}
	_, out, _ = runCLI(t, "export", "--plan", "--in", covPath, "--include", "waived")
	if present, waived := has(out); !present || !waived {
		t.Errorf("--include waived: present=%v waived=%v", present, waived)
	}
}

func TestExportUsageErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no plan":       {[]string{"export", "--in", "x"}, "missing --plan"},
		"no in":         {[]string{"export", "--plan"}, "missing --in"},
		"bad include":   {[]string{"export", "--plan", "--in", "x", "--include", "all"}, "invalid --include"},
		"raw no out":    {[]string{"export", "--plan", "--in", "x", "--har", "a.har", "--spec", "s.yml", "--identities", "i.yaml"}, "only written to a 0600 file: pass --out"},
		"bad base path": {[]string{"export", "--plan", "--in", "x", "--har", "a.har", "--spec", "s.yml", "--identities", "i.yaml", "--out", "o", "--base-path", "api"}, "invalid --base-path"},
		"har alone":     {[]string{"export", "--plan", "--in", "x", "--har", "a.har"}, "--har needs --spec and --identities"},
		"spec no har":   {[]string{"export", "--plan", "--in", "x", "--spec", "s.yml"}, "only used together with --har"},
		"missing input": {[]string{"export", "--plan", "--in", filepath.Join(t.TempDir(), "nope.json")}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := Execute(tc.args, &out, &errb)
			want := ExitUsage
			if name == "missing input" {
				want = ExitInput
			}
			if code != want || !strings.Contains(errb.String(), tc.want) {
				t.Errorf("exit %d, stderr %q", code, errb.String())
			}
		})
	}
}

func TestExportRawStdoutRefused(t *testing.T) {
	cov := runCoverageIn(t, tenantshopSpecFx, tenantshopIDsFx, tenantshopEntries(t))
	covPath := filepath.Join(cov.dir, "out", "coverage.json")
	code, out, errs := runCLI(t, "export", "--plan", "--in", covPath,
		"--har", "t.har", "--spec", "spec.yml", "--identities", "ids.yaml")
	if code != ExitUsage || out != "" || !strings.Contains(errs, "0600") {
		t.Errorf("exit %d stdout %q stderr %q", code, out, errs)
	}
}

func TestExportRawHARMismatchWarning(t *testing.T) {
	cov := runCoverageIn(t, tenantshopSpecFx, tenantshopIDsFx, tenantshopEntries(t))
	covPath := filepath.Join(cov.dir, "out", "coverage.json")
	args := []string{"export", "--plan", "--in", covPath, "--har", "t.har", "--spec", "spec.yml", "--identities", "ids.yaml"}

	_, _, errs := runCLI(t, append(args, "--out", "ok.json")...)
	if strings.Contains(errs, "--har files differ") {
		t.Errorf("unexpected HAR warning for the original file: %s", errs)
	}
	// Same entries plus one extra request: a different file, same pipeline inputs.
	es := append(tenantshopEntries(t), hartest.Entry{Method: "GET", URL: base + "/me", Status: 200})
	hartest.WriteHAR(t, cov.dir, "t.har", es...)
	code, _, errs := runCLI(t, append(args, "--out", "changed.json")...)
	if code != ExitOK || !strings.Contains(errs, "--har files differ") {
		t.Errorf("exit %d, want HAR mismatch warning: %s", code, errs)
	}
}

func TestExportBasePathMirrorsCoverage(t *testing.T) {
	es := tenantshopEntries(t)
	for i := range es { // everything lives under a /api prefix
		es[i].URL = strings.Replace(es[i].URL, base, base+"/api", 1)
	}
	cov := runCoverageIn(t, tenantshopSpecFx, tenantshopIDsFx, es, "--base-path", "/api")
	covPath := filepath.Join(cov.dir, "out", "coverage.json")
	raw := []string{"--har", "t.har", "--spec", "spec.yml", "--identities", "ids.yaml"}

	// Default (auto) must still work; an explicit wrong prefix must fail like coverage does.
	if code, _, errs := runCLI(t, append([]string{"export", "--plan", "--in", covPath, "--out", "a.json"}, raw...)...); code != ExitOK {
		t.Fatalf("auto: exit %d: %s", code, errs)
	}
	if code, _, errs := runCLI(t, append([]string{"export", "--plan", "--in", covPath, "--out", "b.json", "--base-path", "/api"}, raw...)...); code != ExitOK {
		t.Fatalf("/api: exit %d: %s", code, errs)
	}
	code, _, errs := runCLI(t, append([]string{"export", "--plan", "--in", covPath, "--out", "c.json", "--base-path", "/nope"}, raw...)...)
	if code == ExitOK {
		t.Errorf("--base-path /nope should fail like coverage: %s", errs)
	}
}

func rawArgs() []string {
	return []string{"--har", "t.har", "--spec", "spec.yml", "--identities", "ids.yaml"}
}

func TestExportPlan_HashOnly_HintOnStderrOnce(t *testing.T) {
	cov := runCoverageIn(t, tenantshopSpecFx, tenantshopIDsFx, tenantshopEntries(t))
	code, out, errs := runCLI(t, "export", "--plan", "--in", filepath.Join(cov.dir, "out", "coverage.json"))
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if n := strings.Count(errs, "raw ID omitted"); n != 1 {
		t.Errorf("hint on stderr %d times: %s", n, errs)
	}
	if !strings.Contains(out, "raw ID omitted") {
		t.Errorf("no hint note in plan")
	}
}

func TestExportPlan_Raw_RequiresOut_NoStdout(t *testing.T) {
	cov := runCoverageIn(t, tenantshopSpecFx, tenantshopIDsFx, tenantshopEntries(t))
	args := append([]string{"export", "--plan", "--in", filepath.Join(cov.dir, "out", "coverage.json")}, rawArgs()...)
	code, out, _ := runCLI(t, args...)
	if code != ExitUsage || strings.Contains(out, "ord-7f3a") {
		t.Errorf("exit %d, stdout=%s", code, out)
	}
}

func TestExportPlan_Raw_FileMode0600(t *testing.T) {
	cov := runCoverageIn(t, tenantshopSpecFx, tenantshopIDsFx, tenantshopEntries(t))
	o := filepath.Join(cov.dir, "r.json")
	args := append([]string{"export", "--plan", "--in", filepath.Join(cov.dir, "out", "coverage.json"), "--out", o}, rawArgs()...)
	if code, _, errs := runCLI(t, args...); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if st, err := os.Stat(o); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("stat %v err %v", st, err)
	}
}

func TestExportPlan_Raw_ContainsRawIDsTrue(t *testing.T) {
	cov := runCoverageIn(t, tenantshopSpecFx, tenantshopIDsFx, tenantshopEntries(t))
	o := filepath.Join(cov.dir, "r.json")
	args := append([]string{"export", "--plan", "--in", filepath.Join(cov.dir, "out", "coverage.json"), "--out", o}, rawArgs()...)
	if code, _, errs := runCLI(t, args...); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	b, _ := os.ReadFile(o) //nolint:gosec // test path
	if !parsePlan(t, string(b)).ContainsRaw || !strings.Contains(string(b), "ord-7f3a") {
		t.Errorf("raw plan: %s", b)
	}
}

func TestExportPlan_HashOnly_ContainsRawIDsFalse(t *testing.T) {
	cov := runCoverageIn(t, tenantshopSpecFx, tenantshopIDsFx, tenantshopEntries(t))
	code, out, errs := runCLI(t, "export", "--plan", "--in", filepath.Join(cov.dir, "out", "coverage.json"))
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if parsePlan(t, out).ContainsRaw {
		t.Errorf("hash-only plan claims raw IDs: %s", out)
	}
	for _, id := range harRawIDs(t) {
		if strings.Contains(out, id) || strings.Contains(errs, id) {
			t.Errorf("hash-only plan output contains raw ID %q", id)
		}
	}
}

// harRawIDs returns every raw object ID the pipeline learns from the fixture
// HAR in the current directory (the same source as rawFromPipeline).
func harRawIDs(t *testing.T) []string {
	t.Helper()
	a, err := analyze(&coverageOpts{spec: "spec.yml", hars: []string{"t.har"}, identities: "ids.yaml", basePath: basePathAuto}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, ob := range a.objects {
		if ob.Resource != ownership.SubjectResource {
			ids = append(ids, ob.ID)
		}
	}
	if len(ids) == 0 {
		t.Fatal("fixture HAR yields no raw IDs")
	}
	return ids
}

func TestCoverageJSON_NeverContainsRawObjectID(t *testing.T) {
	cov := runCoverageIn(t, tenantshopSpecFx, tenantshopIDsFx, tenantshopEntries(t))
	b, err := os.ReadFile(filepath.Join(cov.dir, "out", "coverage.json")) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range harRawIDs(t) {
		if strings.Contains(string(b), id) {
			t.Errorf("coverage.json contains raw object ID %q", id)
		}
	}
}
