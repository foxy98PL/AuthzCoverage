//go:build e2e

package main_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"tenantshop/record"
	"tenantshop/shop"
)

var update = flag.Bool("update", false, "rewrite the golden file")

const harBase = "http://tenantshop.test"

func runAuthzcov(t *testing.T, bin, har, out string) string {
	t.Helper()
	cmd := exec.Command(bin, "coverage", "--spec", "shop/openapi.yaml", "--identities", "identities.yaml", "--out", out, "--har", har)
	cmd.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("authzcov: %v\n%s", err, stderr.String())
	}
	return stdout.String()
}

func TestTenantshopEndToEnd(t *testing.T) {
	tmp := t.TempDir()
	srv := httptest.NewServer(shop.NewServer())
	defer srv.Close()
	har, err := record.RecordAs(srv.URL, harBase, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(har, []byte(srv.URL)) {
		t.Fatal("HAR leaks the test server address")
	}
	harPath := filepath.Join(tmp, "tenantshop.har")
	if err := os.WriteFile(harPath, har, 0o600); err != nil {
		t.Fatal(err)
	}

	// AC2: every bearer token carries an org_id claim.
	var doc struct {
		Log struct {
			Entries []struct {
				Request struct {
					Headers []struct{ Name, Value string }
				}
			}
		}
	}
	if err := json.Unmarshal(har, &doc); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range doc.Log.Entries {
		for _, h := range e.Request.Headers {
			tok, ok := strings.CutPrefix(h.Value, "Bearer ")
			if h.Name != "Authorization" || !ok {
				continue
			}
			raw, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
			if err != nil {
				t.Fatal(err)
			}
			var c map[string]any
			if err := json.Unmarshal(raw, &c); err != nil || c["org_id"] == nil {
				t.Fatalf("token without org_id claim: %s", raw)
			}
			seen++
		}
	}
	if seen == 0 {
		t.Fatal("no Authorization headers in the HAR")
	}

	bin := filepath.Join(tmp, "authzcov")
	build := exec.Command("go", "build", "-o", bin, "./cmd/authzcov")
	build.Dir = "../../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build authzcov: %v\n%s", err, out)
	}

	out := filepath.Join(tmp, "out")
	stdout := runAuthzcov(t, bin, harPath, out)
	if !strings.Contains(stdout, "OTHER_TENANT") {
		t.Errorf("table has no OTHER_TENANT column:\n%s", stdout)
	}
	golden := filepath.Join("testdata", "golden", "tenantshop.txt")
	if *update {
		if err := os.WriteFile(golden, []byte(stdout), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != string(want) {
		t.Errorf("stdout differs from %s (run with -update)\n--- got\n%s--- want\n%s", golden, stdout, want)
	}

	// Findings: only the seeded bug fires.
	raw, err := os.ReadFile(filepath.Join(out, "coverage.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Findings []struct{ Kind, Endpoint, Relationship, Message string }
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range rep.Findings {
		if f.Kind != "suspicious_allow" {
			continue
		}
		if f.Endpoint != "GET /orgs/{orgId}/orders/{orderId}" || f.Relationship != "other_tenant" {
			t.Errorf("unexpected suspicious_allow: %+v", f)
			continue
		}
		found = true
	}
	if !found {
		t.Errorf("seeded bug not reported as suspicious_allow/other_tenant:\n%s", raw)
	}

	// Determinism.
	if again := runAuthzcov(t, bin, harPath, filepath.Join(tmp, "out2")); again != stdout {
		t.Errorf("second run differs:\n%s\nvs\n%s", again, stdout)
	}
	// Recording twice against fresh servers gives identical bytes.
	srv2 := httptest.NewServer(shop.NewServer())
	defer srv2.Close()
	har2, err := record.RecordAs(srv2.URL, harBase, srv2.Client())
	if err != nil || !bytes.Equal(har, har2) {
		t.Errorf("recording is not deterministic (err %v)", err)
	}
}
