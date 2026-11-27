package sarif

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"authzcov/internal/report/coveragejson"
)

func sample() *coveragejson.Report {
	return &coveragejson.Report{
		Tool:   coveragejson.Tool{Name: "authzcov", Version: "1.2.3"},
		Inputs: coveragejson.Inputs{Spec: coveragejson.FileRef{Path: "api/openapi.yaml"}},
		Endpoints: []coveragejson.Endpoint{
			{ID: "GET /books/{id}", SpecFile: "api/openapi.yaml", SpecLine: 142},
			{ID: "GET /noline", SpecFile: "api/openapi.yaml", SpecLine: 0},
		},
		Findings: []coveragejson.Finding{
			{Fingerprint: "aaaa", Kind: "gap", Severity: "error", Endpoint: "GET /books/{id}", Relationship: "other_user", Message: "gap"},
			{Fingerprint: "bbbb", Kind: "unmatched_request", Severity: "note", Endpoint: "GET /zzz", Message: "3 requests"},
			{Fingerprint: "cccc", Kind: "ambiguous_match", Severity: "weird", Endpoint: "GET /noline", Message: "amb"},
		},
	}
}

func render(t *testing.T, r *coveragejson.Report) (string, map[string]any) {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, r); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	return b.String(), m
}

func firstRun(m map[string]any) map[string]any {
	return m["runs"].([]any)[0].(map[string]any)
}

func TestStructure(t *testing.T) {
	out, m := render(t, sample())
	if m["$schema"] != schemaURL || m["version"] != "2.1.0" {
		t.Fatalf("bad header: %v %v", m["$schema"], m["version"])
	}
	if len(m["runs"].([]any)) != 1 {
		t.Fatal("want one run")
	}
	if !strings.HasSuffix(out, "}\n") {
		t.Error("missing trailing newline")
	}
	run := firstRun(m)
	drv := run["tool"].(map[string]any)["driver"].(map[string]any)
	if drv["name"] != "authzcov" || drv["semanticVersion"] != "1.2.3" {
		t.Errorf("driver = %v", drv)
	}
	rs := drv["rules"].([]any)
	if len(rs) != 5 {
		t.Fatalf("rules = %d", len(rs))
	}
	if run["automationDetails"].(map[string]any)["id"] != "authzcov/" {
		t.Error("automationDetails.id")
	}
	if _, ok := run["originalUriBaseIds"]; ok {
		t.Error("originalUriBaseIds must be omitted")
	}
	gap := rs[0].(map[string]any)
	if gap["properties"].(map[string]any)["security-severity"] != "7.5" {
		t.Error("gap security-severity")
	}
	for _, x := range run["results"].([]any) {
		res := x.(map[string]any)
		idx := int(res["ruleIndex"].(float64))
		if rs[idx].(map[string]any)["id"] != res["ruleId"] {
			t.Errorf("ruleIndex mismatch: %v", res)
		}
		switch res["level"] {
		case "error", "warning", "note":
		default:
			t.Errorf("level %v", res["level"])
		}
		if res["partialFingerprints"].(map[string]any)["authzcovFinding/v1"] == "" {
			t.Error("fingerprint")
		}
		pl := res["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
		if pl["artifactLocation"].(map[string]any)["uri"] == "" || pl["region"].(map[string]any)["startLine"].(float64) < 1 {
			t.Errorf("location %v", pl)
		}
	}
}

func TestLocations(t *testing.T) {
	_, m := render(t, sample())
	res := firstRun(m)["results"].([]any)
	loc := func(i int) (string, float64) {
		pl := res[i].(map[string]any)["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
		return pl["artifactLocation"].(map[string]any)["uri"].(string), pl["region"].(map[string]any)["startLine"].(float64)
	}
	if u, l := loc(0); u != "api/openapi.yaml" || l != 142 {
		t.Errorf("gap = %s:%v", u, l)
	}
	if u, l := loc(1); u != "api/openapi.yaml" || l != 1 {
		t.Errorf("unmatched = %s:%v", u, l)
	}
	if _, l := loc(2); l != 1 {
		t.Errorf("line 0 must become 1, got %v", l)
	}
	if res[2].(map[string]any)["level"] != "note" {
		t.Error("unknown severity must be note")
	}
}

func TestDeterministicFingerprints(t *testing.T) {
	a, _ := render(t, sample())
	b, _ := render(t, sample())
	if a != b {
		t.Error("two renders differ")
	}
	_, m := render(t, sample())
	fp := firstRun(m)["results"].([]any)[0].(map[string]any)["partialFingerprints"].(map[string]any)
	if fp["authzcovFinding/v1"] != "aaaa" {
		t.Errorf("fingerprint = %v", fp)
	}
}

func TestPlainText(t *testing.T) {
	r := sample()
	r.Findings[0].Message = "a\x1b[31mred\x1b[0m\nline\u202eevil\u200b\u0085end"
	out, _ := render(t, r)
	for _, bad := range []string{"\x1b", "\\n", "\u202e", "\u200b", "\u0085", "\\u202e", "\\u001b"} {
		if strings.Contains(out, bad) {
			t.Errorf("output contains %q", bad)
		}
	}
	if strings.Contains(out, "markdown") {
		t.Error("output mentions markdown")
	}
	if !strings.Contains(out, "a[31mred[0m lineevilend") {
		t.Errorf("unexpected message in %s", out)
	}
}

func TestMessageCap(t *testing.T) {
	r := sample()
	r.Findings[0].Message = strings.Repeat("é", 2000)
	_, m := render(t, r)
	msg := firstRun(m)["results"].([]any)[0].(map[string]any)["message"].(map[string]any)["text"].(string)
	if n := len([]rune(msg)); n != 1000 || !strings.HasSuffix(msg, "...") {
		t.Errorf("len=%d", n)
	}
}

func TestEmptyReport(t *testing.T) {
	out, m := render(t, &coveragejson.Report{})
	if !strings.Contains(out, `"results": []`) {
		t.Errorf("results not an empty array:\n%s", out)
	}
	if len(firstRun(m)["results"].([]any)) != 0 {
		t.Error("want no results")
	}
}

func TestNonSemverVersion(t *testing.T) {
	r := sample()
	r.Tool.Version = "dev"
	_, m := render(t, r)
	drv := firstRun(m)["tool"].(map[string]any)["driver"].(map[string]any)
	if _, ok := drv["semanticVersion"]; ok || drv["version"] != "dev" {
		t.Errorf("driver = %v", drv)
	}
}

func results(m map[string]any) []any { return firstRun(m)["results"].([]any) }

func uriOf(res any) string {
	loc := res.(map[string]any)["locations"].([]any)[0].(map[string]any)
	return loc["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"].(string)
}

// Review KAN-23 F1: never emit absolute, external or climbing paths.
func TestRepoURI(t *testing.T) {
	cases := map[string]string{ //nolint:gosec // spec paths, not credentials
		"api/openapi.yaml":                 "api/openapi.yaml",
		"./api/openapi.yaml":               "api/openapi.yaml",
		`api\openapi.yaml`:                 "api/openapi.yaml",
		"/home/u/api/openapi.yaml":         "openapi.yaml",
		"https://example.com/openapi.yaml": "openapi.yaml",
		"../secret/openapi.yaml":           "openapi.yaml",
		`C:\repo\api\openapi.yaml`:         "openapi.yaml",
		"":                                 fallbackURI,
		"/":                                fallbackURI,
	}
	for in, want := range cases {
		if got := repoURI(in); got != want {
			t.Errorf("repoURI(%q) = %q, want %q", in, got, want)
		}
	}
	r := sample()
	r.Endpoints[0].SpecFile = "/home/someone/src/api/openapi.yaml"
	out, m := render(t, r)
	if strings.Contains(out, "/home/") || strings.Contains(out, "someone") {
		t.Errorf("absolute path leaked")
	}
	if got := uriOf(results(m)[0]); got != "openapi.yaml" {
		t.Errorf("uri = %q", got)
	}
}

// Review KAN-23 F2 and F4: every finding yields one result; every kind has its rule.
func TestEveryKindAndUnknownKind(t *testing.T) {
	r := sample()
	r.Findings = append(r.Findings,
		coveragejson.Finding{Fingerprint: "dddd", Kind: "suspicious_allow", Severity: "warning", Endpoint: "GET /books/{id}", Relationship: "same_role_other_user", Message: "s"},
		coveragejson.Finding{Fingerprint: "eeee", Kind: "undocumented_method", Severity: "note", Endpoint: "PATCH /books/<id>", Message: "u"},
		coveragejson.Finding{Fingerprint: "ffff", Kind: "future_kind", Severity: "note", Endpoint: "GET /x", Message: "f"},
	)
	_, m := render(t, r)
	res := results(m)
	if len(res) != len(r.Findings) {
		t.Fatalf("%d results for %d findings", len(res), len(r.Findings))
	}
	rules := firstRun(m)["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	want := map[string]string{"gap": "authzcov/gap", "unmatched_request": "authzcov/unmatched_request",
		"ambiguous_match": "authzcov/ambiguous_match", "suspicious_allow": "authzcov/suspicious_allow",
		"undocumented_method": "authzcov/undocumented_method", "future_kind": "authzcov/other"}
	for i, x := range res {
		rm := x.(map[string]any)
		idx := int(rm["ruleIndex"].(float64))
		id := rules[idx].(map[string]any)["id"].(string)
		if rm["ruleId"] != id || id != want[r.Findings[i].Kind] {
			t.Errorf("finding %s: ruleId %v, rule[%d] %s", r.Findings[i].Kind, rm["ruleId"], idx, id)
		}
	}
	// Without unknown kinds the rule table stays fixed.
	_, m2 := render(t, sample())
	if n := len(firstRun(m2)["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)); n != 5 {
		t.Errorf("rules = %d", n)
	}
}

// Review KAN-23 F5: line/paragraph separators, private use and the version are sanitised.
func TestPlainTextExtra(t *testing.T) {
	r := sample()
	r.Tool.Version = "1.0\u202e\n"
	r.Findings[0].Message = "a\u2028b\u2029c\ue000d"
	out, _ := render(t, r)
	for _, bad := range []string{"\u2028", "\u2029", "\ue000", "\u202e", `\u2028`, `\u2029`} {
		if strings.Contains(out, bad) {
			t.Errorf("output contains %q", bad)
		}
	}
	if !strings.Contains(out, `"a b c d"`) && !strings.Contains(out, `"a b cd"`) {
		t.Errorf("message not sanitised as expected")
	}
}

// Review KAN-23 F3 and F6: fingerprints are a pinned pure function of the
// finding, so separate runs agree; an empty one is recomputed.
func TestFingerprintPinnedAndFilled(t *testing.T) {
	// First 16 hex of SHA-256("gap|GET /books/{id}|owner"), computed outside Go (DOC-04 formula).
	if got := coveragejson.Fingerprint("gap", "GET /books/{id}", "owner"); got != "c87841156ee7b55f" {
		t.Fatalf("fingerprint %q", got)
	}
	r := sample()
	r.Findings[0].Fingerprint = ""
	_, m := render(t, r)
	pf := results(m)[0].(map[string]any)["partialFingerprints"].(map[string]any)[fingerprintKey]
	if pf != coveragejson.Fingerprint(r.Findings[0].Kind, r.Findings[0].Endpoint, r.Findings[0].Relationship) {
		t.Errorf("empty fingerprint not filled: %v", pf)
	}
}
