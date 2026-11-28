package items

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func planJSON(version int, raw bool, probes string) string {
	rawS := "false"
	if raw {
		rawS = "true"
	}
	return `{"plan_version":` + itoa(version) + `,"contains_raw_ids":` + rawS + `,"probes":[` + probes + `]}`
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

const okProbe = `{"id":"p2","method":"GET","path_template":"/t/{tenant}/orders/{oid}","attacker":{"identity":"bob","role":"user"},
"object":{"resource":"order","param":"oid","id_hash":"h","id":"42"},"expect":"deny","path_params":{"tenant":"acme"}}`

func one(t *testing.T, doc string) Item {
	t.Helper()
	got, err := Load(strings.NewReader(doc))
	if err != nil || len(got) != 1 {
		t.Fatalf("err=%v items=%v", err, got)
	}
	return got[0]
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name       string
		doc        string
		path       string
		executable bool
		reason     string
	}{
		{"raw", planJSON(1, true, okProbe), "/t/acme/orders/42", true, ""},
		{"hash only", planJSON(1, false, okProbe), "/t/{tenant}/orders/{oid}", false, "raw"},
		{"empty id", planJSON(1, true, strings.Replace(okProbe, `"id":"42"`, `"id":""`, 1)), "/t/{tenant}/orders/{oid}", false, "object"},
		{"missing attacker", planJSON(1, true, strings.Replace(okProbe, `"attacker":{"identity":"bob","role":"user"}`, `"attacker":null`, 1)), "/t/{tenant}/orders/{oid}", false, "attacker"},
		{"unresolved param", planJSON(1, true, strings.Replace(okProbe, `,"path_params":{"tenant":"acme"}`, ``, 1)), "/t/{tenant}/orders/{oid}", false, "path"},
		{"waived", planJSON(1, true, strings.Replace(okProbe, `"expect"`, `"waived":true,"expect"`, 1)), "/t/{tenant}/orders/{oid}", false, "waived"},
		{"hostile id", planJSON(1, true, strings.Replace(okProbe, `"id":"42"`, `"id":"../x?a=1#"`, 1)), "/t/acme/orders/..%2Fx%3Fa=1%23", true, ""},
		{"dotdot id", planJSON(1, true, strings.Replace(okProbe, `"id":"42"`, `"id":".."`, 1)), "/t/acme/orders/%2E%2E", true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			it := one(t, tc.doc)
			if it.Path != tc.path || it.Executable != tc.executable {
				t.Fatalf("path=%q exec=%v reason=%q", it.Path, it.Executable, it.Reason)
			}
			if tc.executable != (it.Reason == "") || !strings.Contains(it.Reason, tc.reason) {
				t.Fatalf("reason=%q", it.Reason)
			}
			if strings.Contains(it.Reason, "42") || strings.Contains(it.Reason, "..") {
				t.Fatalf("reason leaks id: %q", it.Reason)
			}
			if it.Method != "GET" || it.ProbeID != "p2" {
				t.Fatalf("%+v", it)
			}
		})
	}
}

func TestBadVersion(t *testing.T) {
	for _, v := range []int{0, 2} {
		if _, err := Load(strings.NewReader(planJSON(v, true, okProbe))); err == nil {
			t.Fatalf("version %d accepted", v)
		}
	}
	_, err := Load(strings.NewReader(`{"plan_version":1,"probes":"SECRET-ID"`))
	if err == nil || strings.Contains(err.Error(), "SECRET-ID") {
		t.Fatalf("err=%v", err)
	}
}

func TestDeterministicOrder(t *testing.T) {
	p1 := strings.Replace(okProbe, `"p2"`, `"p1"`, 1)
	a, _ := Load(strings.NewReader(planJSON(1, true, okProbe+","+p1)))
	b, _ := Load(strings.NewReader(planJSON(1, true, p1+","+okProbe)))
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) || a[0].ProbeID != "p1" {
		t.Fatalf("not deterministic: %s vs %s", ja, jb)
	}
}

func TestDeterministicOrderDuplicateIDs(t *testing.T) {
	a1 := okProbe
	a2 := strings.Replace(okProbe, `"GET"`, `"DELETE"`, 1)
	a3 := strings.Replace(okProbe, `"bob"`, `"alice"`, 1)
	perms := [][]string{{a1, a2, a3}, {a3, a2, a1}, {a2, a1, a3}}
	var first []byte
	for _, p := range perms {
		got, err := Load(strings.NewReader(planJSON(1, true, strings.Join(p, ","))))
		if err != nil {
			t.Fatal(err)
		}
		j, _ := json.Marshal(got)
		if first == nil {
			first = j
		} else if !bytes.Equal(first, j) {
			t.Fatalf("order depends on input: %s vs %s", first, j)
		}
	}
}

func TestObjectParamMustBeInTemplate(t *testing.T) {
	tests := []struct{ name, doc string }{
		{"empty param", strings.Replace(strings.Replace(okProbe, `"param":"oid"`, `"param":""`, 1), `"tenant":"acme"`, `"tenant":"acme","oid":"7"`, 1)},
		{"param not in template", strings.Replace(strings.Replace(okProbe, `"param":"oid"`, `"param":"zzz"`, 1), `"tenant":"acme"`, `"tenant":"acme","oid":"7"`, 1)},
		{"nil object ref param", strings.Replace(okProbe, `"object":{"resource":"order","param":"oid","id_hash":"h","id":"42"},`, ``, 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			it := one(t, planJSON(1, true, tc.doc))
			if it.Executable || it.Reason == "" || strings.Contains(it.Reason, "42") {
				t.Fatalf("%+v", it)
			}
		})
	}
}

func TestObjectParamRepeated(t *testing.T) {
	doc := strings.Replace(okProbe, `/t/{tenant}/orders/{oid}`, `/o/{oid}/x/{oid}`, 1)
	it := one(t, planJSON(1, true, doc))
	if !it.Executable || it.Path != "/o/42/x/42" {
		t.Fatalf("%+v", it)
	}
}

func TestTraversalLiteralRejected(t *testing.T) {
	for _, tmpl := range []string{"/a/../b/{oid}", "/a/./b/{oid}", "/a/{oid}/..", "/a/x..y/{oid}"} {
		doc := strings.Replace(okProbe, `/t/{tenant}/orders/{oid}`, tmpl, 1)
		it := one(t, planJSON(1, true, doc))
		if it.Executable || it.Reason == "" {
			t.Fatalf("%s: %+v", tmpl, it)
		}
	}
	doc := strings.Replace(okProbe, `/t/{tenant}/orders/{oid}`, `/v1.2/{oid}`, 1)
	if it := one(t, planJSON(1, true, doc)); !it.Executable {
		t.Fatalf("dotted literal rejected: %+v", it)
	}
}
