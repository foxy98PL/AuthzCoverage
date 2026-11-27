package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mint builds an unsigned JWT-shaped string at runtime so this file holds no literal token.
func mint(payload string) string {
	e := base64.RawURLEncoding.EncodeToString
	return e([]byte(`{"alg":"none"}`)) + "." + e([]byte(payload)) + "."
}

func har(hosts ...string) []byte {
	var b strings.Builder
	b.WriteString("{\"log\":{\"entries\":[\n")
	for i, h := range hosts {
		if i > 0 {
			b.WriteString(",\n")
		}
		b.WriteString(`{"request":{"url":"https://` + h + `/x"}}`)
	}
	b.WriteString("\n]}}")
	return []byte(b.String())
}

func TestJWT(t *testing.T) {
	bad := mint(`{"sub":"alice"}`)
	good := mint(`{"iss":"authzcov-test","sub":"alice"}`)
	if got := scanContent("a_test.go", []byte("x := \""+bad+"\""), allowlist{}); len(got) != 1 || got[0].line != 1 {
		t.Fatalf("non-test iss must fail once, got %v", got)
	}
	if got := scanContent("a.txt", []byte("\n"+good), allowlist{}); len(got) != 0 {
		t.Fatalf("test iss must pass, got %v", got)
	}
	if got := scanContent("a.txt", []byte("eyJ"+"hYQ.eyJ"+"hYQ.x"), allowlist{}); len(got) != 1 {
		t.Fatalf("undecodable token must fail, got %v", got)
	}
}

func TestAllowlist(t *testing.T) {
	t1, t2 := mint(`{"sub":"a"}`), mint(`{"sub":"b"}`)
	al, err := parseAllowlist(strings.NewReader("# c\nf.go " + tokenHash(t1) + " synthetic\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := scanContent("f.go", []byte(t1), al); len(got) != 0 {
		t.Fatalf("allowlisted token must pass, got %v", got)
	}
	if got := scanContent("f.go", []byte(t1+"\n"+t2), al); len(got) != 1 || got[0].line != 2 {
		t.Fatalf("second token in allowlisted file must fail, got %v", got)
	}
	if got := scanContent("other.go", []byte(t1), al); len(got) != 1 {
		t.Fatalf("allowlist is per path, got %v", got)
	}
	if _, err := parseAllowlist(strings.NewReader("f.go abc\n")); err == nil {
		t.Fatal("entry without reason must be rejected")
	}
}

func TestHAR(t *testing.T) {
	if got := scanContent("a.har", har("api.prod.corp.io"), allowlist{}); len(got) != 1 || got[0].line != 2 {
		t.Fatalf("real host must fail at its line, got %v", got)
	}
	ok := har("shop.test", "localhost", "127.0.0.1", "example.com", "a.example.com", "[::1]:8080")
	if got := scanContent("a.har", ok, allowlist{}); len(got) != 0 {
		t.Fatalf("demo hosts must pass, got %v", got)
	}
	if got := scanContent("a.har", har("evilexample.com", "test"), allowlist{}); len(got) != 2 {
		t.Fatalf("suffix tricks must fail, got %v", got)
	}
	if got := scanContent("a.har", []byte("{"), allowlist{}); len(got) != 1 {
		t.Fatalf("invalid HAR must fail, got %v", got)
	}
}

func TestBinaryJWTScanned(t *testing.T) {
	bad := append([]byte{0, 1, 2}, []byte(mint(`{"iss":"evil"}`))...)
	got := scanContent("img.png", bad, allowlist{})
	if len(got) != 1 || !strings.Contains(got[0].String(), "img.png:offset 3:") {
		t.Fatalf("JWT in binary must fail with offset, got %v", got)
	}
	good := append([]byte{0, 1, 2}, []byte(mint(`{"iss":"authzcov-test"}`))...)
	if got := scanContent("img.png", good, allowlist{}); len(got) != 0 {
		t.Fatalf("test JWT in binary must pass, got %v", got)
	}
	if got := scanContent("img.png", []byte{0, 1, 2, 3}, allowlist{}); len(got) != 0 {
		t.Fatalf("plain binary must pass, got %v", got)
	}
}

func TestHARSniffedByContent(t *testing.T) {
	if got := scanContent("renamed.json", har("api.real-company.com"), allowlist{}); len(got) != 1 {
		t.Fatalf("HAR-shaped JSON under any name must fail, got %v", got)
	}
	bom := append([]byte("\xef\xbb\xbf  \n"), har("api.real-company.com")...)
	if got := scanContent("x.txt", bom, allowlist{}); len(got) != 1 {
		t.Fatalf("BOM-prefixed HAR must fail, got %v", got)
	}
	if got := scanContent("x.json", har("localhost"), allowlist{}); len(got) != 0 {
		t.Fatalf("demo HAR must pass, got %v", got)
	}
	for _, other := range []string{`{"log":{"entries":"no"}}`, `{"entries":[{"request":{"url":"https://real.io"}}]}`, `["entries"]`, `plain "entries" text`} {
		if got := scanContent("o.json", []byte(other), allowlist{}); len(got) != 0 {
			t.Fatalf("non-HAR %q must pass, got %v", other, got)
		}
	}
}

func TestZipMembersSniffed(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("data/session.json")
	_, _ = w.Write(har("api.real-company.com"))
	_ = zw.Close()
	for _, name := range []string{"bundle.zip", "bundle.har.zip"} {
		got := scanContent(name, buf.Bytes(), allowlist{})
		if len(got) != 1 || !strings.HasPrefix(got[0].path, name+"!") {
			t.Fatalf("%s: want host failure from sniffed member, got %v", name, got)
		}
	}
	// A .zip that is not a zip falls back to the raw scan.
	if got := scanContent("fake.zip", []byte("hello"), allowlist{}); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestOversizeFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.bin")
	f, err := os.Create(p) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxFileSize + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	got := scanFile(dir, "big.bin", allowlist{})
	if len(got) != 1 || !strings.Contains(got[0].reason, "50 MiB") {
		t.Fatalf("oversize must fail clearly, got %v", got)
	}
	al := allowlist{"big.bin": {"000000000000": "large asset"}}
	if got := scanFile(dir, "big.bin", al); len(got) != 0 {
		t.Fatalf("path-allowlisted oversize file must pass, got %v", got)
	}
}

func TestHARZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("session.har")
	_, _ = w.Write(har("real.example.org"))
	w, _ = zw.Create("notes.txt")
	_, _ = w.Write([]byte(mint(`{"sub":"x"}`)))
	_ = zw.Close()
	got := scanContent("c.har.zip", buf.Bytes(), allowlist{})
	if len(got) != 2 || !strings.HasPrefix(got[0].path, "c.har.zip!") {
		t.Fatalf("want host and token failures from zip members, got %v", got)
	}
}

func TestScanFilesAndRun(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ok.txt", []byte(mint(`{"iss":"authzcov-test"}`)))
	write("bad.har", har("real.example.org"))
	files := []string{"ok.txt", "bad.har", "missing.txt"}
	if got := scanFiles(dir, files, allowlist{}); len(got) != 1 || got[0].path != "bad.har" {
		t.Fatalf("got %v", got)
	}
}
