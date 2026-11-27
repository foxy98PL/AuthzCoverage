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

func TestBinarySkipped(t *testing.T) {
	data := append([]byte{0, 1, 2}, []byte(mint(`{"sub":"x"}`))...)
	if got := scanContent("img.png", data, allowlist{}); len(got) != 0 {
		t.Fatalf("binary must be skipped, got %v", got)
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
