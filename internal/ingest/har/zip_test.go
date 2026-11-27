package har

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authzcov/internal/model"
)

func zipHAR(path string) string {
	return `{"log":{"entries":[{"request":{"method":"GET","url":"http://h/` + path + `"},"response":{"status":200,"content":{}}}]}}`
}

func writeZip(t *testing.T, members [][2]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "run.har.zip")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range members {
		w, err := zw.Create(m[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(m[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func readAll(p string) ([]*model.Exchange, error) {
	var xs []*model.Exchange
	mk := func(label string) Options { return Options{Source: label, Extract: bearerExtract} }
	for x, err := range ExchangesFromFile(p, mk, nil) {
		if err != nil {
			return xs, err
		}
		xs = append(xs, x)
	}
	return xs, nil
}

func TestZipMembersSortedAndFiltered(t *testing.T) {
	p := writeZip(t, [][2]string{
		{"b.har", zipHAR("b")},
		{"notes.txt", "ignore me"},
		{"a.har", zipHAR("a")},
		{"sub/c.HAR", zipHAR("c")},
	})
	xs, err := readAll(p)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range xs {
		got = append(got, x.Source+" "+x.Path)
	}
	want := "run.har.zip!a.har#0 /a,run.har.zip!b.har#0 /b,run.har.zip!sub/c.HAR#0 /c"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %q\nwant %q", strings.Join(got, ","), want)
	}
}

func TestZipErrors(t *testing.T) {
	notZip := filepath.Join(t.TempDir(), "x.zip")
	if err := os.WriteFile(notZip, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, path, want string
	}{
		{"no har members", writeZip(t, [][2]string{{"a.txt", "x"}}), "no .har members"},
		{"corrupt zip", notZip, "x.zip"},
		{"missing file", filepath.Join(t.TempDir(), "missing.har"), "missing.har"},
		{"bad member json", writeZip(t, [][2]string{{"a.har", "not json"}}), "run.har.zip!a.har"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := readAll(tt.path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestZipLimits(t *testing.T) {
	bomb := `{"log":{"entries":[],"pad":"` + strings.Repeat("A", 200000) + `"}}`
	small := zipHAR("a")
	tests := []struct {
		name    string
		members [][2]string
		ratio   int64
		total   int64
		wantErr bool
	}{
		{"high ratio", [][2]string{{"bomb.har", bomb}}, 100, 2 << 30, true},
		{"ratio raised", [][2]string{{"bomb.har", bomb}}, 1 << 20, 2 << 30, false},
		{"total exceeded", [][2]string{{"a.har", small}, {"b.har", small}}, 1 << 20, int64(len(small)) + 5, true},
		{"within limits", [][2]string{{"a.har", small}}, 1 << 20, 2 << 30, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldR, oldT := maxZipRatio, maxZipTotal
			t.Cleanup(func() { maxZipRatio, maxZipTotal = oldR, oldT })
			maxZipRatio, maxZipTotal = tt.ratio, tt.total
			_, err := readAll(writeZip(t, tt.members))
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "decompressed size limit exceeded") || !strings.HasPrefix(err.Error(), "har: run.har.zip!") {
					t.Fatalf("err = %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func bearerExtract(func(string) []string) model.Credential { return model.Credential{Kind: "none"} }

// A member header that claims a huge compressed size defeats the per-member
// ratio cap, but the total cap (counted from bytes actually read) still bounds it.
func TestZipForgedCompressedSizeStillBoundedByTotal(t *testing.T) {
	bomb := `{"log":{"entries":[],"pad":"` + strings.Repeat("A", 200000) + `"}}`
	var raw bytes.Buffer
	fw, err := flate.NewWriter(&raw, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte(bomb))
	_ = fw.Close()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{
		Name:               "forged.har",
		Method:             zip.Deflate,
		CRC32:              crc32.ChecksumIEEE([]byte(bomb)),
		CompressedSize64:   1 << 30, // forged: real size is a few hundred bytes
		UncompressedSize64: uint64(len(bomb)),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Write the real compressed data; the header's claimed size is not enforced by CreateRaw.
	if _, err := w.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "forged.har.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	oldR, oldT := maxZipRatio, maxZipTotal
	t.Cleanup(func() { maxZipRatio, maxZipTotal = oldR, oldT })
	maxZipRatio, maxZipTotal = 100, 50000
	_, err = readAll(p)
	if err == nil || !strings.Contains(err.Error(), "decompressed size limit exceeded") || !strings.Contains(err.Error(), "forged.har.zip!forged.har") {
		t.Fatalf("err = %v", err)
	}
}
