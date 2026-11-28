package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestFingerprintCmd(t *testing.T) {
	sum := sha256.Sum256([]byte("k-123"))
	want := hex.EncodeToString(sum[:]) + "\n"
	for name, in := range map[string]string{"plain": "k-123", "newline": "k-123\n", "crlf": "k-123\r\n"} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			cmd := newFingerprintCmd()
			cmd.SetIn(strings.NewReader(in))
			cmd.SetOut(&out)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if out.String() != want {
				t.Fatalf("got %q want %q", out.String(), want)
			}
		})
	}
	t.Run("empty", func(t *testing.T) {
		cmd := newFingerprintCmd()
		cmd.SetIn(strings.NewReader("\n"))
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		if err := cmd.Execute(); err == nil {
			t.Fatal("empty credential must be an error")
		}
	})
}
