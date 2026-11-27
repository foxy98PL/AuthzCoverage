package cli

import (
	"bytes"
	"testing"
)

func TestVersionOutput(t *testing.T) {
	oldV, oldC := version, commit
	t.Cleanup(func() { version, commit = oldV, oldC })

	tests := []struct{ version, commit, want string }{
		{"dev", "", "authzcov dev\n"},
		{"0.1.0", "abc1234", "authzcov 0.1.0 (commit abc1234)\n"},
	}
	for _, tt := range tests {
		version, commit = tt.version, tt.commit
		var out, errb bytes.Buffer
		if code := Execute([]string{"version"}, &out, &errb); code != ExitOK {
			t.Fatalf("exit %d, stderr %q", code, errb.String())
		}
		if out.String() != tt.want {
			t.Errorf("version(%q, %q) = %q, want %q", tt.version, tt.commit, out.String(), tt.want)
		}
	}
}
