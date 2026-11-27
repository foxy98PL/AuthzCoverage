package redact

import (
	"bytes"
	"strings"
	"testing"
)

func TestFingerprint(t *testing.T) {
	// sha256("abc") = ba7816bf8f01cfea...
	if got := Fingerprint("abc"); got != "ba7816bf8f01" {
		t.Fatalf("Fingerprint(abc) = %q", got)
	}
	if len(Fingerprint("")) != 12 {
		t.Fatal("fingerprint length must be 12")
	}
	if Fingerprint("a") == Fingerprint("b") {
		t.Fatal("collision on trivial input")
	}
}

func TestIsSensitiveHeader(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"Authorization", true}, {"authorization", true}, {"Proxy-Authorization", true},
		{"Cookie", true}, {"Set-Cookie", true}, {"X-API-Key", true}, {"Api-Key", true},
		{"X-Auth-Token", true}, {"X-CSRF-Token", true}, {"X-XSRF-TOKEN", true},
		{"Content-Type", false}, {"Accept", false}, {"Host", false},
	}
	for _, tt := range tests {
		if got := IsSensitiveHeader(tt.name); got != tt.want {
			t.Errorf("IsSensitiveHeader(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestStripControl(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"plain", "GET /books/v1", "GET /books/v1"},
		{"csi colour", "\x1b[31mred\x1b[0m", "red"},
		{"csi cursor move", "a\x1b[2Kb\x1b[10;20Hc", "abc"},
		{"osc title bel", "x\x1b]0;pwned\x07y", "xy"},
		{"osc hyperlink st", "\x1b]8;;http://evil\x1b\\link\x1b]8;;\x1b\\", "link"},
		{"two-byte escape (ESC c = reset)", "a\x1bcb", "ab"},
		{"trailing esc", "ab\x1b", "ab"},
		{"c0 controls", "a\r\nb\tc\x00d\x07", "abcd"},
		{"del", "a\x7fb", "ab"},
		{"c1 csi", "a\u009b31mb", "a31mb"},
		{"bidi override", "admin\u202eresu", "adminresu"},
		{"invalid utf8", "a\xffb", "a�b"},
		{"unicode kept", "zażółć 書", "zażółć 書"},
		{"truncated csi", "a\x1b[", "a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StripControl(tt.in); got != tt.want {
				t.Errorf("StripControl(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestWriterKeepsLayoutControls(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	in := "A\tB\n\x1b[31mC\x1b[0m\r\n"
	n, err := w.Write([]byte(in))
	if err != nil || n != len(in) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if got := buf.String(); got != "A\tB\nC\n" {
		t.Fatalf("got %q", got)
	}
}

func TestJSON(t *testing.T) {
	jwtLike := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln"
	tests := []struct {
		name    string
		in      string
		want    string // exact output; "" => expect error
		mustNot []string
	}{
		{"keeps data", `{"book_title":"t1","n":1.50}`, `{"book_title":"t1","n":1.50}`, nil},
		{"password", `{"username":"alice","password":"hunter2"}`, `{"password":"[redacted]","username":"alice"}`, []string{"hunter2", Fingerprint("hunter2")}},
		{"passwd/pwd/secret/clientsecret no fp", `{"passwd":"p1","pwd":"p2","secret":"p3","client_secret":"p4"}`, `{"client_secret":"[redacted]","passwd":"[redacted]","pwd":"[redacted]","secret":"[redacted]"}`, []string{Fingerprint("p1"), Fingerprint("p2"), Fingerprint("p3"), Fingerprint("p4")}},
		{"non-string password", `{"password":12345,"pwd":true}`, `{"password":"[redacted]","pwd":"[redacted]"}`, []string{Fingerprint("12345")}},
		{"token keeps fp", `{"auth_token":"opaque123"}`, `{"auth_token":"[redacted:` + Fingerprint("opaque123") + `]"}`, []string{"opaque123"}},
		{"auth_token nested", `{"data":{"auth_token":"opaque123"}}`, "", []string{"opaque123"}},
		{"jwt-shaped value under any key", `{"x":["` + jwtLike + `"]}`, "", []string{jwtLike, "c2ln"}},
		{"case-insensitive keys", `{"Access_Token":"zzz","API-KEY":"kkk","Secret":"sss"}`, "", []string{"zzz", "kkk", "sss"}},
		{"non-string secret", `{"token":12345}`, "", []string{"12345"}},
		{"top-level array", `[{"refresh_token":"r1"}]`, "", []string{"r1"}},
		{"invalid json", `{"a":`, "", nil},
		{"trailing data", `{"a":1} {"b":2}`, "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JSON([]byte(tt.in))
			if tt.name == "invalid json" || tt.name == "trailing data" {
				if err == nil {
					t.Fatalf("want error, got %s", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.want != "" && string(got) != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
			for _, s := range tt.mustNot {
				if strings.Contains(string(got), s) {
					t.Errorf("output %s still contains %q", got, s)
				}
			}
		})
	}
}

func TestLooksLikeJWT(t *testing.T) {
	for s, want := range map[string]bool{
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig": true,
		"eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.":     true,
		"a.b.c":                                    false,
		"eyJ.only-two":                             false,
		"hello world":                              false,
	} {
		if got := LooksLikeJWT(s); got != want {
			t.Errorf("LooksLikeJWT(%q) = %v, want %v", s, got, want)
		}
	}
}
