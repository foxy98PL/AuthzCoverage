// Package redact turns secrets into fingerprints and makes traffic-derived
// text safe to print.
package redact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Fingerprint returns the first 12 hex chars of SHA-256(raw).
func Fingerprint(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:12]
}

var sensitiveHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true,
	"cookie": true, "set-cookie": true,
	"x-api-key": true, "api-key": true, "apikey": true,
	"x-auth-token": true, "x-access-token": true,
	"x-csrf-token": true, "x-xsrf-token": true,
	"x-amz-security-token": true,
}

// IsSensitiveHeader reports whether a header's value must never be kept.
func IsSensitiveHeader(name string) bool { return sensitiveHeaders[strings.ToLower(name)] }

// sensitiveKeys are JSON object keys whose values are replaced. Compared
// after lower-casing and removing '-' and '_'.
var sensitiveKeys = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "secret": true, "clientsecret": true,
	"token": true, "authtoken": true, "accesstoken": true, "refreshtoken": true, "idtoken": true,
	"apikey": true, "authorization": true, "cookie": true, "sessionid": true, "jwt": true,
}

// passwordKeys are the low-entropy subset of sensitiveKeys: their values get
// no fingerprint at all, since a printed hash would allow offline guessing.
var passwordKeys = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "secret": true, "clientsecret": true,
}

func normKey(k string) string {
	return strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(k))
}

func isSensitiveKey(k string) bool { return sensitiveKeys[normKey(k)] }

func isPasswordKey(k string) bool { return passwordKeys[normKey(k)] }

// LooksLikeJWT reports a compact JWS shape: three dot-separated base64url
// parts with a JSON header ("eyJ").
func LooksLikeJWT(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "eyJ") || !strings.HasPrefix(parts[1], "eyJ") {
		return false
	}
	for _, p := range parts {
		for _, r := range p {
			if !isBase64URL(r) {
				return false
			}
		}
	}
	return true
}

func isBase64URL(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return r == '-' || r == '_' || r == '='
}

// JSON returns body with secret values replaced by "[redacted:<fp>]": values
// under sensitive keys and any JWT-shaped string. Keys come out sorted.
func JSON(body []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("redact json: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("redact json: trailing data after value")
	}
	out, err := json.Marshal(scrub(v, plain))
	if err != nil {
		return nil, fmt.Errorf("redact json: %w", err)
	}
	return out, nil
}

type mode int

const (
	plain    mode = iota
	token         // fingerprinted redaction
	password      // bare "[redacted]", never a fingerprint
)

func scrub(v any, m mode) any {
	if m == password && v != nil {
		if _, isContainer := v.(map[string]any); !isContainer {
			if _, isList := v.([]any); !isList {
				return "[redacted]"
			}
		}
	}
	sensitive := m != plain
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			switch {
			case isPasswordKey(k):
				t[k] = scrub(val, password)
			case isSensitiveKey(k):
				t[k] = scrub(val, token)
			default:
				t[k] = scrub(val, plain)
			}
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = scrub(val, m)
		}
		return t
	case string:
		if sensitive || LooksLikeJWT(t) {
			return "[redacted:" + Fingerprint(t) + "]"
		}
		return t
	case json.Number:
		if sensitive {
			return "[redacted:" + Fingerprint(t.String()) + "]"
		}
		return t
	default:
		if sensitive && v != nil {
			return "[redacted]"
		}
		return v
	}
}

// StripControl removes ANSI escape sequences, C0/C1 control characters, DEL
// and bidi controls, and replaces invalid UTF-8. Use for single-line cells.
func StripControl(s string) string { return strip(s, false) }

func strip(s string, keepLayout bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c == 0x1b {
			i = skipEscape(s, i)
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteRune(utf8.RuneError)
		case keepLayout && (r == '\n' || r == '\t'):
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
		case isBidi(r):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// skipEscape returns the index after the escape sequence starting at s[i].
func skipEscape(s string, i int) int {
	i++ // ESC
	if i >= len(s) {
		return i
	}
	switch s[i] {
	case '[': // CSI: params/intermediates then a final byte 0x40-0x7e
		i++
		for i < len(s) && (s[i] < 0x40 || s[i] > 0x7e) {
			i++
		}
		return min(i+1, len(s))
	case ']', 'P', '_', '^', 'X': // OSC/DCS/APC/PM/SOS: until BEL or ESC \
		i++
		for i < len(s) {
			if s[i] == 0x07 {
				return i + 1
			}
			if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
				return i + 2
			}
			i++
		}
		return i
	default: // two-byte sequence
		return i + 1
	}
}

func isBidi(r rune) bool {
	return (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200e || r == 0x200f || r == 0x061c
}

// Writer strips escape sequences and control characters except '\n' and
// '\t' from everything written through it. Wrap terminal output with it.
type Writer struct{ w io.Writer }

func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// Write reports len(p) on success so callers like tabwriter are not confused
// by the shorter cleaned output.
func (w *Writer) Write(p []byte) (int, error) {
	if _, err := io.WriteString(w.w, strip(string(p), true)); err != nil {
		return 0, err
	}
	return len(p), nil
}
