package credentials

import (
	"fmt"
	"log/slog"

	"authzcov/internal/redact"
)

// Secret holds a credential in memory only. Every way of printing or
// serialising it (fmt verbs, json, yaml, text, slog) yields a redacted marker;
// the only way out is Expose, which exec calls when it sets the header.
type Secret struct {
	b    []byte
	noFP bool // env secrets are low-entropy: no fingerprint in the marker
}

// NewSecret wraps b; the Secret takes ownership of the slice.
func NewSecret(b []byte) Secret { return Secret{b: b} }

// Expose returns the raw value. Call it only where the value is sent.
func (s Secret) Expose() string { return string(s.b) }

// Zero overwrites the value (best effort; copies made by Expose are not reached).
func (s *Secret) Zero() {
	for i := range s.b {
		s.b[i] = 0
	}
	s.b = nil
}

func (s Secret) redacted() string {
	if s.noFP {
		return "[REDACTED]"
	}
	return "[REDACTED:" + redact.Fingerprint(string(s.b)) + "]"
}

// String implements fmt.Stringer.
func (s Secret) String() string { return s.redacted() }

// GoString implements fmt.GoStringer.
func (s Secret) GoString() string { return s.redacted() }

// Format implements fmt.Formatter so no verb (%x, %d, ...) can reveal bytes.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(s.redacted())) }

// MarshalJSON implements json.Marshaler.
func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + s.redacted() + `"`), nil }

// MarshalText implements encoding.TextMarshaler.
func (s Secret) MarshalText() ([]byte, error) { return []byte(s.redacted()), nil }

// MarshalYAML implements yaml.Marshaler.
func (s Secret) MarshalYAML() (any, error) { return s.redacted(), nil }

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue(s.redacted()) }
