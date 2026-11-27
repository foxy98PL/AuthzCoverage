package shop

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

// demoKey signs demo tokens. It protects nothing; tenantshop is a test fixture.
var demoKey = []byte("tenantshop-demo-key-not-a-secret")

// fixedIAT keeps tokens byte-identical across runs.
const fixedIAT = 1767225600 // 2026-01-01T00:00:00Z

var enc = base64.RawURLEncoding

// Claims are the JWT claims. Field order is fixed so tokens are deterministic.
type Claims struct {
	Sub   string `json:"sub"`
	OrgID string `json:"org_id"`
	Role  string `json:"role"`
	IAT   int64  `json:"iat"`
}

func sign(msg string) string {
	m := hmac.New(sha256.New, demoKey)
	m.Write([]byte(msg))
	return enc.EncodeToString(m.Sum(nil))
}

// MakeToken returns the HS256 JWT for a user.
func MakeToken(u User) string {
	hdr := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, _ := json.Marshal(Claims{Sub: u.Name, OrgID: u.Org, Role: u.Role, IAT: fixedIAT})
	msg := hdr + "." + enc.EncodeToString(body)
	return msg + "." + sign(msg)
}

// callerOf verifies the bearer token and returns the claims, or false.
func callerOf(r *http.Request) (Claims, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return Claims{}, false
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || !hmac.Equal([]byte(sign(parts[0]+"."+parts[1])), []byte(parts[2])) {
		return Claims{}, false
	}
	raw, err := enc.DecodeString(parts[1])
	if err != nil {
		return Claims{}, false
	}
	var c Claims
	if json.Unmarshal(raw, &c) != nil || c.Sub == "" {
		return Claims{}, false
	}
	return c, true
}
