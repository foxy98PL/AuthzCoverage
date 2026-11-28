package identity

import (
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// The same bearer token yields one shared, correct credential; a different
// token never reuses it.
func TestExtractorSharesCredentialPerToken(t *testing.T) {
	ex := NewExtractor(nil)
	a := mkJWT(t, jwt.MapClaims{"sub": "alice"})
	b := mkJWT(t, jwt.MapClaims{"sub": "bob"})
	c1 := ex(hdr("Authorization", "Bearer "+a))
	c2 := ex(hdr("Authorization", "Bearer "+a))
	c3 := ex(hdr("Authorization", "Bearer "+b))
	if reflect.ValueOf(c1.Claims).Pointer() != reflect.ValueOf(c2.Claims).Pointer() {
		t.Error("same token: claims map not shared")
	}
	if c1.Fingerprint != c2.Fingerprint || c1.Fingerprint == c3.Fingerprint {
		t.Errorf("fingerprints: %q %q %q", c1.Fingerprint, c2.Fingerprint, c3.Fingerprint)
	}
	if c1.Claims["sub"] != "alice" || c3.Claims["sub"] != "bob" {
		t.Errorf("claims: %v %v", c1.Claims, c3.Claims)
	}
}
