// Package testkey holds the public signing key and issuer for pseudonymised
// and generated JWTs. The key protects nothing: tokens signed with it are
// stand-ins that carry no authority anywhere.
package testkey

// Issuer is the iss claim of every re-signed or fixture JWT.
const Issuer = "authzcov-test"

// Key signs fixture JWTs (HS256).
var Key = []byte("authzcov-test-signing-key-not-a-secret") //nolint:gosec // public test key, not a secret
