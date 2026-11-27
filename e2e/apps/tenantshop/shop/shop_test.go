package shop

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func login(t *testing.T, h http.Handler, user string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"`+user+`","password":"demo"}`)))
	var out struct{ Token string }
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Token == "" {
		t.Fatalf("login %s: %d %s", user, rec.Code, rec.Body)
	}
	return out.Token
}

func get(h http.Handler, path, tok string) int {
	req := httptest.NewRequest("GET", path, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestLoginJWTHasOrgID(t *testing.T) {
	h := NewServer()
	tok := login(t, h, "adminB")
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c["org_id"] != "OrgB" || c["sub"] != "adminB" || c["role"] != "admin" {
		t.Fatalf("claims = %v", c)
	}
	if tok != login(t, h, "adminB") {
		t.Fatal("tokens are not deterministic")
	}
	if got := get(h, "/me", tok+"x"); got != 401 {
		t.Fatalf("bad signature: %d", got)
	}
}

func TestTenantCheckOnList(t *testing.T) {
	h := NewServer()
	if got := get(h, "/orgs/OrgA/orders", login(t, h, "adminB")); got != 403 {
		t.Fatalf("adminB list OrgA orders = %d, want 403", got)
	}
	if got := get(h, "/orgs/OrgA/orders", login(t, h, "ann")); got != 200 {
		t.Fatalf("ann list own org = %d", got)
	}
}

// Documents the seeded bug (KAN-74): the order read has no tenant check.
func TestSeededBugAdminBReadsOrgAOrder(t *testing.T) {
	h := NewServer()
	if got := get(h, "/orgs/OrgA/orders/o-1", login(t, h, "adminB")); got != 200 {
		t.Fatalf("seeded bug gone: adminB GET OrgA order = %d, want 200", got)
	}
	if got := get(h, "/orgs/OrgA/orders/o-1", login(t, h, "ben")); got != 403 {
		t.Fatalf("ben (customer) = %d, want 403", got)
	}
}

func TestSeedShape(t *testing.T) {
	customers := map[string]int{}
	admins := map[string]int{}
	for _, u := range seedUsers {
		switch u.Role {
		case "customer":
			customers[u.Org]++
		case "admin":
			admins[u.Org]++
		default:
			t.Fatalf("unexpected role %q for %s", u.Role, u.Name)
		}
	}
	for _, org := range []string{"OrgA", "OrgB"} {
		if customers[org] != 2 || admins[org] != 1 {
			t.Fatalf("%s: customers=%d admins=%d, want 2 and 1", org, customers[org], admins[org])
		}
	}
	if len(customers) != 2 || len(admins) != 2 {
		t.Fatalf("unexpected orgs: customers=%v admins=%v", customers, admins)
	}
}

func TestOpenAPIServed(t *testing.T) {
	rec := httptest.NewRecorder()
	NewServer().ServeHTTP(rec, httptest.NewRequest("GET", "/openapi.yaml", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "yaml") {
		t.Fatalf("content type = %q, want yaml", ct)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "openapi: 3") || !strings.Contains(body, "/orgs/{orgId}/orders/{orderId}") {
		t.Fatalf("unexpected body start: %.60q", body)
	}
}
