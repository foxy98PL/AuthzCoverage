// Package shop is tenantshop: a tiny multi-tenant demo API with one seeded
// cross-tenant bug (KAN-74), used as an end-to-end test of authzcov.
package shop

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
)

//go:embed openapi.yaml
var openapiYAML []byte

// User is a seeded account. Every password is "demo".
type User struct{ Name, Org, Role string }

// Order belongs to one customer in one org.
type Order struct {
	ID    string `json:"id"`
	Org   string `json:"org"`
	Owner string `json:"owner"`
	Item  string `json:"item"`
}

type server struct {
	mu     sync.Mutex
	users  map[string]User
	orders map[string]*Order
	next   int
}

var seedUsers = []User{
	{"ann", "OrgA", "customer"}, {"amy", "OrgA", "customer"}, {"adminA", "OrgA", "admin"},
	{"ben", "OrgB", "customer"}, {"bob", "OrgB", "customer"}, {"adminB", "OrgB", "admin"},
}

// NewServer returns a fresh tenantshop handler with seed data.
func NewServer() http.Handler {
	s := &server{users: map[string]User{}, orders: map[string]*Order{}}
	for _, u := range seedUsers {
		s.users[u.Name] = u
		if u.Role == "customer" {
			for _, item := range []string{"book", "lamp"} {
				s.create(u, item)
			}
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(openapiYAML)
	})
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("GET /me", s.auth(s.me))
	mux.HandleFunc("GET /orgs/{orgId}/orders", s.auth(s.list))
	mux.HandleFunc("POST /orgs/{orgId}/orders", s.auth(s.createOrder))
	mux.HandleFunc("GET /orgs/{orgId}/orders/{orderId}", s.auth(s.getOrder))
	mux.HandleFunc("PUT /orgs/{orgId}/orders/{orderId}", s.auth(s.putOrder))
	mux.HandleFunc("DELETE /orgs/{orgId}/orders/{orderId}", s.auth(s.deleteOrder))
	mux.HandleFunc("GET /orgs/{orgId}/customers", s.auth(s.customers))
	return mux
}

// create adds an order with the next deterministic ID (caller holds the lock or is setting up).
func (s *server) create(u User, item string) *Order {
	s.next++
	o := &Order{ID: fmt.Sprintf("o-%d", s.next), Org: u.Org, Owner: u.Name, Item: item}
	s.orders[o.ID] = o
	return o
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *server) auth(h func(http.ResponseWriter, *http.Request, Claims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := callerOf(r)
		if !ok {
			fail(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		h(w, r, c)
	}
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		fail(w, http.StatusBadRequest, "bad json")
		return
	}
	u, ok := s.users[in.Username]
	if !ok || in.Password != "demo" {
		fail(w, http.StatusUnauthorized, "bad credentials")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": MakeToken(u)})
}

func (s *server) me(w http.ResponseWriter, _ *http.Request, c Claims) {
	writeJSON(w, http.StatusOK, c)
}

func (s *server) list(w http.ResponseWriter, r *http.Request, c Claims) {
	org := r.PathValue("orgId")
	if c.OrgID != org {
		fail(w, http.StatusForbidden, "forbidden")
		return
	}
	out := []*Order{}
	for _, o := range s.orders {
		if o.Org == org && (c.Role == "admin" || o.Owner == c.Sub) {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return len(out[i].ID) < len(out[j].ID) || len(out[i].ID) == len(out[j].ID) && out[i].ID < out[j].ID
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *server) createOrder(w http.ResponseWriter, r *http.Request, c Claims) {
	if c.OrgID != r.PathValue("orgId") {
		fail(w, http.StatusForbidden, "forbidden")
		return
	}
	var in struct{ Item string }
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Item == "" {
		fail(w, http.StatusBadRequest, "item required")
		return
	}
	o := s.create(s.users[c.Sub], in.Item)
	writeJSON(w, http.StatusCreated, o)
}

func (s *server) getOrder(w http.ResponseWriter, r *http.Request, c Claims) {
	o, ok := s.orders[r.PathValue("orderId")]
	if !ok {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	// SEEDED BUG (KAN-74): missing tenant check. Only "owner or admin" is tested; neither
	// the caller's org vs {orgId} nor the order's org is compared, so adminB can read OrgA orders.
	if o.Owner != c.Sub && c.Role != "admin" {
		fail(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, o)
}

// scoped is the correct check: tenant, order in that tenant, then owner or admin.
func (s *server) scoped(w http.ResponseWriter, r *http.Request, c Claims) *Order {
	org := r.PathValue("orgId")
	if c.OrgID != org {
		fail(w, http.StatusForbidden, "forbidden")
		return nil
	}
	o, ok := s.orders[r.PathValue("orderId")]
	if !ok || o.Org != org {
		fail(w, http.StatusNotFound, "not found")
		return nil
	}
	if o.Owner != c.Sub && c.Role != "admin" {
		fail(w, http.StatusForbidden, "forbidden")
		return nil
	}
	return o
}

func (s *server) putOrder(w http.ResponseWriter, r *http.Request, c Claims) {
	o := s.scoped(w, r, c)
	if o == nil {
		return
	}
	var in struct{ Item string }
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Item == "" {
		fail(w, http.StatusBadRequest, "item required")
		return
	}
	o.Item = in.Item
	writeJSON(w, http.StatusOK, o)
}

func (s *server) deleteOrder(w http.ResponseWriter, r *http.Request, c Claims) {
	o := s.scoped(w, r, c)
	if o == nil {
		return
	}
	delete(s.orders, o.ID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) customers(w http.ResponseWriter, r *http.Request, c Claims) {
	if c.OrgID != r.PathValue("orgId") || c.Role != "admin" {
		fail(w, http.StatusForbidden, "forbidden")
		return
	}
	out := []string{}
	for _, u := range seedUsers {
		if u.Org == c.OrgID && u.Role == "customer" {
			out = append(out, u.Name)
		}
	}
	writeJSON(w, http.StatusOK, out)
}
