package shop

import (
	"fmt"
	"net/http"
	"slices"
)

// Mutant is one fixed-app variant with exactly one authorization check removed.
type Mutant struct {
	ID           string
	Description  string
	Endpoint     string // "METHOD /template", as authzcov names it
	Relationship string // the authzcov relationship that should raise suspicious_allow
}

const (
	orderEP     = "/orgs/{orgId}/orders/{orderId}"
	listEP      = "/orgs/{orgId}/orders"
	customersEP = "/orgs/{orgId}/customers"
)

var mutants = []Mutant{
	{"get-tenant", "GET order: caller's org vs {orgId} not compared", "GET " + orderEP, "other_tenant"},
	{"get-owner", "GET order: owner-or-admin check removed", "GET " + orderEP, "same_role_other_user"},
	{"put-tenant", "PUT order: caller's org vs {orgId} not compared", "PUT " + orderEP, "other_tenant"},
	{"put-owner", "PUT order: owner-or-admin check removed", "PUT " + orderEP, "same_role_other_user"},
	{"delete-tenant", "DELETE order: caller's org vs {orgId} not compared", "DELETE " + orderEP, "other_tenant"},
	{"delete-owner", "DELETE order: owner-or-admin check removed", "DELETE " + orderEP, "same_role_other_user"},
	{"list-tenant", "list orders: caller's org vs {orgId} not compared", "GET " + listEP, "other_tenant"},
	{"create-tenant", "create order: caller's org vs {orgId} not compared", "POST " + listEP, "other_tenant"},
	{"customers-role", "list customers: admin-only role check removed", "GET " + customersEP, "lower_role"},
	{"customers-tenant", "list customers: caller's org vs {orgId} not compared", "GET " + customersEP, "other_tenant"},
}

// Skip returns the checks the mutant removes (always exactly its own ID).
func (m Mutant) Skip() map[string]bool { return map[string]bool{m.ID: true} }

// Mutants lists the variants NewVariant accepts besides "seeded" and "fixed".
func Mutants() []Mutant { return slices.Clone(mutants) }

// NewVariant returns a fresh tenantshop handler. "seeded" is NewServer (the seeded getOrder bug),
// "fixed" has that bug fixed, and any Mutants ID is "fixed" minus exactly that one check.
func NewVariant(name string) (http.Handler, error) {
	switch name {
	case "seeded":
		return NewServer(), nil
	case "fixed":
		return newServer(nil, true), nil
	}
	for _, m := range mutants {
		if m.ID == name {
			return newServer(m.Skip(), true), nil
		}
	}
	return nil, fmt.Errorf("shop: unknown variant %q", name)
}
