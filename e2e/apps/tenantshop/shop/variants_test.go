package shop

import "testing"

func TestNewVariant(t *testing.T) {
	if _, err := NewVariant("nope"); err == nil {
		t.Fatal("unknown variant must fail")
	}
	// o-1 is ann's order in OrgA; adminB is an admin in OrgB.
	status := func(name string) int {
		h, err := NewVariant(name)
		if err != nil {
			t.Fatal(err)
		}
		return get(h, "/orgs/OrgA/orders/o-1", login(t, h, "adminB"))
	}
	if got := status("seeded"); got != 200 {
		t.Errorf("seeded = %d, want 200", got)
	}
	if got := status("fixed"); got != 403 {
		t.Errorf("fixed = %d, want 403", got)
	}
	if got := status("get-tenant"); got != 200 {
		t.Errorf("get-tenant = %d, want 200", got)
	}
	for _, m := range Mutants() {
		if _, err := NewVariant(m.ID); err != nil {
			t.Errorf("%s: %v", m.ID, err)
		}
	}
}
