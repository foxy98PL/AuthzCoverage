package record

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"tenantshop/shop"
)

func TestFullScriptCellsUnique(t *testing.T) {
	seen := map[string]bool{}
	n := 0
	for _, s := range FullScript() {
		if s.Cell == "" {
			continue
		}
		n++
		if seen[s.Cell] {
			t.Errorf("duplicate cell %q", s.Cell)
		}
		seen[s.Cell] = true
	}
	if n < 16 {
		t.Errorf("only %d attacker steps", n)
	}
}

func TestSeededScriptHasNoCells(t *testing.T) {
	for _, s := range SeededScript() {
		if s.Cell != "" {
			t.Errorf("seeded step has cell %q", s.Cell)
		}
	}
}

// harStatuses records steps against a fresh server of the variant and returns the response
// status of every script step (the six login entries are skipped).
func harStatuses(t *testing.T, variant string, steps []Step) []int {
	t.Helper()
	h, err := shop.NewVariant(variant)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	raw, err := RecordScript(srv.URL, "http://tenantshop.test", nil, steps)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Log struct {
			Entries []struct {
				Response struct{ Status int }
			}
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	const logins = 6
	if len(doc.Log.Entries) != logins+len(steps) {
		t.Fatalf("%s: %d entries for %d steps", variant, len(doc.Log.Entries), len(steps))
	}
	out := make([]int, len(steps))
	for i := range steps {
		out[i] = doc.Log.Entries[logins+i].Response.Status
	}
	return out
}

// TestMutantsRemoveExactlyOneCheck: against the fixed app, each mutant changes the response
// status of its own target cell step and of no other step. FullScript gives every write attack its
// own victim order and runs destructive attacks last, so no downstream step is expected to differ.
func TestMutantsRemoveExactlyOneCheck(t *testing.T) {
	steps := FullScript()
	fixed := harStatuses(t, "fixed", steps)
	for _, m := range shop.Mutants() {
		t.Run(m.ID, func(t *testing.T) {
			if n := len(m.Skip()); n != 1 {
				t.Errorf("skip set has %d keys, want exactly 1", n)
			}
			target := m.Endpoint + "|" + m.Relationship
			got := harStatuses(t, m.ID, steps)
			hit := false
			for i, s := range steps {
				switch {
				case got[i] == fixed[i]:
				case s.Cell == target:
					hit = true
				default:
					t.Errorf("step %d (%s %s, cell %q): status %d, fixed %d: only %q may differ", i, s.method, s.path, s.Cell, got[i], fixed[i], target)
				}
			}
			if !hit {
				t.Errorf("target cell %q has the same status as the fixed app", target)
			}
		})
	}
}
