package rules

import (
	"testing"

	"github.com/sriharifortitude/kubeshield/internal/manifest"
)

// parseOne builds a single Resource from a YAML fixture -- real parsing,
// not hand-built maps, so a rule's test exercises the same path a real
// manifest would.
func parseOne(t *testing.T, yaml string) manifest.Resource {
	t.Helper()
	resources, err := manifest.Parse([]byte(yaml), "fixture.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 {
		t.Fatalf("fixture produced %d resources, want 1", len(resources))
	}
	return resources[0]
}

func ruleByID(id string) Rule {
	for _, r := range All() {
		if r.ID() == id {
			return r
		}
	}
	return nil
}

func TestRegistryHasNoDuplicateIDs(t *testing.T) {
	seen := map[string]bool{}
	all := All()
	if len(all) != 10 {
		t.Fatalf("got %d rules, want 10", len(all))
	}
	for _, r := range all {
		if seen[r.ID()] {
			t.Fatalf("duplicate rule ID %q", r.ID())
		}
		seen[r.ID()] = true
	}
}
