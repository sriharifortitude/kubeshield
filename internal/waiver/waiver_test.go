package waiver

import (
	"strings"
	"testing"
	"time"

	"github.com/sriharifortitude/kubeshield/internal/rules"
)

func TestParseRequiresEveryField(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"missing rule", `waivers:
  - kind: Pod
    name: web
    reason: test
    expires: "2030-01-01"`, "rule"},
		{"missing kind", `waivers:
  - rule: run-as-root
    name: web
    reason: test
    expires: "2030-01-01"`, "kind"},
		{"missing name", `waivers:
  - rule: run-as-root
    kind: Pod
    reason: test
    expires: "2030-01-01"`, "name"},
		{"missing reason", `waivers:
  - rule: run-as-root
    kind: Pod
    name: web
    expires: "2030-01-01"`, "reason"},
		{"missing expires", `waivers:
  - rule: run-as-root
    kind: Pod
    name: web
    reason: test`, "expires"},
		{"malformed expires", `waivers:
  - rule: run-as-root
    kind: Pod
    name: web
    reason: test
    expires: "next tuesday"`, "expires"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.yaml))
			if err == nil {
				t.Fatalf("Parse(%q) succeeded, want an error", c.yaml)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestParseAcceptsAWellFormedWaiver(t *testing.T) {
	yaml := `waivers:
  - rule: run-as-root
    kind: Pod
    namespace: prod
    name: legacy-worker
    reason: pre-dates the policy, migration ticket JIRA-1
    expires: "2030-01-01"
`
	f, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Waivers) != 1 {
		t.Fatalf("got %d waivers, want 1", len(f.Waivers))
	}
}

func TestApplyMatchesOnRuleKindNamespaceAndNameExactly(t *testing.T) {
	f := &File{Waivers: []Entry{{
		Rule: "run-as-root", Kind: "Pod", Namespace: "prod", Name: "legacy-worker",
		Reason: "test", Expires: "2030-01-01",
	}}}
	today := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	match := rules.Finding{RuleID: "run-as-root", Kind: "Pod", Namespace: "prod", Name: "legacy-worker"}
	if outcome, entry := f.Apply(match, today); outcome != Waived || entry == nil {
		t.Fatalf("got %v, %v, want Waived", outcome, entry)
	}

	wrongNamespace := rules.Finding{RuleID: "run-as-root", Kind: "Pod", Namespace: "staging", Name: "legacy-worker"}
	if outcome, _ := f.Apply(wrongNamespace, today); outcome != NotWaived {
		t.Fatalf("got %v, want NotWaived (different namespace)", outcome)
	}

	wrongRule := rules.Finding{RuleID: "privileged-container", Kind: "Pod", Namespace: "prod", Name: "legacy-worker"}
	if outcome, _ := f.Apply(wrongRule, today); outcome != NotWaived {
		t.Fatalf("got %v, want NotWaived (different rule)", outcome)
	}
}

func TestApplyReportsExpiredSeparatelyFromWaived(t *testing.T) {
	f := &File{Waivers: []Entry{{
		Rule: "run-as-root", Kind: "Pod", Name: "legacy-worker",
		Reason: "test", Expires: "2026-06-15",
	}}}
	finding := rules.Finding{RuleID: "run-as-root", Kind: "Pod", Name: "legacy-worker"}

	dayBefore := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	if outcome, _ := f.Apply(finding, dayBefore); outcome != Waived {
		t.Errorf("day before expiry: got %v, want Waived", outcome)
	}

	expiryDay := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	if outcome, _ := f.Apply(finding, expiryDay); outcome != Waived {
		t.Errorf("expiry day itself: got %v, want Waived", outcome)
	}

	dayAfter := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	if outcome, _ := f.Apply(finding, dayAfter); outcome != Expired {
		t.Errorf("day after expiry: got %v, want Expired", outcome)
	}
}
