package rules

import (
	"fmt"
	"strings"

	"github.com/sriharifortitude/kubeshield/internal/manifest"
)

func init() {
	register(rbacWildcard{})
}

var rbacKinds = map[string]bool{"Role": true, "ClusterRole": true}

// --- rbac-wildcard -----------------------------------------------------------

type rbacWildcard struct{}

func (rbacWildcard) ID() string         { return "rbac-wildcard" }
func (rbacWildcard) Severity() Severity { return Critical }
func (rbacWildcard) Description() string {
	return "a Role or ClusterRole granting every verb, every resource, or every API group with a single \"*\""
}

func (r rbacWildcard) Check(resources []manifest.Resource) []Finding {
	var out []Finding
	for _, res := range resources {
		if !rbacKinds[res.Kind] {
			continue
		}
		rawRules, _ := res.Raw["rules"].([]any)
		for i, rr := range rawRules {
			ruleMap, ok := rr.(map[string]any)
			if !ok {
				continue
			}
			var wild []string
			for _, field := range []string{"verbs", "resources", "apiGroups"} {
				items, _ := ruleMap[field].([]any)
				for _, v := range manifest.StringSlice(items) {
					if v == "*" {
						wild = append(wild, field)
						break
					}
				}
			}
			if len(wild) == 0 {
				continue
			}
			out = append(out, Finding{
				RuleID: r.ID(), Severity: r.Severity(), Kind: res.Kind, Name: res.Name,
				Namespace: res.Namespace, File: res.File,
				Message:     fmt.Sprintf("rules[%d] uses a wildcard \"*\" in %s", i, strings.Join(wild, " and ")),
				Remediation: "list the specific verbs, resources and API groups the workload actually needs instead of \"*\"",
			})
		}
	}
	return out
}
