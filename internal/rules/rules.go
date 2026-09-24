// Package rules holds kubeshield's checks and the machinery that runs
// them.
//
// Unlike a Terraform plan, a Kubernetes manifest has no "not known until
// apply" attribute -- every field present is a concrete, final value, so
// there is no third "indeterminate" outcome to make room for here. A
// rule either finds the problem (Fail) or it doesn't (silently: Pass is
// the absence of a Finding, never asserted as its own value).
package rules

import (
	"fmt"

	"github.com/sriharifortitude/kubeshield/internal/manifest"
)

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
)

var severityOrder = map[Severity]int{Low: 0, Medium: 1, High: 2, Critical: 3}

// AtLeast reports whether s is at or above threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	return severityOrder[s] >= severityOrder[threshold]
}

// Finding is one rule's verdict against one resource (and, where the
// problem is scoped to one container, that container too).
type Finding struct {
	RuleID      string
	Severity    Severity
	File        string
	Kind        string
	Name        string
	Namespace   string
	Container   string // empty when the finding is about the resource as a whole
	Message     string
	Remediation string
}

// Rule inspects every resource and reports the ones it has an opinion
// about.
type Rule interface {
	ID() string
	Severity() Severity
	Description() string
	Check(resources []manifest.Resource) []Finding
}

var registry []Rule

func register(r Rule) {
	for _, existing := range registry {
		if existing.ID() == r.ID() {
			panic(fmt.Sprintf("rule ID %q registered twice", r.ID()))
		}
	}
	registry = append(registry, r)
}

// All returns every built-in rule, in registration order.
func All() []Rule {
	out := make([]Rule, len(registry))
	copy(out, registry)
	return out
}

// RunAll executes every rule and returns every finding, in rule order.
func RunAll(resources []manifest.Resource) []Finding {
	var out []Finding
	for _, r := range All() {
		out = append(out, r.Check(resources)...)
	}
	return out
}

// eachContainer runs check against every container and init container of
// every resource that has a pod spec, and wraps whatever it flags into a
// Finding for id/severity/remediation -- every container-scoped rule in
// this package is this loop plus one predicate. check receives the
// owning resource too, because a container-level securityContext field
// left unset falls back to the pod-level one, not to a hardcoded
// default.
func eachContainer(resources []manifest.Resource, id string, severity Severity, remediation string, check func(manifest.Resource, manifest.Container) (bool, string)) []Finding {
	var out []Finding
	for _, r := range resources {
		containers := append(append([]manifest.Container{}, r.Containers...), r.InitContainers...)
		for _, c := range containers {
			if bad, msg := check(r, c); bad {
				out = append(out, Finding{
					RuleID: id, Severity: severity, Kind: r.Kind, Name: r.Name, Namespace: r.Namespace,
					File: r.File, Container: c.Name, Message: msg, Remediation: remediation,
				})
			}
		}
	}
	return out
}

// containerSecurityContext returns the container's own securityContext
// map, falling back to the pod-level one (spec.securityContext) when the
// container has none -- Kubernetes applies the same fallback when
// deciding the effective value of a field like runAsNonRoot.
func containerSecurityContext(pod manifest.Resource, c manifest.Container) map[string]any {
	if sc, ok := manifest.NestedMap(c.Raw, "securityContext"); ok {
		return sc
	}
	if sc, ok := manifest.NestedMap(pod.PodSpec, "securityContext"); ok {
		return sc
	}
	return nil
}
