// Package manifest parses Kubernetes YAML manifests -- possibly several
// `---`-separated documents in one file -- into a normalized Resource
// that rules can inspect without each one re-deriving where a pod spec
// lives inside a Deployment vs a bare Pod vs a CronJob.
package manifest

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// Container is one container (or init container) in a pod spec, with
// just the fields the rules in this tool look at.
type Container struct {
	Name string
	Raw  map[string]any
}

// Resource is one parsed Kubernetes object.
type Resource struct {
	Kind       string
	APIVersion string
	Name       string
	Namespace  string
	File       string // the path it was read from, for a finding's location
	Raw        map[string]any

	// PodSpec is the map at spec / spec.template.spec / spec.jobTemplate.spec.template.spec,
	// nil for a Kind with no pod spec (a Role, a Service, ...).
	PodSpec        map[string]any
	Containers     []Container
	InitContainers []Container
}

// Parse reads every YAML document in data and returns the ones that
// decode to a Kubernetes object (a document that is empty, or has no
// "kind", is skipped rather than erroring -- a stray `---` at the top of
// a file is common and not malformed).
func Parse(data []byte, file string) ([]Resource, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	var resources []Resource
	for i := 0; ; i++ {
		var doc map[string]any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: document %d: %w", file, i+1, err)
		}
		if doc == nil {
			continue
		}
		kind, _ := doc["kind"].(string)
		if kind == "" {
			continue
		}
		resources = append(resources, build(doc, kind, file))
	}
	return resources, nil
}

func build(doc map[string]any, kind, file string) Resource {
	apiVersion, _ := doc["apiVersion"].(string)
	meta, _ := doc["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	namespace, _ := meta["namespace"].(string)

	r := Resource{Kind: kind, APIVersion: apiVersion, Name: name, Namespace: namespace, File: file, Raw: doc}
	r.PodSpec = podSpec(doc, kind)
	if r.PodSpec != nil {
		r.Containers = containersAt(r.PodSpec, "containers")
		r.InitContainers = containersAt(r.PodSpec, "initContainers")
	}
	return r
}

// podSpecPaths says, for each Kind that embeds a PodSpec, the key path
// to it. A bare Pod's spec IS the pod spec; a Deployment's is nested
// under a template; a CronJob's is nested twice.
var podSpecPaths = map[string][]string{
	"Pod":         {"spec"},
	"Deployment":  {"spec", "template", "spec"},
	"StatefulSet": {"spec", "template", "spec"},
	"DaemonSet":   {"spec", "template", "spec"},
	"ReplicaSet":  {"spec", "template", "spec"},
	"Job":         {"spec", "template", "spec"},
	"CronJob":     {"spec", "jobTemplate", "spec", "template", "spec"},
}

func podSpec(doc map[string]any, kind string) map[string]any {
	path, ok := podSpecPaths[kind]
	if !ok {
		return nil
	}
	cur := doc
	for _, key := range path {
		next, ok := cur[key].(map[string]any)
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

func containersAt(podSpec map[string]any, key string) []Container {
	list, ok := podSpec[key].([]any)
	if !ok {
		return nil
	}
	var out []Container
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		out = append(out, Container{Name: name, Raw: m})
	}
	return out
}
