package rules

import (
	"fmt"

	"github.com/sriharifortitude/kubeshield/internal/manifest"
)

func init() {
	register(hostNamespace{})
	register(hostPathVolume{})
}

// --- host-namespace --------------------------------------------------------

var hostNamespaceFields = []string{"hostNetwork", "hostPID", "hostIPC"}

type hostNamespace struct{}

func (hostNamespace) ID() string         { return "host-namespace" }
func (hostNamespace) Severity() Severity { return Critical }
func (hostNamespace) Description() string {
	return "a pod sharing the host's network, process, or IPC namespace, stepping outside container isolation entirely"
}

func (r hostNamespace) Check(resources []manifest.Resource) []Finding {
	var out []Finding
	for _, res := range resources {
		if res.PodSpec == nil {
			continue
		}
		for _, field := range hostNamespaceFields {
			if v, ok := manifest.NestedBool(res.PodSpec, field); ok && v {
				out = append(out, Finding{
					RuleID: r.ID(), Severity: r.Severity(), Kind: res.Kind, Name: res.Name,
					Namespace: res.Namespace, File: res.File,
					Message:     fmt.Sprintf("spec.%s is true", field),
					Remediation: fmt.Sprintf("remove %s, or set it to false", field),
				})
			}
		}
	}
	return out
}

// --- hostpath-volume ---------------------------------------------------------

type hostPathVolume struct{}

func (hostPathVolume) ID() string         { return "hostpath-volume" }
func (hostPathVolume) Severity() Severity { return High }
func (hostPathVolume) Description() string {
	return "a pod mounting a path from the host filesystem, which can be used to read or write files outside the container"
}

func (r hostPathVolume) Check(resources []manifest.Resource) []Finding {
	var out []Finding
	for _, res := range resources {
		if res.PodSpec == nil {
			continue
		}
		volumes, _ := manifest.NestedSlice(res.PodSpec, "volumes")
		for _, v := range volumes {
			vm, ok := v.(map[string]any)
			if !ok {
				continue
			}
			hostPath, ok := manifest.NestedMap(vm, "hostPath")
			if !ok {
				continue
			}
			path, _ := hostPath["path"].(string)
			name, _ := vm["name"].(string)
			out = append(out, Finding{
				RuleID: r.ID(), Severity: r.Severity(), Kind: res.Kind, Name: res.Name,
				Namespace: res.Namespace, File: res.File,
				Message:     fmt.Sprintf("volume %q mounts hostPath %q", name, path),
				Remediation: "use a PersistentVolumeClaim, ConfigMap, Secret, or emptyDir instead of a hostPath volume",
			})
		}
	}
	return out
}
