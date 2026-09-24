package rules

import (
	"fmt"
	"strings"

	"github.com/sriharifortitude/kubeshield/internal/manifest"
)

func init() {
	register(privilegedContainer{})
	register(allowPrivilegeEscalation{})
	register(dangerousCapabilities{})
	register(runAsRoot{})
	register(readOnlyRootFilesystemMissing{})
	register(missingResourceLimits{})
	register(imageNotPinned{})
}

// --- privileged-container ---------------------------------------------

type privilegedContainer struct{}

func (privilegedContainer) ID() string         { return "privileged-container" }
func (privilegedContainer) Severity() Severity { return Critical }
func (privilegedContainer) Description() string {
	return "a container running as privileged, with full access to the host"
}

func (r privilegedContainer) Check(resources []manifest.Resource) []Finding {
	return eachContainer(resources, r.ID(), r.Severity(),
		"remove securityContext.privileged, or set it to false explicitly",
		func(_ manifest.Resource, c manifest.Container) (bool, string) {
			sc, _ := manifest.NestedMap(c.Raw, "securityContext")
			privileged, _ := manifest.NestedBool(sc, "privileged")
			if !privileged {
				return false, ""
			}
			return true, "securityContext.privileged is true"
		})
}

// --- allow-privilege-escalation ----------------------------------------

type allowPrivilegeEscalation struct{}

func (allowPrivilegeEscalation) ID() string         { return "allow-privilege-escalation" }
func (allowPrivilegeEscalation) Severity() Severity { return High }
func (allowPrivilegeEscalation) Description() string {
	return "a container that can gain more privileges than its parent process (the Kubernetes default when this field is left unset)"
}

func (r allowPrivilegeEscalation) Check(resources []manifest.Resource) []Finding {
	return eachContainer(resources, r.ID(), r.Severity(),
		"set securityContext.allowPrivilegeEscalation: false",
		func(_ manifest.Resource, c manifest.Container) (bool, string) {
			sc, _ := manifest.NestedMap(c.Raw, "securityContext")
			allowed, known := manifest.NestedBool(sc, "allowPrivilegeEscalation")
			if known && !allowed {
				return false, ""
			}
			if !known {
				return true, "allowPrivilegeEscalation is not set, which defaults to true"
			}
			return true, "allowPrivilegeEscalation is true"
		})
}

// --- dangerous-capabilities-added ---------------------------------------

var dangerousCaps = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "NET_ADMIN": true, "SYS_PTRACE": true,
	"SYS_MODULE": true, "SYS_RAWIO": true, "DAC_READ_SEARCH": true,
}

type dangerousCapabilities struct{}

func (dangerousCapabilities) ID() string         { return "dangerous-capabilities-added" }
func (dangerousCapabilities) Severity() Severity { return Critical }
func (dangerousCapabilities) Description() string {
	return "a container adding a Linux capability that grants effective root-equivalent power"
}

func (r dangerousCapabilities) Check(resources []manifest.Resource) []Finding {
	return eachContainer(resources, r.ID(), r.Severity(),
		"remove the capability from securityContext.capabilities.add, or drop to the minimum the process actually needs",
		func(_ manifest.Resource, c manifest.Container) (bool, string) {
			sc, _ := manifest.NestedMap(c.Raw, "securityContext")
			add, _ := manifest.NestedSlice(sc, "capabilities", "add")
			for _, cap := range manifest.StringSlice(add) {
				if dangerousCaps[cap] {
					return true, fmt.Sprintf("capabilities.add includes %s", cap)
				}
			}
			return false, ""
		})
}

// --- run-as-root ----------------------------------------------------------

type runAsRoot struct{}

func (runAsRoot) ID() string          { return "run-as-root" }
func (runAsRoot) Severity() Severity  { return Medium }
func (runAsRoot) Description() string { return "a container not required to run as a non-root user" }

func (r runAsRoot) Check(resources []manifest.Resource) []Finding {
	return eachContainer(resources, r.ID(), r.Severity(),
		"set securityContext.runAsNonRoot: true (at the container or pod level)",
		func(pod manifest.Resource, c manifest.Container) (bool, string) {
			sc := containerSecurityContext(pod, c)
			nonRoot, known := manifest.NestedBool(sc, "runAsNonRoot")
			if known && nonRoot {
				return false, ""
			}
			return true, "runAsNonRoot is not set to true, at either the container or pod level"
		})
}

// --- read-only-root-filesystem-missing -------------------------------------

type readOnlyRootFilesystemMissing struct{}

func (readOnlyRootFilesystemMissing) ID() string         { return "read-only-root-filesystem-missing" }
func (readOnlyRootFilesystemMissing) Severity() Severity { return Low }
func (readOnlyRootFilesystemMissing) Description() string {
	return "a container whose root filesystem is writable, when the workload may not need to write to it at all"
}

func (r readOnlyRootFilesystemMissing) Check(resources []manifest.Resource) []Finding {
	return eachContainer(resources, r.ID(), r.Severity(),
		"set securityContext.readOnlyRootFilesystem: true, and mount an emptyDir for any path that genuinely needs to be written",
		func(_ manifest.Resource, c manifest.Container) (bool, string) {
			sc, _ := manifest.NestedMap(c.Raw, "securityContext")
			readOnly, known := manifest.NestedBool(sc, "readOnlyRootFilesystem")
			if known && readOnly {
				return false, ""
			}
			return true, "readOnlyRootFilesystem is not set to true"
		})
}

// --- missing-resource-limits ------------------------------------------------

type missingResourceLimits struct{}

func (missingResourceLimits) ID() string         { return "missing-resource-limits" }
func (missingResourceLimits) Severity() Severity { return Medium }
func (missingResourceLimits) Description() string {
	return "a container with no CPU or memory limit, able to starve every other workload on its node"
}

func (r missingResourceLimits) Check(resources []manifest.Resource) []Finding {
	return eachContainer(resources, r.ID(), r.Severity(),
		"set resources.limits.cpu and resources.limits.memory",
		func(_ manifest.Resource, c manifest.Container) (bool, string) {
			limits, _ := manifest.NestedMap(c.Raw, "resources", "limits")
			_, hasCPU := limits["cpu"]
			_, hasMemory := limits["memory"]
			switch {
			case !hasCPU && !hasMemory:
				return true, "resources.limits has neither cpu nor memory set"
			case !hasCPU:
				return true, "resources.limits.cpu is not set"
			case !hasMemory:
				return true, "resources.limits.memory is not set"
			default:
				return false, ""
			}
		})
}

// --- image-not-pinned --------------------------------------------------------

type imageNotPinned struct{}

func (imageNotPinned) ID() string         { return "image-not-pinned" }
func (imageNotPinned) Severity() Severity { return Medium }
func (imageNotPinned) Description() string {
	return "a container image with no tag, the \"latest\" tag, or no digest -- what actually runs can change without this manifest changing"
}

func (r imageNotPinned) Check(resources []manifest.Resource) []Finding {
	return eachContainer(resources, r.ID(), r.Severity(),
		"pin the image to a digest (image@sha256:...) or at minimum a specific version tag, never :latest or an untagged reference",
		func(_ manifest.Resource, c manifest.Container) (bool, string) {
			image, ok := c.Raw["image"].(string)
			if !ok || image == "" {
				return false, "" // malformed manifest; not this rule's job to flag
			}
			tag, digest := parseImageRef(image)
			switch {
			case digest != "":
				return false, ""
			case tag == "":
				return true, fmt.Sprintf("image %q has no tag and no digest", image)
			case tag == "latest":
				return true, fmt.Sprintf("image %q uses the \"latest\" tag", image)
			default:
				return false, ""
			}
		})
}

// parseImageRef splits an image reference into its tag and digest parts
// (at most one is non-empty). It is not a full reference parser -- just
// enough to tell "pinned" from "not": a registry host may itself contain
// a colon (a port number), so only the segment after the last "/" is
// searched for the "@digest" or ":tag" that belongs to the image name.
func parseImageRef(image string) (tag, digest string) {
	name := image
	if i := strings.LastIndexByte(image, '/'); i >= 0 {
		name = image[i+1:]
	}
	if i := strings.IndexByte(name, '@'); i >= 0 {
		return "", name[i+1:]
	}
	if i := strings.IndexByte(name, ':'); i >= 0 {
		return name[i+1:], ""
	}
	return "", ""
}
