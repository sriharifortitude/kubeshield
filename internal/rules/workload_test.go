package rules

import (
	"testing"

	"github.com/sriharifortitude/kubeshield/internal/manifest"
)

func check(t *testing.T, ruleID, yaml string) []Finding {
	t.Helper()
	rule := ruleByID(ruleID)
	if rule == nil {
		t.Fatalf("no registered rule %q", ruleID)
	}
	return rule.Check([]manifest.Resource{parseOne(t, yaml)})
}

func TestPrivilegedContainer(t *testing.T) {
	bad := check(t, "privileged-container", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - {name: app, image: example/app:1.0, securityContext: {privileged: true}}
`)
	if len(bad) != 1 {
		t.Fatalf("got %d findings, want 1", len(bad))
	}

	good := check(t, "privileged-container", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - {name: app, image: example/app:1.0, securityContext: {privileged: false}}
`)
	if len(good) != 0 {
		t.Fatalf("got %d findings, want 0", len(good))
	}
}

func TestAllowPrivilegeEscalation(t *testing.T) {
	unset := check(t, "allow-privilege-escalation", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - {name: app, image: example/app:1.0}
`)
	if len(unset) != 1 {
		t.Fatalf("unset field: got %d findings, want 1 (Kubernetes defaults it to true)", len(unset))
	}

	explicitTrue := check(t, "allow-privilege-escalation", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - {name: app, image: example/app:1.0, securityContext: {allowPrivilegeEscalation: true}}
`)
	if len(explicitTrue) != 1 {
		t.Fatalf("explicit true: got %d findings, want 1", len(explicitTrue))
	}

	good := check(t, "allow-privilege-escalation", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - {name: app, image: example/app:1.0, securityContext: {allowPrivilegeEscalation: false}}
`)
	if len(good) != 0 {
		t.Fatalf("got %d findings, want 0", len(good))
	}
}

func TestDangerousCapabilities(t *testing.T) {
	bad := check(t, "dangerous-capabilities-added", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - name: app
      image: example/app:1.0
      securityContext:
        capabilities:
          add: ["NET_BIND_SERVICE", "SYS_ADMIN"]
`)
	if len(bad) != 1 {
		t.Fatalf("got %d findings, want 1", len(bad))
	}

	good := check(t, "dangerous-capabilities-added", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - name: app
      image: example/app:1.0
      securityContext:
        capabilities:
          add: ["NET_BIND_SERVICE"]
`)
	if len(good) != 0 {
		t.Fatalf("got %d findings, want 0 (NET_BIND_SERVICE alone is not on the dangerous list)", len(good))
	}
}

func TestRunAsRootFallsBackToThePodLevelSecurityContext(t *testing.T) {
	neitherSet := check(t, "run-as-root", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - {name: app, image: example/app:1.0}
`)
	if len(neitherSet) != 1 {
		t.Fatalf("got %d findings, want 1", len(neitherSet))
	}

	podLevel := check(t, "run-as-root", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  securityContext: {runAsNonRoot: true}
  containers:
    - {name: app, image: example/app:1.0}
`)
	if len(podLevel) != 0 {
		t.Fatalf("got %d findings, want 0 (pod-level runAsNonRoot should satisfy the container)", len(podLevel))
	}

	containerLevel := check(t, "run-as-root", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - {name: app, image: example/app:1.0, securityContext: {runAsNonRoot: true}}
`)
	if len(containerLevel) != 0 {
		t.Fatalf("got %d findings, want 0", len(containerLevel))
	}
}

// Regression test for a real false positive: grainops' Helm chart sets
// runAsNonRoot at the pod level and other fields (allowPrivilegeEscalation,
// readOnlyRootFilesystem) on the container itself. An earlier
// implementation picked the container's securityContext map as a whole
// the moment it existed at all, and so stopped looking at the pod's
// runAsNonRoot the moment the container set anything of its own --
// Kubernetes actually merges every securityContext field independently.
func TestRunAsRootMergesPerFieldNotPerWholeSecurityContextMap(t *testing.T) {
	got := check(t, "run-as-root", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  securityContext: {runAsNonRoot: true}
  containers:
    - name: app
      image: example/app:1.0
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true}
`)
	if len(got) != 0 {
		t.Fatalf("got %d findings, want 0: the pod-level runAsNonRoot must still apply to a container with its own (partial) securityContext: %+v", len(got), got)
	}
}

func TestReadOnlyRootFilesystemMissing(t *testing.T) {
	bad := check(t, "read-only-root-filesystem-missing", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - {name: app, image: example/app:1.0}
`)
	if len(bad) != 1 {
		t.Fatalf("got %d findings, want 1", len(bad))
	}

	good := check(t, "read-only-root-filesystem-missing", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - {name: app, image: example/app:1.0, securityContext: {readOnlyRootFilesystem: true}}
`)
	if len(good) != 0 {
		t.Fatalf("got %d findings, want 0", len(good))
	}
}

func TestMissingResourceLimits(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{"neither set", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - {name: app, image: example/app:1.0}
`, 1},
		{"only cpu", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - name: app
      image: example/app:1.0
      resources:
        limits: {cpu: "500m"}
`, 1},
		{"both set", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - name: app
      image: example/app:1.0
      resources:
        limits: {cpu: "500m", memory: "256Mi"}
`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := check(t, "missing-resource-limits", c.yaml)
			if len(got) != c.want {
				t.Fatalf("got %d findings, want %d", len(got), c.want)
			}
		})
	}
}

func TestImageNotPinned(t *testing.T) {
	cases := []struct {
		name  string
		image string
		want  int
	}{
		{"no tag", "example/app", 1},
		{"latest tag", "example/app:latest", 1},
		{"specific tag", "example/app:1.4.2", 0},
		{"digest", "example/app@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 0},
		{"registry with a port, no tag", "registry.internal:5000/example/app", 1},
		{"registry with a port, tagged", "registry.internal:5000/example/app:1.0", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			yaml := `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - {name: app, image: "` + c.image + `"}
`
			got := check(t, "image-not-pinned", yaml)
			if len(got) != c.want {
				t.Fatalf("image %q: got %d findings, want %d: %+v", c.image, len(got), c.want, got)
			}
		})
	}
}

func TestContainerRulesAlsoCheckInitContainers(t *testing.T) {
	got := check(t, "privileged-container", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  initContainers:
    - {name: migrate, image: example/migrate:1.0, securityContext: {privileged: true}}
  containers:
    - {name: app, image: example/app:1.0}
`)
	if len(got) != 1 || got[0].Container != "migrate" {
		t.Fatalf("got %+v, want one finding naming the init container", got)
	}
}

func TestContainerRulesReachThroughADeploymentsTemplate(t *testing.T) {
	got := check(t, "privileged-container", `
kind: Deployment
apiVersion: apps/v1
metadata: {name: web}
spec:
  template:
    spec:
      containers:
        - {name: app, image: example/app:1.0, securityContext: {privileged: true}}
`)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}
