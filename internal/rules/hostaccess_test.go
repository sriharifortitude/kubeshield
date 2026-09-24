package rules

import "testing"

func TestHostNamespace(t *testing.T) {
	cases := []struct {
		name  string
		field string
	}{
		{"hostNetwork", "hostNetwork"},
		{"hostPID", "hostPID"},
		{"hostIPC", "hostIPC"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			yaml := `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  ` + c.field + `: true
  containers:
    - {name: app, image: example/app:1.0}
`
			got := check(t, "host-namespace", yaml)
			if len(got) != 1 {
				t.Fatalf("got %d findings, want 1", len(got))
			}
		})
	}

	good := check(t, "host-namespace", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  containers:
    - {name: app, image: example/app:1.0}
`)
	if len(good) != 0 {
		t.Fatalf("got %d findings, want 0", len(good))
	}
}

func TestHostNamespaceFlagsEveryTrueFieldSeparately(t *testing.T) {
	got := check(t, "host-namespace", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  hostNetwork: true
  hostPID: true
  containers:
    - {name: app, image: example/app:1.0}
`)
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 (hostNetwork and hostPID)", len(got))
	}
}

func TestHostPathVolume(t *testing.T) {
	bad := check(t, "hostpath-volume", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  volumes:
    - name: docker-sock
      hostPath: {path: /var/run/docker.sock}
  containers:
    - {name: app, image: example/app:1.0}
`)
	if len(bad) != 1 {
		t.Fatalf("got %d findings, want 1", len(bad))
	}
	if bad[0].Message == "" {
		t.Error("expected a message naming the volume and path")
	}

	good := check(t, "hostpath-volume", `
kind: Pod
apiVersion: v1
metadata: {name: web}
spec:
  volumes:
    - name: cache
      emptyDir: {}
  containers:
    - {name: app, image: example/app:1.0}
`)
	if len(good) != 0 {
		t.Fatalf("got %d findings, want 0", len(good))
	}
}
