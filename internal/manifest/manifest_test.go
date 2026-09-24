package manifest

import "testing"

func TestParseSkipsEmptyDocumentsAndThoseWithNoKind(t *testing.T) {
	data := []byte(`---
---
just: a map, no kind field
---
kind: Pod
apiVersion: v1
metadata:
  name: web
spec:
  containers:
    - name: app
      image: example/app:1.0
`)
	resources, err := Parse(data, "fixture.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 {
		t.Fatalf("got %d resources, want 1", len(resources))
	}
	if resources[0].Kind != "Pod" || resources[0].Name != "web" {
		t.Errorf("got %+v", resources[0])
	}
}

func TestParseReturnsAnErrorForInvalidYAML(t *testing.T) {
	if _, err := Parse([]byte("kind: [this is not valid: yaml"), "bad.yaml"); err == nil {
		t.Fatal("expected an error for malformed YAML")
	}
}

func TestParseExtractsNamespaceWhenPresent(t *testing.T) {
	data := []byte(`kind: Pod
apiVersion: v1
metadata:
  name: web
  namespace: prod
spec: {}
`)
	resources, err := Parse(data, "fixture.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if resources[0].Namespace != "prod" {
		t.Errorf("Namespace = %q, want prod", resources[0].Namespace)
	}
}

func TestPodSpecAndContainersForABarePod(t *testing.T) {
	data := []byte(`kind: Pod
apiVersion: v1
metadata:
  name: web
spec:
  hostNetwork: true
  containers:
    - name: app
      image: example/app:1.0
  initContainers:
    - name: migrate
      image: example/migrate:1.0
`)
	resources, err := Parse(data, "fixture.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := resources[0]
	if r.PodSpec == nil {
		t.Fatal("PodSpec is nil, want the spec map")
	}
	if hostNetwork, _ := NestedBool(r.PodSpec, "hostNetwork"); !hostNetwork {
		t.Error("hostNetwork not readable from PodSpec")
	}
	if len(r.Containers) != 1 || r.Containers[0].Name != "app" {
		t.Errorf("Containers = %+v", r.Containers)
	}
	if len(r.InitContainers) != 1 || r.InitContainers[0].Name != "migrate" {
		t.Errorf("InitContainers = %+v", r.InitContainers)
	}
}

func TestPodSpecForADeploymentIsNestedUnderTemplate(t *testing.T) {
	data := []byte(`kind: Deployment
apiVersion: apps/v1
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: app
          image: example/app:1.0
`)
	resources, err := Parse(data, "fixture.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := resources[0]
	if len(r.Containers) != 1 || r.Containers[0].Name != "app" {
		t.Errorf("Containers = %+v, want one container named app", r.Containers)
	}
}

func TestPodSpecForACronJobIsNestedTwiceUnderJobTemplate(t *testing.T) {
	data := []byte(`kind: CronJob
apiVersion: batch/v1
metadata:
  name: nightly
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: app
              image: example/app:1.0
`)
	resources, err := Parse(data, "fixture.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := resources[0]
	if len(r.Containers) != 1 || r.Containers[0].Name != "app" {
		t.Errorf("Containers = %+v, want one container named app", r.Containers)
	}
}

func TestKindsWithNoPodSpecHaveANilPodSpecAndNoContainers(t *testing.T) {
	data := []byte(`kind: Service
apiVersion: v1
metadata:
  name: web
spec:
  ports:
    - port: 80
`)
	resources, err := Parse(data, "fixture.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := resources[0]
	if r.PodSpec != nil {
		t.Errorf("PodSpec = %+v, want nil for a Service", r.PodSpec)
	}
	if r.Containers != nil {
		t.Errorf("Containers = %+v, want nil", r.Containers)
	}
}

func TestParseHandlesMultipleResourcesInOneFile(t *testing.T) {
	data := []byte(`kind: Deployment
apiVersion: apps/v1
metadata:
  name: web
spec:
  template:
    spec:
      containers: [{name: app, image: example/app:1.0}]
---
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: web-role
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
`)
	resources, err := Parse(data, "fixture.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 2 {
		t.Fatalf("got %d resources, want 2", len(resources))
	}
	if resources[0].Kind != "Deployment" || resources[1].Kind != "Role" {
		t.Errorf("got kinds %s, %s", resources[0].Kind, resources[1].Kind)
	}
}
