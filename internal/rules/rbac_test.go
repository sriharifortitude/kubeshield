package rules

import "testing"

func TestRBACWildcard(t *testing.T) {
	bad := check(t, "rbac-wildcard", `
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata: {name: everything}
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
`)
	if len(bad) != 1 {
		t.Fatalf("got %d findings, want 1", len(bad))
	}

	good := check(t, "rbac-wildcard", `
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata: {name: pod-reader}
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
`)
	if len(good) != 0 {
		t.Fatalf("got %d findings, want 0", len(good))
	}
}

func TestRBACWildcardChecksEveryRuleEntrySeparately(t *testing.T) {
	got := check(t, "rbac-wildcard", `
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata: {name: mixed}
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["*"]
`)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1 (only the second rules[] entry is wild)", len(got))
	}
}

func TestRBACWildcardIgnoresOtherKinds(t *testing.T) {
	got := check(t, "rbac-wildcard", `
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata: {name: binding}
roleRef: {kind: Role, name: pod-reader, apiGroup: rbac.authorization.k8s.io}
subjects:
  - kind: ServiceAccount
    name: default
`)
	if len(got) != 0 {
		t.Fatalf("got %d findings, want 0 (RoleBinding has no rules field)", len(got))
	}
}
