package kubernetes_test

import (
	"testing"

	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func TestKubernetesRuleMatchingPreservesScopeNamesAndSubresources(t *testing.T) {
	cases := []struct {
		name       string
		rule       kube.ScopedRule
		permission kube.Permission
		allow      bool
	}{
		{"namespace", kube.ScopedRule{Namespace: "finance", Rule: kube.Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}, kube.Permission{Resource: "pods", Verb: "get", Namespace: "finance", Name: "reports"}, true},
		{"cross-namespace", kube.ScopedRule{Namespace: "finance", Rule: kube.Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}, kube.Permission{Resource: "pods", Verb: "get", Namespace: "wallet", Name: "reports"}, false},
		{"cluster-resource", kube.ScopedRule{Namespace: "finance", Rule: kube.Rule{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"}, Verbs: []string{"bind"}}}, kube.Permission{APIGroup: kube.RBACGroup, Resource: "clusterroles", Verb: "bind", Name: "cluster-admin"}, false},
		{"wildcard", kube.ScopedRule{Rule: kube.Rule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}, kube.Permission{APIGroup: "apps", Resource: "deployments", Subresource: "scale", Verb: "update", Namespace: "finance", Name: "reports"}, true},
		{"subresource-only-wildcard", kube.ScopedRule{Rule: kube.Rule{APIGroups: []string{"apps"}, Resources: []string{"*/scale"}, Verbs: []string{"update"}}}, kube.Permission{APIGroup: "apps", Resource: "deployments", Subresource: "scale", Verb: "update", Namespace: "finance"}, true},
		{"unsupported-resource-glob-is-literal", kube.ScopedRule{Rule: kube.Rule{APIGroups: []string{""}, Resources: []string{"pods/*"}, Verbs: []string{"create"}}}, kube.Permission{Resource: "pods", Subresource: "exec", Verb: "create", Namespace: "finance", Name: "reports"}, false},
		{"parent-does-not-grant-subresource", kube.ScopedRule{Rule: kube.Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}, kube.Permission{Resource: "pods", Subresource: "log", Verb: "get", Namespace: "finance", Name: "reports"}, false},
		{"named-resource", kube.ScopedRule{Rule: kube.Rule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}, ResourceNames: []string{"reports"}}}, kube.Permission{Resource: "secrets", Verb: "get", Namespace: "finance", Name: "reports"}, true},
		{"other-resource-name", kube.ScopedRule{Rule: kube.Rule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}, ResourceNames: []string{"reports"}}}, kube.Permission{Resource: "secrets", Verb: "get", Namespace: "finance", Name: "wallet"}, false},
		{"resource-name-star-is-literal", kube.ScopedRule{Rule: kube.Rule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}, ResourceNames: []string{"*"}}}, kube.Permission{Resource: "secrets", Verb: "get", Namespace: "finance", Name: "reports"}, false},
		{"named-top-level-create", kube.ScopedRule{Rule: kube.Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}, ResourceNames: []string{"reports"}}}, kube.Permission{Resource: "pods", Verb: "create", Namespace: "finance", Name: "reports"}, false},
		{"named-token-create", kube.ScopedRule{Namespace: "finance", Rule: kube.Rule{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, Verbs: []string{"create"}, ResourceNames: []string{"reports"}}}, kube.Permission{Resource: "serviceaccounts", Subresource: "token", Verb: "create", Namespace: "finance", Name: "reports"}, true},
		{"named-list-requires-selector", kube.ScopedRule{Rule: kube.Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}, ResourceNames: []string{"reports"}}}, kube.Permission{Resource: "pods", Verb: "list", Namespace: "finance"}, false},
		{"named-list-selector", kube.ScopedRule{Rule: kube.Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}, ResourceNames: []string{"reports"}}}, kube.Permission{Resource: "pods", Verb: "list", Namespace: "finance", Name: "reports"}, true},
		{"non-resource-prefix", kube.ScopedRule{Rule: kube.Rule{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz/*"}}}, kube.Permission{Verb: "get", NonResourceURL: "/healthz/ready"}, true},
		{"non-resource-prefix-boundary", kube.ScopedRule{Rule: kube.Rule{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz/*"}}}, kube.Permission{Verb: "get", NonResourceURL: "/healthz-admin"}, false},
		{"namespaced-binding-not-non-resource", kube.ScopedRule{Namespace: "finance", Rule: kube.Rule{Verbs: []string{"get"}, NonResourceURLs: []string{"*"}}}, kube.Permission{Verb: "get", NonResourceURL: "/healthz"}, false},
		{"api-group-is-not-resource-prefix", kube.ScopedRule{Rule: kube.Rule{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"update"}}}, kube.Permission{APIGroup: "extensions", Resource: "deployments", Verb: "update", Namespace: "finance"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.rule.Allows(tc.permission)
			if err != nil || got != tc.allow {
				t.Fatal("authorization mismatch", got, err)
			}
		})
	}
	if allowed, err := kube.Allows([]kube.ScopedRule{cases[0].rule, {Rule: kube.Rule{Resources: []string{"pods"}, Verbs: []string{"*"}}}}, cases[0].permission); err == nil || allowed {
		t.Fatal("malformed trailing rule was ignored after allow")
	}
}

func TestKubernetesSelectorsIncludeMissingNotInKeysAndRejectUnknownOperators(t *testing.T) {
	labels := map[string]string{"team": "finance", "environment": "demo"}
	for _, selector := range []kube.Selector{
		{MatchLabels: map[string]string{"team": "finance"}},
		{MatchExpressions: []kube.SelectorRequirement{{Key: "team", Operator: "In", Values: []string{"finance", "wallet"}}}},
		{MatchExpressions: []kube.SelectorRequirement{{Key: "absent", Operator: "NotIn", Values: []string{"wallet"}}}},
		{MatchExpressions: []kube.SelectorRequirement{{Key: "environment", Operator: "Exists"}, {Key: "absent", Operator: "DoesNotExist"}}},
	} {
		if match, err := selector.Matches(labels); err != nil || !match {
			t.Fatal("valid selector", match, err)
		}
	}
	for _, selector := range []kube.Selector{
		{MatchExpressions: []kube.SelectorRequirement{{Key: "team", Operator: "In"}}},
		{MatchExpressions: []kube.SelectorRequirement{{Key: "team", Operator: "Exists", Values: []string{"finance"}}}},
		{MatchExpressions: []kube.SelectorRequirement{{Key: "team", Operator: "Unknown"}}},
	} {
		if _, err := selector.Matches(labels); err == nil {
			t.Fatal("malformed/unknown selector accepted")
		}
	}
}

func TestKubernetesMutationBindsUIDOpaqueVersionAndImmutableRoleReference(t *testing.T) {
	before := kube.Object{Kind: "RoleBinding", Namespace: "finance", Name: "review", UID: "original-uid", ResourceVersion: "opaque/rv:17", RoleKind: "Role", RoleName: "reader", Subjects: []kube.Subject{{Kind: "User", Name: "alice"}}}
	after := before
	after.Subjects = []kube.Subject{{Kind: "User", Name: "alice"}, {Kind: "User", Name: "bob"}}
	m := kube.Mutation{Cluster: "local-cluster", Connector: "kubernetes", Operation: "UPDATE", Before: &before, After: &after, ObjectDigest: ports.Digest{1}, OldObjectDigest: ports.Digest{2}}
	if err := m.Validate(); err != nil {
		t.Fatal("valid exact update", err)
	}
	for _, change := range []func(*kube.Object){func(o *kube.Object) { o.Namespace = "wallet" }, func(o *kube.Object) { o.UID = "replacement-uid" }, func(o *kube.Object) { o.ResourceVersion = "opaque/rv:18" }, func(o *kube.Object) { o.RoleName = "admin" }, func(o *kube.Object) { o.Kind = "ClusterRoleBinding" }} {
		changed := after
		change(&changed)
		input := m
		input.After = &changed
		if input.Validate() == nil {
			t.Fatal("mismatched identity/precondition admitted")
		}
	}
	create := after
	create.UID = ""
	create.ResourceVersion = ""
	if err := (kube.Mutation{Cluster: "local-cluster", Connector: "kubernetes", Operation: "CREATE", After: &create, ObjectDigest: ports.Digest{1}}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (kube.Mutation{Cluster: "local-cluster", Connector: "kubernetes", Operation: "DELETE", Before: &before, ObjectDigest: ports.Digest{1}, OldObjectDigest: ports.Digest{2}}).Validate(); err != nil {
		t.Fatal(err)
	}
	m.Operation = "CONNECT"
	if m.Validate() == nil {
		t.Fatal("unknown mutation became a reduction")
	}
}
