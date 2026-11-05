package kubernetes_test

import (
	"testing"

	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
)

func TestCoverageRequiresEveryPermissionWithoutFiniteWildcardExpansion(t *testing.T) {
	rule := func(scope, resource string, verbs ...string) kube.ScopedRule {
		return kube.ScopedRule{Namespace: scope, Rule: kube.Rule{APIGroups: []string{""}, Resources: []string{resource}, Verbs: verbs}}
	}
	named := func(r kube.ScopedRule, names ...string) kube.ScopedRule { r.Rule.ResourceNames = names; return r }
	url := func(pattern string) kube.ScopedRule {
		return kube.ScopedRule{Rule: kube.Rule{Verbs: []string{"get"}, NonResourceURLs: []string{pattern}}}
	}
	cases := []struct {
		name       string
		have, want []kube.ScopedRule
		covered    bool
	}{
		{"union of verbs", []kube.ScopedRule{rule("finance", "pods", "get"), rule("finance", "pods", "list")}, []kube.ScopedRule{rule("finance", "pods", "get", "list")}, true},
		{"missing verb", []kube.ScopedRule{rule("finance", "pods", "get")}, []kube.ScopedRule{rule("finance", "pods", "get", "list")}, false},
		{"global covers namespace", []kube.ScopedRule{rule("", "pods", "get")}, []kube.ScopedRule{rule("finance", "pods", "get")}, true},
		{"namespace never covers global", []kube.ScopedRule{rule("finance", "pods", "get"), rule("wallet", "pods", "get")}, []kube.ScopedRule{rule("", "pods", "get")}, false},
		{"resource wildcard", []kube.ScopedRule{rule("finance", "*", "*")}, []kube.ScopedRule{rule("finance", "pods", "get")}, true},
		{"finite resources do not cover future", []kube.ScopedRule{rule("finance", "pods", "get"), rule("finance", "secrets", "get")}, []kube.ScopedRule{rule("finance", "*", "get")}, false},
		{"finite verbs do not cover future", []kube.ScopedRule{rule("finance", "pods", "get", "list", "watch")}, []kube.ScopedRule{rule("finance", "pods", "*")}, false},
		{"subresource wildcard", []kube.ScopedRule{rule("finance", "*/scale", "update")}, []kube.ScopedRule{rule("finance", "deployments/scale", "update")}, true},
		{"subresource not parent", []kube.ScopedRule{rule("finance", "*/scale", "update")}, []kube.ScopedRule{rule("finance", "deployments", "update")}, false},
		{"names union", []kube.ScopedRule{named(rule("finance", "pods", "get"), "one"), named(rule("finance", "pods", "get"), "two")}, []kube.ScopedRule{named(rule("finance", "pods", "get"), "one", "two")}, true},
		{"names do not cover unbounded", []kube.ScopedRule{named(rule("finance", "pods", "get"), "one", "two")}, []kube.ScopedRule{rule("finance", "pods", "get")}, false},
		{"name star is literal", []kube.ScopedRule{named(rule("finance", "pods", "get"), "*")}, []kube.ScopedRule{named(rule("finance", "pods", "get"), "one")}, false},
		{"named top level create grants nothing", nil, []kube.ScopedRule{named(rule("finance", "pods", "create"), "one")}, true},
		{"named token create remains meaningful", nil, []kube.ScopedRule{named(rule("finance", "serviceaccounts/token", "create"), "one")}, false},
		{"url prefix covers narrower", []kube.ScopedRule{url("/healthz/*")}, []kube.ScopedRule{url("/healthz/check*")}, true},
		{"url exact does not cover prefix", []kube.ScopedRule{url("/healthz/check")}, []kube.ScopedRule{url("/healthz/*")}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := kube.Covers(tc.have, tc.want)
			if err != nil || got != tc.covered {
				t.Fatalf("coverage=%v err=%v; want %v", got, err, tc.covered)
			}
		})
	}
	if covered, err := kube.Covers([]kube.ScopedRule{rule("", "*", "*")}, []kube.ScopedRule{{Rule: kube.Rule{Verbs: []string{"get"}}}}); err == nil || covered {
		t.Fatal("malformed requested rule was accepted")
	}
}

func TestIdentityNamesWithSpacesRetainExactMatching(t *testing.T) {
	r := kube.ScopedRule{Rule: kube.Rule{APIGroups: []string{""}, Resources: []string{"users"}, Verbs: []string{"impersonate"}, ResourceNames: []string{"Finance Approver"}}}
	for _, name := range []string{"Finance Approver", "finance approver", "Finance  Approver"} {
		got, err := r.Allows(kube.Permission{Resource: "users", Verb: "impersonate", Name: name})
		if err != nil || got != (name == "Finance Approver") {
			t.Fatal(name, got, err)
		}
	}
}
