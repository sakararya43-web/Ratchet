package kubernetes_test

import (
	"errors"
	"fmt"
	"testing"

	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func state() kube.State {
	return kube.State{Cluster: "cluster", ResourceVersion: "opaque/list-1", Complete: true, Namespaces: []string{"finance", "wallet"}, Principals: []kube.Principal{{ID: "alice", Kind: "User", Name: "alice", Groups: []string{"finance-readers"}}, {ID: "worker", Kind: "ServiceAccount", Name: "worker", Namespace: "wallet"}}, Objects: []kube.Object{
		{Kind: "ClusterRole", Name: "reader", UID: "role-1", ResourceVersion: "rv-A", Rules: []kube.Rule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}},
		{Kind: "RoleBinding", Name: "read", Namespace: "finance", UID: "binding-1", ResourceVersion: "rv-B", RoleKind: "ClusterRole", RoleName: "reader", Subjects: []kube.Subject{{Kind: "Group", Name: "finance-readers"}}},
	}}
}

func TestEffectiveRulesResolveNamespacedClusterRolesAndServiceAccountGroups(t *testing.T) {
	s := state()
	rules, err := s.EffectiveRules("alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{"finance", "wallet", ""} {
		allowed, err := kube.Allows(rules, kube.Permission{Resource: "pods", Verb: "get", Namespace: ns, Name: "report"})
		if err != nil || allowed != (ns == "finance") {
			t.Fatal("namespace escaped", ns, allowed, err)
		}
	}
	s.Objects = append(s.Objects, kube.Object{Kind: "ClusterRoleBinding", Name: "workers", UID: "binding-2", ResourceVersion: "rv-C", RoleKind: "ClusterRole", RoleName: "reader", Subjects: []kube.Subject{{Kind: "Group", Name: "system:serviceaccounts:wallet"}}})
	rules, err = s.EffectiveRules("worker")
	if err != nil {
		t.Fatal(err)
	}
	if allowed, err := kube.Allows(rules, kube.Permission{Resource: "pods", Verb: "get", Namespace: "finance"}); err != nil || !allowed {
		t.Fatal("service account default groups were lost", err)
	}
	s.Complete = false
	if _, err := s.EffectiveRules("alice"); err == nil {
		t.Fatal("incomplete group/identity roster accepted")
	}
}

func TestAggregationResolvesTransitiveCyclesWithoutInventingAuthority(t *testing.T) {
	s := state()
	s.Objects[0].Rules = nil
	s.Objects[0].Aggregation = []kube.Selector{{MatchLabels: map[string]string{"aggregate": "reader"}}}
	s.Objects = append(s.Objects,
		kube.Object{Kind: "ClusterRole", Name: "leaf", UID: "leaf", ResourceVersion: "rv-L", Labels: map[string]string{"aggregate": "reader"}, Rules: []kube.Rule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}},
		kube.Object{Kind: "ClusterRole", Name: "cycle-a", UID: "cycle-a", ResourceVersion: "rv-CA", Labels: map[string]string{"cycle": "a"}, Aggregation: []kube.Selector{{MatchLabels: map[string]string{"cycle": "b"}}}},
		kube.Object{Kind: "ClusterRole", Name: "cycle-b", UID: "cycle-b", ResourceVersion: "rv-CB", Labels: map[string]string{"cycle": "b"}, Aggregation: []kube.Selector{{MatchLabels: map[string]string{"cycle": "a"}}}},
	)
	rules, err := s.EffectiveRules("alice")
	if err != nil {
		t.Fatal(err)
	}
	if allow, err := kube.Allows(rules, kube.Permission{Resource: "pods", Verb: "get", Namespace: "finance"}); err != nil || !allow {
		t.Fatal("aggregate did not inherit selected rules", err)
	}
	resolved, err := s.RoleRules()
	if err != nil || len(resolved["ClusterRole//cycle-a"]) != 0 || len(resolved["ClusterRole//cycle-b"]) != 0 {
		t.Fatal("cycle manufactured authority", err)
	}
}

func TestDeletingRoleLeavesInertBindingAndProposalDoesNotMutateObservation(t *testing.T) {
	s := state()
	role := s.Objects[0]
	after, err := s.After(kube.Mutation{Cluster: "cluster", Connector: "source", Operation: "DELETE", Before: &role, ObjectDigest: ports.Digest{1}, OldObjectDigest: ports.Digest{2}})
	if err != nil {
		t.Fatal("valid dangling binding rejected", err)
	}
	rules, err := after.EffectiveRules("alice")
	if err != nil || len(rules) != 0 {
		t.Fatal("missing role still grants permission", err)
	}
	if len(s.Objects) != 2 || len(after.Objects) != 1 {
		t.Fatal("proposal mutated original objects")
	}
	role.UID = ""
	role.ResourceVersion = ""
	created, err := after.After(kube.Mutation{Cluster: "cluster", Connector: "source", Operation: "CREATE", After: &role, ObjectDigest: ports.Digest{3}})
	if err != nil {
		t.Fatal(err)
	}
	rules, err = created.EffectiveRules("alice")
	if err != nil || len(rules) != 1 {
		t.Fatal("creating referenced role did not activate old binding", err)
	}
	created.Objects[1].Rules[0].Verbs[0] = "delete"
	if s.Objects[0].Rules[0].Verbs[0] != "get" {
		t.Fatal("proposal retained caller-owned arrays")
	}
}

func TestAggregationWorkBoundRefusesIncompleteAuthorityAndResultsAreDetached(t *testing.T) {
	s := state()
	rules, err := s.EffectiveRules("alice")
	if err != nil {
		t.Fatal(err)
	}
	rules[0].Rule.Verbs[0] = "delete"
	if s.Objects[0].Rules[0].Verbs[0] != "get" {
		t.Fatal("resolved rule aliases normalized observation")
	}
	s.Objects = nil
	for i := range 1500 {
		name := fmt.Sprintf("agg-%04d", i)
		s.Objects = append(s.Objects, kube.Object{Kind: "ClusterRole", Name: name, UID: name, ResourceVersion: "opaque", Aggregation: []kube.Selector{{}}})
	}
	if _, err := s.RoleRules(); !errors.Is(err, kube.ErrUnsupported) {
		t.Fatal("oversized aggregation returned an apparently complete rule set", err)
	}
}
