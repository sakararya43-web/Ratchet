package graph

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func kubeState() kube.State {
	return kube.State{Cluster: "test-cluster", ResourceVersion: "list/opaque-1", Complete: true, Namespaces: []string{"finance", "wallet"},
		Principals: []kube.Principal{{ID: "alice", Kind: "User", Name: "alice"}, {ID: "bob", Kind: "User", Name: "bob", Groups: []string{"approvers"}}, {ID: "worker", Kind: "ServiceAccount", Name: "worker", Namespace: "wallet"}},
		Resources:  []kube.APIResource{{Resource: "pods", Namespaced: true}, {Resource: "secrets", Namespaced: true}, {Resource: "nodes"}},
	}
}

func kubeRule(group, resource string, verbs ...string) kube.Rule {
	return kube.Rule{APIGroups: []string{group}, Resources: []string{resource}, Verbs: verbs}
}

func kubeRole(name, ns string, rules ...kube.Rule) kube.Object {
	kind := "ClusterRole"
	if ns != "" {
		kind = "Role"
	}
	return kube.Object{Kind: kind, Namespace: ns, Name: name, UID: kind + ":" + ns + ":" + name, ResourceVersion: "rv/one", Rules: rules}
}

func kubeBinding(name, ns string, role kube.Object, subjects ...kube.Subject) kube.Object {
	kind := "ClusterRoleBinding"
	if ns != "" {
		kind = "RoleBinding"
	}
	return kube.Object{Kind: kind, Name: name, Namespace: ns, UID: kind + ":" + ns + ":" + name, ResourceVersion: "rv/two", RoleKind: role.Kind, RoleName: role.Name, Subjects: subjects}
}

func kubeAssign(s *kube.State, name, ns string, rules ...kube.Rule) {
	r := kubeRole(name, ns, rules...)
	s.Objects = append(s.Objects, r, kubeBinding(name+"-binding", ns, r, kube.Subject{Kind: "User", Name: "alice"}))
}

func kubeCompile(t *testing.T, s kube.State) *Snapshot {
	t.Helper()
	snap, err := CompileKubernetes(44, s)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func kubeCan(t *testing.T, s kube.State, snap *Snapshot, principal string, match func(kube.Permission) bool) bool {
	t.Helper()
	atoms, err := kubeAtoms([]kube.State{s})
	if err != nil {
		t.Fatal(err)
	}
	r, err := snap.Reach(KubernetesNodeID(s.Cluster, "identity", principal))
	if err != nil {
		t.Fatal(err)
	}
	for signature, p := range atoms {
		if match(p) && slices.Contains(r.Powers, Power{NodeID: KubernetesNodeID(s.Cluster, "permission", signature), Action: p.Verb}) {
			return true
		}
	}
	return false
}

func kubeReads(resource, ns string) func(kube.Permission) bool {
	return func(p kube.Permission) bool { return p.Resource == resource && p.Verb == "get" && p.Namespace == ns }
}

func TestKubernetesProjectionScopesClusterRolesAndPreservesDeterminism(t *testing.T) {
	s := kubeState()
	role := kubeRole("reader", "", kubeRule("", "pods", "get"), kubeRule("", "nodes", "get"))
	s.Objects = []kube.Object{role, kubeBinding("read", "finance", role, kube.Subject{Kind: "User", Name: "alice"})}
	snap := kubeCompile(t, s)
	if !kubeCan(t, s, snap, "alice", kubeReads("pods", "finance")) || kubeCan(t, s, snap, "alice", kubeReads("pods", "wallet")) || kubeCan(t, s, snap, "alice", kubeReads("nodes", "")) {
		t.Fatal("namespaced ClusterRole authority escaped")
	}
	before, _ := json.Marshal(s)
	for range 5 {
		again := kubeCompile(t, s)
		if !reflect.DeepEqual(snap.Data(), again.Data()) {
			t.Fatal("projection is nondeterministic")
		}
	}
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("projection mutated observation")
	}
	s.Complete = false
	if _, err := CompileKubernetes(44, s); err == nil {
		t.Fatal("incomplete roster accepted")
	}
}

func TestKubernetesTokenRequestControlsOnlyTheNamedServiceAccount(t *testing.T) {
	for _, ns := range []string{"wallet", "finance"} {
		t.Run(ns, func(t *testing.T) {
			s := kubeState()
			token := kubeRule("", "serviceaccounts/token", "create")
			token.ResourceNames = []string{"worker"}
			kubeAssign(&s, "mint", ns, token)
			reader := kubeRole("secrets", "wallet", kubeRule("", "secrets", "get"))
			s.Objects = append(s.Objects, reader, kubeBinding("worker", "wallet", reader, kube.Subject{Kind: "ServiceAccount", Name: "worker", Namespace: "wallet"}))
			snap := kubeCompile(t, s)
			reach, err := snap.Reach(KubernetesNodeID(s.Cluster, "identity", "alice"))
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(reach.Controlled, KubernetesNodeID(s.Cluster, "identity", "worker")) != (ns == "wallet") {
				t.Fatal("token takeover escaped name/namespace")
			}
			if kubeCan(t, s, snap, "alice", kubeReads("secrets", "wallet")) != (ns == "wallet") {
				t.Fatal("token did not carry actual account's authority")
			}
		})
	}
}

func TestKubernetesBindRequiresBindingWriteAndBindOrCoveredPermissions(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		write, bind, wrongName bool
		want                   bool
	}{{"bind only", false, true, false, false}, {"write only", true, false, false, false}, {"both", true, true, false, true}, {"wrong role name", true, true, true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := kubeState()
			role := kubeRole("sensitive", "", kubeRule("", "secrets", "get"))
			s.Objects = append(s.Objects, role)
			rules := []kube.Rule{}
			if tc.write {
				rules = append(rules, kubeRule(kube.RBACGroup, "rolebindings", "create"))
			}
			if tc.bind {
				r := kubeRule(kube.RBACGroup, "clusterroles", "bind")
				r.ResourceNames = []string{"sensitive"}
				if tc.wrongName {
					r.ResourceNames = []string{"different"}
				}
				rules = append(rules, r)
			}
			kubeAssign(&s, "manager", "finance", rules...)
			snap := kubeCompile(t, s)
			if got := kubeCan(t, s, snap, "alice", kubeReads("secrets", "finance")); got != tc.want {
				t.Fatalf("can get secrets=%v; want %v", got, tc.want)
			}
			if kubeCan(t, s, snap, "alice", kubeReads("secrets", "wallet")) {
				t.Fatal("namespaced bind became global")
			}
		})
	}
}

func TestKubernetesEscalateRequiresEditingAnAccessibleRole(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		edit, escalate, bound bool
		want                  bool
	}{{"escalate only", false, true, true, false}, {"edit only", true, false, true, false}, {"unbound", true, true, false, false}, {"both bound", true, true, true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			s := kubeState()
			target := kubeRole("editable", "finance", kubeRule("", "pods", "get"))
			s.Objects = append(s.Objects, target)
			if tc.bound {
				s.Objects = append(s.Objects, kubeBinding("editable", "finance", target, kube.Subject{Kind: "User", Name: "alice"}))
			}
			rules := []kube.Rule{}
			for _, entry := range []struct {
				yes  bool
				verb string
			}{{tc.edit, "update"}, {tc.escalate, "escalate"}} {
				if entry.yes {
					r := kubeRule(kube.RBACGroup, "roles", entry.verb)
					r.ResourceNames = []string{"editable"}
					rules = append(rules, r)
				}
			}
			kubeAssign(&s, "editor", "finance", rules...)
			snap := kubeCompile(t, s)
			critical := kubeCan(t, s, snap, "alice", func(p kube.Permission) bool { return p.Namespace == "finance" && p.Verb == kubeFuture+"-verb" })
			if critical != tc.want {
				t.Fatalf("future wildcard authority=%v; want %v", critical, tc.want)
			}
		})
	}
}

func TestKubernetesImpersonationDoesNotInheritHumanDirectoryGroups(t *testing.T) {
	for _, withGroup := range []bool{false, true} {
		s := kubeState()
		user := kubeRule("", "users", "impersonate")
		user.ResourceNames = []string{"bob"}
		rules := []kube.Rule{user}
		if withGroup {
			r := kubeRule("", "groups", "impersonate")
			r.ResourceNames = []string{"approvers"}
			rules = append(rules, r)
		}
		kubeAssign(&s, "impersonator", "", rules...)
		reader := kubeRole("approver", "finance", kubeRule("", "secrets", "get"))
		s.Objects = append(s.Objects, reader, kubeBinding("approvers", "finance", reader, kube.Subject{Kind: "Group", Name: "approvers"}))
		snap := kubeCompile(t, s)
		if got := kubeCan(t, s, snap, "alice", kubeReads("secrets", "finance")); got != withGroup {
			t.Fatal("human groups inherited without group impersonation", got, withGroup)
		}
		r, err := snap.Reach(KubernetesNodeID(s.Cluster, "identity", "alice"))
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(r.Controlled, KubernetesNodeID(s.Cluster, "identity", "bob")) {
			t.Fatal("Kubernetes impersonation treated as human passkey compromise")
		}
	}
}

func TestKubernetesCreationOfUnobservedRoleCannotHideEscalation(t *testing.T) {
	for _, name := range []string{"", "not-yet-created"} {
		t.Run(name, func(t *testing.T) {
			s := kubeState()
			create := kubeRule(kube.RBACGroup, "roles", "create")
			escalate := kubeRule(kube.RBACGroup, "roles", "escalate")
			bind := kubeRule(kube.RBACGroup, "roles", "bind")
			if name != "" {
				escalate.ResourceNames = []string{name}
				bind.ResourceNames = []string{name}
			}
			kubeAssign(&s, "manager", "finance", create, escalate, bind, kubeRule(kube.RBACGroup, "rolebindings", "create"))
			snap := kubeCompile(t, s)
			if !kubeCan(t, s, snap, "alice", func(p kube.Permission) bool { return p.Namespace == "finance" && p.Verb == kubeFuture+"-verb" }) {
				t.Fatal("create+escalate+bind could create an unobserved privileged role")
			}
		})
	}
}

func TestKubernetesUpdatingBindingCannotChangeItsImmutableRoleReference(t *testing.T) {
	s := kubeState()
	low := kubeRole("low", "finance", kubeRule("", "pods", "get"))
	high := kubeRole("high", "finance", kubeRule("", "secrets", "get"))
	binding := kubeBinding("editable-binding", "finance", low, kube.Subject{Kind: "User", Name: "bob"})
	s.Objects = append(s.Objects, low, high, binding)
	update := kubeRule(kube.RBACGroup, "rolebindings", "update")
	update.ResourceNames = []string{binding.Name}
	bind := kubeRule(kube.RBACGroup, "roles", "bind")
	bind.ResourceNames = []string{high.Name}
	kubeAssign(&s, "manager", "finance", update, bind)
	if kubeCan(t, s, kubeCompile(t, s), "alice", kubeReads("secrets", "finance")) {
		t.Fatal("binding update was allowed to replace immutable roleRef")
	}
}

func TestKubernetesImpersonatingMastersIncludesAuthorizerBypass(t *testing.T) {
	s := kubeState()
	u := kubeRule("", "users", "impersonate")
	u.ResourceNames = []string{"arbitrary-user"}
	g := kubeRule("", "groups", "impersonate")
	g.ResourceNames = []string{"system:masters"}
	kubeAssign(&s, "impersonator", "", u, g)
	snap := kubeCompile(t, s)
	r, err := snap.Reach(KubernetesNodeID(s.Cluster, "identity", "alice"))
	if err != nil || r.ByTier[0] == 0 {
		t.Fatal("system:masters bypass missing", err)
	}
	if !kubeCan(t, s, snap, "alice", func(p kube.Permission) bool { return p.Verb == kubeFuture+"-verb" && p.Namespace == "wallet" }) {
		t.Fatal("masters impersonation failed to reach wildcard authority")
	}
}

func kubeUpdate(before, after kube.Object) kube.Mutation {
	return kube.Mutation{Cluster: "test-cluster", Connector: "source", Operation: "UPDATE", Before: &before, After: &after, ObjectDigest: ports.Digest{1}, OldObjectDigest: ports.Digest{2}}
}

func TestKubernetesWildcardNarrowingIsReductionButExpansionIsNot(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, after kube.Rule
		reduction     bool
	}{
		{"narrow wildcard", kubeRule("", "*", "get"), kubeRule("", "pods", "get"), true},
		{"widen wildcard", kubeRule("", "pods", "get"), kubeRule("", "*", "get"), false},
		{"widen verbs", kubeRule("", "pods", "get"), kubeRule("", "pods", "*"), false},
		{"sentinel name collision", func() kube.Rule {
			r := kubeRule("", "pods", "get")
			r.ResourceNames = []string{kubeFuture + "-name"}
			return r
		}(), kubeRule("", "pods", "get"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := kubeState()
			kubeAssign(&s, "reader", "finance", tc.before)
			before := s.Objects[0]
			after := before
			after.Rules = []kube.Rule{tc.after}
			impact, err := KubernetesImpact(44, s, kubeUpdate(before, after))
			if err != nil {
				t.Fatal(err)
			}
			if impact.MonotonicReduction != tc.reduction {
				t.Fatalf("reduction=%v; want %v", impact.MonotonicReduction, tc.reduction)
			}
		})
	}
}

func TestKubernetesCreatingDanglingRoleAffectsOtherBeneficiary(t *testing.T) {
	s := kubeState()
	role := kubeRole("missing", "finance", kubeRule("", "secrets", "get"))
	s.Objects = []kube.Object{kubeBinding("latent", "finance", role, kube.Subject{Kind: "User", Name: "bob"})}
	role.UID = ""
	role.ResourceVersion = ""
	impact, err := KubernetesImpact(44, s, kube.Mutation{Cluster: s.Cluster, Connector: "source", Operation: "CREATE", After: &role, ObjectDigest: ports.Digest{1}})
	if err != nil {
		t.Fatal(err)
	}
	if impact.MonotonicReduction {
		t.Fatal("activation of existing binding was treated as reduction")
	}
	found := false
	for _, a := range impact.Affected {
		if a.IdentityID == KubernetesNodeID(s.Cluster, "identity", "bob") && len(a.NewPowers) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("nonrequester beneficiary omitted")
	}
}

func TestKubernetesAggregateLabelChangeAffectsBoundIdentity(t *testing.T) {
	s := kubeState()
	aggregate := kubeRole("aggregate", "", nil...)
	aggregate.Aggregation = []kube.Selector{{MatchLabels: map[string]string{"aggregate": "yes"}}}
	leaf := kubeRole("leaf", "", kubeRule("", "secrets", "get"))
	s.Objects = []kube.Object{aggregate, leaf, kubeBinding("aggregate", "finance", aggregate, kube.Subject{Kind: "Group", Name: "approvers"})}
	after := leaf
	after.Labels = map[string]string{"aggregate": "yes"}
	impact, err := KubernetesImpact(44, s, kubeUpdate(leaf, after))
	if err != nil || impact.MonotonicReduction {
		t.Fatal("aggregation selector increase missed", err)
	}
	if len(impact.Affected) != 1 || impact.Affected[0].IdentityID != KubernetesNodeID(s.Cluster, "identity", "bob") {
		t.Fatal("wrong affected beneficiary", impact.Affected)
	}
}
