package workflow

import (
	"reflect"
	"slices"
	"testing"

	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func TestObservedNativeTransitionMatchesSortedAPIInventoryWithoutIgnoringConcurrentChanges(t *testing.T) {
	role := kube.Object{Kind: "ClusterRole", Name: "reader", UID: "role", ResourceVersion: "role-rv", Rules: []kube.Rule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}}
	binding := kube.Object{Kind: "RoleBinding", Namespace: "finance", Name: "z-existing", UID: "binding", ResourceVersion: "binding-rv", RoleKind: "ClusterRole", RoleName: "reader", Subjects: []kube.Subject{{Kind: "User", Name: "alice"}}}
	before := kube.State{Cluster: "cluster", Complete: true, ResourceVersion: "cut-before", Namespaces: []string{"finance"}, Principals: []kube.Principal{{ID: "alice", Kind: "User", Name: "alice"}}, Resources: []kube.APIResource{{Resource: "pods", Namespaced: true}}, Objects: []kube.Object{role, binding}}
	proposal := binding
	proposal.Name = "a-new"
	proposal.UID = ""
	proposal.ResourceVersion = ""
	observed := proposal
	observed.UID = "new-uid"
	observed.ResourceVersion = "new-rv"
	current, err := before.Clone()
	if err != nil {
		t.Fatal(err)
	}
	current.ResourceVersion = "cut-after"
	current.Objects = []kube.Object{role, observed, binding}
	message := SignedKubernetesDrift{BaselineGraphVersion: 1, Before: before, Mutation: kube.Mutation{Connector: "native", Cluster: before.Cluster, Operation: "CREATE", After: &proposal, ObjectDigest: ports.Digest{1}}, Observation: NativeObservation{Object: &observed}}
	original := slices.Clone(current.Objects)
	if !observedNativeTransition(message, current) {
		t.Fatal("exact sorted live transition was not proved")
	}
	if !reflect.DeepEqual(original, current.Objects) {
		t.Fatal("comparison mutated caller inventory")
	}
	current.Namespaces = append(current.Namespaces, "other")
	if observedNativeTransition(message, current) {
		t.Fatal("concurrent inventory change ignored")
	}
}
