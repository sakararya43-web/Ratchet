package graph

import (
	"errors"
	"reflect"
	"testing"
)

func TestKubernetesSourceSeparatesRetainedAuthorityFromPrivateContext(t *testing.T) {
	s := kubeState()
	kubeAssign(&s, "reader", "finance", kubeRule("", "pods", "get"))
	snapshot, err := KubernetesSource(44, s)
	if err != nil {
		t.Fatal(err)
	}
	key := KubernetesSourceKey(s.Cluster)
	data := snapshot.Data()
	mutated := data.Kubernetes[key]
	mutated.Principals[0].Name = "changed"
	data.Kubernetes[key] = mutated
	data.KubernetesDigests[key] = "changed"
	actual, err := snapshot.KubernetesState(s.Cluster)
	if err != nil || actual.Principals[0].Name != "alice" {
		t.Fatal("source snapshot aliased mutable caller data", err)
	}
	data = snapshot.Data()
	data.Kubernetes = nil
	public, err := Build(44, data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := public.KubernetesState(s.Cluster); !errors.Is(err, ErrUnavailable) {
		t.Fatal("public replay fabricated exact source context", err)
	}
	a, _ := snapshot.Reach(KubernetesNodeID(s.Cluster, "identity", "alice"))
	b, _ := public.Reach(KubernetesNodeID(s.Cluster, "identity", "alice"))
	if !reflect.DeepEqual(a.Powers, b.Powers) {
		t.Fatal("retained replay lost authority facts")
	}
	data = snapshot.Data()
	state := data.Kubernetes[key]
	state.ResourceVersion = "another-opaque-cut"
	data.Kubernetes[key] = state
	if _, err := Build(44, data); err == nil {
		t.Fatal("source digest mismatch accepted")
	}
	copyState, err := s.Clone()
	if err != nil {
		t.Fatal(err)
	}
	copyState.Objects[0].Rules[0].Verbs[0] = "delete"
	if s.Objects[0].Rules[0].Verbs[0] != "get" {
		t.Fatal("normalized source clone aliases input")
	}
}
