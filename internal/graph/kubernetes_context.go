package graph

import (
	"fmt"
	"reflect"

	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
)

// KubernetesProposal compares a native change within the complete organization
// graph. External controllers and unrelated business grants remain present in
// both views, so a local-cluster-only impact cannot omit their consequences.
// The caller must supply retained, authenticated source facts and separately
// check source revisions; projection equality does not prove target freshness.
// Returned views share the current ledger position and are isolated proposals.
func (s *Snapshot) KubernetesProposal(before kube.State, mutation kube.Mutation) (*Snapshot, *Snapshot, Impact, error) {
	after, err := before.After(mutation)
	if err != nil {
		return nil, nil, Impact{}, err
	}
	current, err := CompileKubernetes(s.version, before)
	if err != nil {
		return nil, nil, Impact{}, err
	}
	a, err := CompileKubernetes(s.version, before, after)
	if err != nil {
		return nil, nil, Impact{}, err
	}
	b, err := CompileKubernetes(s.version, after, before)
	if err != nil {
		return nil, nil, Impact{}, err
	}
	combinedBefore, err := s.replaceKubernetes(current, a)
	if err != nil {
		return nil, nil, Impact{}, err
	}
	combinedAfter, err := s.replaceKubernetes(current, b)
	if err != nil {
		return nil, nil, Impact{}, err
	}
	result, err := combinedBefore.ImpactDiff(snapshotDifference(combinedBefore, combinedAfter))
	if err != nil {
		return nil, nil, Impact{}, err
	}
	return combinedBefore, combinedAfter, result, nil
}

func (s *Snapshot) replaceKubernetes(current, replacement *Snapshot) (*Snapshot, error) {
	nodes := map[string]Node{}
	edges := map[string]Edge{}
	for _, n := range s.nodes {
		nodes[n.ID] = n
	}
	for _, e := range s.edges {
		edges[e.ID] = e
	}
	for _, n := range current.nodes {
		if actual, ok := nodes[n.ID]; !ok || !reflect.DeepEqual(actual, n) {
			return nil, fmt.Errorf("%w: native projection disagrees with organization graph", ErrUnavailable)
		}
		delete(nodes, n.ID)
	}
	for _, e := range current.edges {
		if actual, ok := edges[e.ID]; !ok || !reflect.DeepEqual(actual, e) {
			return nil, fmt.Errorf("%w: native grant provenance disagrees with organization graph", ErrUnavailable)
		}
		delete(edges, e.ID)
	}
	for _, n := range replacement.nodes {
		if existing, ok := nodes[n.ID]; ok && !reflect.DeepEqual(existing, n) {
			return nil, ErrInvalid
		}
		nodes[n.ID] = n
	}
	for _, e := range replacement.edges {
		if existing, ok := edges[e.ID]; ok && !reflect.DeepEqual(existing, e) {
			return nil, ErrInvalid
		}
		edges[e.ID] = e
	}
	data := Data{Nodes: make([]Node, 0, len(nodes)), Edges: make([]Edge, 0, len(edges))}
	data.Kubernetes = s.kubernetes
	data.KubernetesDigests = s.kubernetesDigests
	for _, n := range nodes {
		data.Nodes = append(data.Nodes, n)
	}
	for _, e := range edges {
		data.Edges = append(data.Edges, e)
	}
	// Build refuses any external reference that the proposed replacement could
	// not retain. No incoming control edge is silently discarded.
	return Build(s.version, data)
}
