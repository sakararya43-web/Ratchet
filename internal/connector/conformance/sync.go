// Package conformance validates connector output against the core sync contract.
// It is a test/integration boundary, not a target adapter or a fake control plane.
package conformance

import (
	"errors"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
)

func Snapshot(snapshot *v1.GraphSnapshot) (*graph.Snapshot, error) {
	if snapshot == nil || !snapshot.Complete {
		return nil, errors.New("complete snapshot marker required")
	}
	e := snapshot.Envelope
	if e == nil || e.SchemaVersion != 1 || e.TenantId != snapshot.TenantId || e.ConnectorId != snapshot.ConnectorId || e.SourceRevision != snapshot.SourceRevision || e.CorrelationId == "" {
		return nil, errors.New("authenticated sync envelope metadata required")
	}
	if id, err := uuid.Parse(e.MessageId); err != nil || id == uuid.Nil {
		return nil, errors.New("stable UUID message identity required")
	}
	if _, err := uuid.Parse(e.CorrelationId); err != nil {
		return nil, errors.New("UUID correlation identity required")
	}
	if snapshot.SourceRevision < 1 || snapshot.SourceRevision > 1<<53-1 {
		return nil, errors.New("positive source revision required")
	}
	return Graph(snapshot)
}

// Graph is also callable separately to locate model defects before transport
// adoption. It never fills missing nodes, provenance or session state.
func Graph(snapshot *v1.GraphSnapshot) (*graph.Snapshot, error) {
	if snapshot == nil {
		return nil, graph.ErrInvalid
	}
	d := graph.Data{Nodes: []graph.Node{}, Edges: []graph.Edge{}}
	for _, n := range snapshot.Nodes {
		if n == nil {
			return nil, graph.ErrInvalid
		}
		d.Nodes = append(d.Nodes, graph.Node{ID: n.Id, Type: n.Type, Tier: int(n.Tier), DisplayName: n.DisplayName, Properties: n.Properties})
	}
	for _, e := range snapshot.Edges {
		if e == nil {
			return nil, graph.ErrInvalid
		}
		d.Edges = append(d.Edges, graph.Edge{Source: e.Source, Target: e.Target, Kind: e.Kind, Action: e.Action, Properties: e.Properties})
	}
	return graph.Build(0, d)
}
