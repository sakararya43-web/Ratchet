package conformance_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/connector/conformance"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
)

func TestSnapshotCompletenessAndModelContract(t *testing.T) {
	s := &v1.GraphSnapshot{TenantId: "tenant", ConnectorId: "source", SourceRevision: 1, Complete: true, Envelope: &v1.ConnectorEnvelope{SchemaVersion: 1, TenantId: "tenant", ConnectorId: "source", SourceRevision: 1, MessageId: uuid.NewString(), CorrelationId: uuid.NewString()}, Nodes: []*v1.GraphNode{{Id: "user:a", Type: "Human"}, {Id: "role:r", Type: "Role"}}, Edges: []*v1.GraphEdge{{Source: "user:a", Target: "role:r", Kind: "ASSIGNED"}}}
	if _, err := conformance.Snapshot(s); err != nil {
		t.Fatal(err)
	}
	s.Complete = false
	if _, err := conformance.Snapshot(s); err == nil {
		t.Fatal("partial snapshot accepted")
	}
	s.Complete = true
	s.Envelope.TenantId = "other"
	if _, err := conformance.Snapshot(s); err == nil {
		t.Fatal("tenant mismatch accepted")
	}
	s.Envelope.TenantId = "tenant"
	s.Edges[0].Target = "missing"
	if _, err := conformance.Snapshot(s); err == nil {
		t.Fatal("dangling relation accepted")
	}
}
