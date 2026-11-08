package graph_test

import (
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/graph"
)

func TestExecutableRevocationsCoverFullGrantAndSessionEffects(t *testing.T) {
	data := graph.Data{Nodes: []graph.Node{{ID: "human", Type: "Human"}, {ID: "service", Type: "ServiceAccount"}, {ID: "role", Type: "Role"}, {ID: "wallet", Type: "Resource", Tier: 0}, {ID: "session", Type: "Session"}}, Edges: []graph.Edge{{ID: "binding-1", Source: "human", Target: "role", Kind: "ASSIGNED"}, {ID: "binding-2", Source: "human", Target: "role", Kind: "ASSIGNED"}, {ID: "role-grant", Source: "role", Target: "wallet", Kind: "GRANTS", Action: "sign"}, {ID: "service-read", Source: "service", Target: "wallet", Kind: "GRANTS", Action: "read", Properties: map[string]string{"grant_id": "original-permission"}}, {ID: "service-sign", Source: "service", Target: "wallet", Kind: "GRANTS", Action: "sign", Properties: map[string]string{"grant_id": "original-permission"}}, {ID: "use-session", Source: "human", Target: "session", Kind: "GRANTS", Action: "use"}, {ID: "session-assume", Source: "session", Target: "service", Kind: "CAN_ASSUME"}}}
	s, err := graph.Build(1, data)
	if err != nil {
		t.Fatal(err)
	}
	role := graph.Revocation{Kind: "ROLE_REVOKE", Target: "human", Access: "role"}
	d, err := s.RevocationDelta(role)
	if err != nil || len(d.EdgesRemoved) != 2 {
		t.Fatal("partial role binding removal", err)
	}
	service := graph.Revocation{Kind: "REMOVE_SERVICE_PERMISSION", Target: "service", Access: "original-permission"}
	d, err = s.RevocationDelta(service)
	if err != nil || len(d.EdgesRemoved) != 2 {
		t.Fatal("shared permission removed only one effect", err)
	}
	if _, err := s.RevocationDelta(graph.Revocation{Kind: "REMOVE_SERVICE_PERMISSION", Target: "service", Access: "service-read"}); err == nil {
		t.Fatal("derived edge mistaken for original target grant")
	}
	after, _, err := s.ApplyRevocations([]graph.Revocation{role, service, {Kind: "TERMINATE_SESSION", Target: "session"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"human", "service"} {
		reach, err := after.Reach(id)
		if err != nil || reach.ByTier[0] != 0 {
			t.Fatal("critical authority survived", id, err)
		}
	}
	if _, _, err := s.ApplyRevocations([]graph.Revocation{{Kind: "RESTRICT_ACCOUNT", Target: "human", Protected: true}}); err == nil {
		t.Fatal("protected operation admitted")
	}
	if _, err := s.RevocationDelta(graph.Revocation{Kind: "DELETE_SAFEGUARD", Target: "wallet"}); err == nil {
		t.Fatal("unsupported action admitted")
	}

	// Test RESTRICT_ACCOUNT disables owned sessions in delta
	dataWithOwnedSession := graph.Data{
		Nodes: []graph.Node{
			{ID: "user:target", Type: "Human"},
			{ID: "session:user-1", Type: "Session", Properties: map[string]string{"owner": "user:target"}},
		},
		Edges: []graph.Edge{
			{ID: "grant-sess", Source: "user:target", Target: "session:user-1", Kind: "GRANTS", Action: "use"},
		},
	}
	sOwned, err := graph.Build(1, dataWithOwnedSession)
	if err != nil {
		t.Fatal(err)
	}
	restrictDelta, err := sOwned.RevocationDelta(graph.Revocation{Kind: "RESTRICT_ACCOUNT", Target: "user:target"})
	if err != nil {
		t.Fatal(err)
	}
	if len(restrictDelta.NodesAdded) != 2 {
		t.Fatalf("expected 2 modified nodes (account + session), got %d", len(restrictDelta.NodesAdded))
	}
	accountDisabled := false
	sessionDisabled := false
	for _, n := range restrictDelta.NodesAdded {
		if n.ID == "user:target" && n.Properties["disabled"] == "true" {
			accountDisabled = true
		}
		if n.ID == "session:user-1" && n.Properties["disabled"] == "true" {
			sessionDisabled = true
		}
	}
	if !accountDisabled || !sessionDisabled {
		t.Fatal("RESTRICT_ACCOUNT did not disable both account and owned session")
	}
}
