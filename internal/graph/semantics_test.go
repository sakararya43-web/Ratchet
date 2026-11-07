package graph_test

import (
	"errors"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/graph"
)

func TestActionOnlyRevocationStillReportsAffectedIdentity(t *testing.T) {
	s, err := graph.Build(1, graph.Data{Nodes: []graph.Node{{ID: "user:a", Type: "Human"}, {ID: "asset", Type: "Resource", Tier: 2}}, Edges: []graph.Edge{{ID: "read", Source: "user:a", Target: "asset", Kind: "GRANTS", Action: "read"}, {ID: "write", Source: "user:a", Target: "asset", Kind: "GRANTS", Action: "write"}}})
	if err != nil {
		t.Fatal(err)
	}
	impact, err := s.ImpactDiff(graph.Delta{EdgesRemoved: []string{"write"}})
	if err != nil || !impact.MonotonicReduction || len(impact.Affected) != 1 {
		t.Fatalf("action-only revocation lost: %+v %v", impact, err)
	}
	if got := impact.Affected[0]; len(got.RemovedPowers) != 1 || got.RemovedPowers[0].Action != "write" || got.BlastDelta[2] != 0 {
		t.Fatalf("incorrect removed authority: %+v", got)
	}
}

func TestPartialDenyCannotBeHiddenByWildcard(t *testing.T) {
	s, err := graph.Build(1, graph.Data{Nodes: []graph.Node{{ID: "user:a", Type: "Human"}, {ID: "asset", Type: "Resource", Tier: 0}}, Edges: []graph.Edge{{Source: "user:a", Target: "asset", Kind: "GRANTS", Action: "*"}, {Source: "user:a", Target: "asset", Kind: "DENIES", Action: "sign"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reach("user:a"); !errors.Is(err, graph.ErrInvalid) {
		t.Fatal("partial deny represented as unlimited authority:", err)
	}
}

func TestDeclaredSafeguardWeakeningAndStrengthening(t *testing.T) {
	s, err := graph.Build(1, graph.Data{Nodes: []graph.Node{{ID: "user:a", Type: "Human"}, {ID: "guard", Type: "Safeguard", Tier: 0, Properties: map[string]string{"guard_kind": "withdrawal_threshold_v1", "required_checks": "2", "threshold_usd": "10000"}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		parameters map[string]string
		weak       bool
	}{{map[string]string{"required_checks": "1"}, true}, {map[string]string{"threshold_usd": "1000000"}, true}, {map[string]string{"required_checks": "3", "threshold_usd": "1000"}, false}} {
		d, err := s.EditSafeguard("guard", tc.parameters)
		if err != nil {
			t.Fatal(err)
		}
		impact, err := s.ImpactDiff(d)
		if err != nil {
			t.Fatal(err)
		}
		if (len(impact.Weakened) > 0) != tc.weak || impact.MonotonicReduction == tc.weak {
			t.Fatalf("guard edit %+v: %+v", tc, impact)
		}
	}
	if _, err := s.EditSafeguard("guard", map[string]string{"required_checks": "unknown"}); err == nil {
		t.Fatal("unknown parameter value accepted")
	}
}

func TestWildcardToNarrowGrantIsReduction(t *testing.T) {
	s, err := graph.Build(1, graph.Data{Nodes: []graph.Node{{ID: "user:a", Type: "Human"}, {ID: "asset", Type: "Resource", Tier: 2}}, Edges: []graph.Edge{{ID: "all", Source: "user:a", Target: "asset", Kind: "GRANTS", Action: "*"}}})
	if err != nil {
		t.Fatal(err)
	}
	impact, err := s.ImpactDiff(graph.Delta{EdgesRemoved: []string{"all"}, EdgesAdded: []graph.Edge{{Source: "user:a", Target: "asset", Kind: "GRANTS", Action: "read"}}})
	if err != nil || !impact.MonotonicReduction {
		t.Fatalf("wildcard reduction %+v %v", impact, err)
	}
}

func TestSessionMetadataIsNotPossessionAndRevokedSessionDoesNotInherit(t *testing.T) {
	for _, tc := range []struct {
		action     string
		disabled   string
		controlled int
	}{{"inspect", "false", 0}, {"use", "false", 1}, {"use", "true", 0}} {
		s, err := graph.Build(1, graph.Data{Nodes: []graph.Node{{ID: "user:a", Type: "Human"}, {ID: "user:b", Type: "Human"}, {ID: "session:b", Type: "Session", Properties: map[string]string{"disabled": tc.disabled}}}, Edges: []graph.Edge{{Source: "user:a", Target: "session:b", Kind: "GRANTS", Action: tc.action}, {Source: "session:b", Target: "user:b", Kind: "CAN_ASSUME"}}})
		if err != nil {
			t.Fatal(err)
		}
		control, err := s.ControlSet("user:a")
		if err != nil || len(control) != tc.controlled {
			t.Fatalf("session %+v: %v %v", tc, control, err)
		}
		if tc.action == "use" && tc.disabled == "false" {
			withMetadata, err := s.Overlay(2, graph.Delta{EdgesAdded: []graph.Edge{{ID: "0-metadata-first", Source: "user:a", Target: "session:b", Kind: "GRANTS", Action: "inspect"}}})
			if err != nil {
				t.Fatal(err)
			}
			control, err = withMetadata.ControlSet("user:a")
			if err != nil || len(control) != 1 {
				t.Fatal("metadata discovery suppressed usable-session expansion")
			}
		}
	}
}
