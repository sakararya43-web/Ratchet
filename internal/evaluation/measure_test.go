package evaluation_test

import (
	"context"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/evaluation"
	"github.com/sakararya43-web/Ratchet/internal/graph"
)

func TestReplayReportsDenominatorAndUnexpectedCauses(t *testing.T) {
	cases := []evaluation.BenignCase{{ID: "owner", ExpectedOutcome: "REQUIRE_APPROVAL", ExpectedQuorum: 1}, {ID: "held", ExpectedOutcome: "REQUIRE_APPROVAL", ExpectedQuorum: 1}}
	r, err := evaluation.Replay(context.Background(), cases, func(_ context.Context, c evaluation.BenignCase) (domain.Decision, error) {
		if c.ID == "held" {
			return domain.Decision{Outcome: "HOLD"}, nil
		}
		return domain.Decision{Outcome: "REQUIRE_APPROVAL", Quorum: 1}, nil
	})
	if err != nil || r.Denominator != 2 || r.Unexpected != 1 || r.UnexpectedPercent != 50 || r.Causes["unexpected HOLD"] != 1 {
		t.Fatal(r, err)
	}
	if _, err := evaluation.Replay(context.Background(), nil, nil); err == nil {
		t.Fatal("empty workload reported success")
	}
}

func TestLargeGraphCompositionAndControlledBeneficiary(t *testing.T) {
	d := evaluation.LargeGraph()
	if len(d.Edges) != 100000 {
		t.Fatal("wrong graph size", len(d.Edges))
	}
	s, err := graph.Build(1, d)
	if err != nil {
		t.Fatal(err)
	}
	delta, err := s.Draft("ROLE_ASSIGN", "principal:0", "role:777")
	if err != nil {
		t.Fatal(err)
	}
	impact, err := s.ImpactDiff(delta)
	if err != nil {
		t.Fatal(err)
	}
	controller := false
	for _, a := range impact.Affected {
		if a.IdentityID == "principal:960" && len(a.NewPowers) > 0 {
			controller = true
		}
	}
	if !controller {
		t.Fatal("dataset did not exercise a non-requester beneficiary")
	}
}

func BenchmarkImpactShared100k(b *testing.B) {
	s, err := graph.Build(1, evaluation.LargeGraph())
	if err != nil {
		b.Fatal(err)
	}
	delta, err := s.Draft("ROLE_ASSIGN", "principal:0", "role:777")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := s.ImpactDiff(delta); err != nil {
			b.Fatal(err)
		}
	}
}
