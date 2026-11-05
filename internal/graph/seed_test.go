package graph_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/evaluation"
	"github.com/sakararya43-web/Ratchet/internal/graph"
)

// This test-only fixture compiler expresses the proposed typed semantics of the
// real simulator seed. It is never used by a production API or ingest consumer.
// Logical permissions are explicit nodes, not invented resources for dangling
// connector edges. The peer must confirm the broad iam:all semantics.
func exchange(t *testing.T) *graph.Snapshot {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/orgs/exchange-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := evaluation.CompileDemo(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestExchangeImpactGolden(t *testing.T) {
	s := exchange(t)
	delta, err := s.Draft("ROLE_ASSIGN", "user:rahul", "role:exchange-admin")
	if err != nil {
		t.Fatal(err)
	}
	impact, err := s.ImpactDiff(delta)
	if err != nil {
		t.Fatal(err)
	}
	wallet, leader := false, false
	for _, item := range impact.Affected {
		if item.IdentityID == "user:rahul" {
			for _, n := range item.NewResources {
				wallet = wallet || n.ID == "svc:wallet-signer"
			}
			for _, id := range item.NewControlled {
				leader = leader || id == "user:sec-lead-1"
			}
			if len(item.NewRoutes) == 0 {
				t.Fatal("missing critical route")
			}
		}
	}
	if !wallet || !leader || impact.MonotonicReduction {
		t.Fatal("admin consequences missing")
	}
	raw, err := json.MarshalIndent(impact, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := filepath.Join("..", "..", "testdata", "impact", "rahul-admin-v1.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(expected) != string(raw) {
		t.Fatal("impact differs from reviewed-candidate fixture; inspect before regeneration")
	}
	before, err := s.Reach("user:rahul")
	if err != nil || before.ByTier[0] != 0 || s.Version() != 1000 {
		t.Fatal("fixture simulation mutated base")
	}
}

func TestExchangeImpactScenarioFacts(t *testing.T) {
	s := exchange(t)
	type scenario struct {
		Name       string            `json:"name"`
		Kind       string            `json:"kind"`
		Target     string            `json:"target"`
		Access     string            `json:"access,omitempty"`
		Parameters map[string]string `json:"parameters,omitempty"`
		Impact     graph.Impact      `json:"impact"`
	}
	cases := []scenario{{Name: "ordinary-existing-finance-assistant", Kind: "ROLE_ASSIGN", Target: "user:rahul-assistant", Access: "role:finance-analyst"}, {Name: "service-overgrant", Kind: "ROLE_ASSIGN", Target: "svc:reporting-worker", Access: "role:wallet-operator"}, {Name: "withdrawal-rule-weakening", Kind: "MODIFY_SAFEGUARD", Target: "safeguard:withdrawal-rule", Parameters: map[string]string{"required_checks": "1", "threshold_usd": "1000000"}}, {Name: "revoke-finance-role", Kind: "ROLE_REVOKE", Target: "user:rahul", Access: "role:finance-analyst"}}
	for index := range cases {
		c := &cases[index]
		var d graph.Delta
		var err error
		if c.Parameters != nil {
			d, err = s.EditSafeguard(c.Target, c.Parameters)
		} else {
			d, err = s.Draft(c.Kind, c.Target, c.Access)
		}
		if err != nil {
			t.Fatal(err)
		}
		c.Impact, err = s.ImpactDiff(d)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(cases[0].Impact.Affected) != 1 || cases[0].Impact.Affected[0].IdentityID != "user:rahul-assistant" || len(cases[1].Impact.Affected) != 1 || len(cases[1].Impact.Affected[0].NewResources) != 1 || len(cases[2].Impact.Weakened) != 1 || !cases[3].Impact.MonotonicReduction {
		t.Fatal("seeded scenario consequences differ")
	}
	seed, err := os.ReadFile("../../testdata/orgs/exchange-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canon.New().Digest(json.RawMessage(seed))
	if err != nil {
		t.Fatal(err)
	}
	document := struct {
		Source       string     `json:"source"`
		SourceDigest string     `json:"source_canonical_digest"`
		Semantics    string     `json:"semantics_status"`
		Cases        []scenario `json:"cases"`
	}{"testdata/orgs/exchange-v1.json", digest.String(), "proposed; peer review pending", cases}
	raw, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := "../../testdata/policies/phase1-impact-facts.json"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(expected) != string(raw) {
		t.Fatal("scenario facts changed; inspect before updating shared fixture")
	}
}
