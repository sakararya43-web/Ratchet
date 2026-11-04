package graph_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/canon"
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
	var seed struct {
		Identities []struct {
			ID, Type string
			Disabled bool `json:"is_disabled"`
		} `json:"identities"`
		Roles []struct {
			ID          string
			Permissions []string
		} `json:"roles"`
		Resources []struct {
			ID   string
			Tier int
		} `json:"resources"`
		Safeguards []struct {
			ID         string
			Tier       int
			Resources  []string          `json:"protected_resources"`
			Parameters map[string]string `json:"parameters"`
		} `json:"safeguards"`
		Grants []struct {
			ID         string
			IdentityID string `json:"identity_id"`
			RoleID     string `json:"role_id"`
			By         string `json:"granted_by"`
		} `json:"grants"`
		Control []struct {
			Source string `json:"controller_id"`
			Target string `json:"controlled_id"`
			Kind   string `json:"kind"`
		} `json:"control_relations"`
		Sessions []struct {
			ID       string `json:"session_id"`
			Identity string `json:"identity_id"`
			Revoked  bool   `json:"is_revoked"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(raw, &seed); err != nil {
		t.Fatal(err)
	}
	d := graph.Data{}
	known := map[string]bool{}
	add := func(n graph.Node) { known[n.ID] = true; d.Nodes = append(d.Nodes, n) }
	for _, n := range seed.Identities {
		p := map[string]string{}
		if n.Disabled {
			p["disabled"] = "true"
		}
		add(graph.Node{ID: n.ID, Type: n.Type, Properties: p})
	}
	for _, r := range seed.Roles {
		add(graph.Node{ID: r.ID, Type: "Role"})
	}
	for _, r := range seed.Resources {
		add(graph.Node{ID: r.ID, Type: "Resource", Tier: r.Tier})
	}
	for _, s := range seed.Safeguards {
		properties := s.Parameters
		if s.ID == "safeguard:withdrawal-rule" {
			properties["guard_kind"] = "withdrawal_threshold_v1"
		}
		add(graph.Node{ID: s.ID, Type: "Safeguard", Tier: s.Tier, Properties: properties})
		for _, resource := range s.Resources {
			d.Edges = append(d.Edges, graph.Edge{Source: resource, Target: s.ID, Kind: "PROTECTED_BY"})
		}
	}
	for _, r := range seed.Roles {
		for _, permission := range r.Permissions {
			at := strings.LastIndex(permission, ":")
			if at < 0 {
				t.Fatal("malformed seed permission")
			}
			target, action := permission[:at], permission[at+1:]
			if !known[target] {
				target = "permission:" + permission
				if !known[target] {
					add(graph.Node{ID: target, Type: "Permission"})
				}
				action = "exercise"
			}
			d.Edges = append(d.Edges, graph.Edge{Source: r.ID, Target: target, Kind: "GRANTS", Action: action})
			if permission == "iam:all" {
				for _, role := range seed.Roles {
					d.Edges = append(d.Edges, graph.Edge{Source: target, Target: role.ID, Kind: "CAN_MODIFY"})
				}
				for _, identity := range seed.Identities {
					d.Edges = append(d.Edges, graph.Edge{Source: target, Target: identity.ID, Kind: "CAN_ADMINISTER"})
				}
				for _, resource := range seed.Resources {
					d.Edges = append(d.Edges, graph.Edge{Source: target, Target: resource.ID, Kind: "GRANTS", Action: "*"})
				}
			}
		}
	}
	for _, g := range seed.Grants {
		d.Edges = append(d.Edges, graph.Edge{ID: g.ID, Source: g.IdentityID, Target: g.RoleID, Kind: "ASSIGNED", Properties: map[string]string{"granted_by": g.By}})
	}
	for _, c := range seed.Control {
		d.Edges = append(d.Edges, graph.Edge{Source: c.Source, Target: c.Target, Kind: c.Kind})
	}
	for _, s := range seed.Sessions {
		props := map[string]string{}
		if s.Revoked {
			props["disabled"] = "true"
		}
		add(graph.Node{ID: s.ID, Type: "Session", Properties: props})
		if !s.Revoked {
			d.Edges = append(d.Edges, graph.Edge{Source: s.ID, Target: s.Identity, Kind: "CAN_ASSUME"})
		}
	}
	s, err := graph.Build(1000, d)
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
