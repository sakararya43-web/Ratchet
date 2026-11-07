//go:build integration

package workflow_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestRecordedDecisionReplayRejectsTamperingAndSurvivesContextChanges(t *testing.T) {
	sys := setup(t)
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	c, err := service.Submit(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, workflow.Submit{CommandID: uuid.New(), Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:finance"}, Justification: "Replay the original finance review decision"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Assess(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: 1, Operation: "assess"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.DecisionEvidence(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, c.ID, 0); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("requester obtained investigator evidence", err)
	}
	evidence, err := service.DecisionEvidence(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}, c.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		result, err := workflow.ReplayDecision(sys.ctx, evidence, sys.root, evidence.EventHash)
		if err != nil || result.Decision.Quorum != 1 {
			t.Fatal("deterministic replay", err)
		}
	}
	for _, name := range []string{"graph", "policy", "root", "event", "registry"} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(evidence)
			if err != nil {
				t.Fatal(err)
			}
			var altered workflow.DecisionEvidence
			if err := json.Unmarshal(raw, &altered); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "graph":
				altered.Graph.Edges = nil
			case "policy":
				altered.Bundle = []byte(`{}`)
			case "root":
				altered.Root = ports.Digest{5}
			case "event":
				altered.CanonicalEvent = []byte(`{}`)
			case "registry":
				altered.RegistryProof = []byte(`{}`)
			}
			if _, err := workflow.ReplayDecision(sys.ctx, altered, sys.root, evidence.EventHash); err == nil {
				t.Fatal("tampered replay accepted")
			}
		})
	}
	current, err := sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	held, err := service.Review(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:owner"}, c.ID, uuid.New(), current.Revision, "MORE_INFO", "Explain the precise reporting requirement")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ProvideContext(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, c.ID, uuid.New(), held.Revision, "A new private explanation invalidates the old approval context"); err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.ReplayDecision(sys.ctx, evidence, sys.root, evidence.EventHash); err != nil {
		t.Fatal("later context changed historical replay", err)
	}
	if _, _, err := sys.store.VerifyTenant(sys.ctx, sys.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.ReplayDecision(sys.ctx, evidence, sys.root, ports.Digest{42}); !errors.Is(err, eventstore.ErrIntegrity) {
		t.Fatal("unpinned event accepted", err)
	}
}
