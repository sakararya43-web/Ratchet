//go:build integration

package workflow_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestRequestVisibilityRestrictsOtherPeopleAndKeepsIndependentReview(t *testing.T) {
	sys := setup(t)
	snapshot, err := sys.store.CurrentGraph(sys.ctx, sys.tenant, sys.key)
	if err != nil {
		t.Fatal(err)
	}
	data := snapshot.Data()
	data.Nodes = append(data.Nodes, graph.Node{ID: "user:outsider", Type: "Human"})
	replaceGraph(t, sys, data)
	s, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	requester := workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}
	c, err := s.Submit(sys.ctx, requester, workflow.Submit{CommandID: uuid.New(), Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: requester.ID, Access: "role:finance"}, Justification: "A private requester explanation for independent review"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Assess(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: 1, Operation: "assess"}); err != nil {
		t.Fatal(err)
	}
	c, err = sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if detail, err := s.ResponseDetail(sys.ctx, requester, c); err != nil || detail {
		t.Fatal("requester received detail", err)
	}
	if detail, err := s.ResponseDetail(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:owner"}, c); err != nil || !detail {
		t.Fatal("independent owner lost review detail", err)
	}
	outsider := workflow.Actor{TenantID: sys.tenant, ID: "user:outsider"}
	if _, err := s.View(sys.ctx, outsider, c.ID); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("unrelated identity read private request", err)
	}
	list, _, _, err := s.List(sys.ctx, outsider, 0, 200, "", 0)
	if err != nil || len(list) != 0 {
		t.Fatal("unrelated request entered list", err)
	}
	attention, _, err := s.Attention(sys.ctx, outsider)
	if err != nil || len(attention) != 0 {
		t.Fatal("unrelated request entered overview", err)
	}
}
