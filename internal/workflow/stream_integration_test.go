//go:build integration

package workflow_test

import (
	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	"testing"
)

func TestListAndResumableStreamsShareAnImmutableBoundary(t *testing.T) {
	sys := setup(t)
	s, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}
	submit := func() domain.Change {
		t.Helper()
		c, err := s.Submit(sys.ctx, actor, workflow.Submit{CommandID: uuid.New(), Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: actor.ID, Access: "role:finance"}, Justification: "An independently reviewed streaming boundary request"})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	first, second := submit(), submit()
	page, err := s.ListWindow(sys.ctx, actor, "", 0, 0, 1)
	if err != nil || !page.More || len(page.Changes) != 1 || page.Changes[0].ID != first.ID {
		t.Fatal("initial fixed window", err)
	}
	if err := s.Assess(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: second.ID, Revision: 1, Operation: "assess"}); err != nil {
		t.Fatal(err)
	}
	third := submit()
	tail, err := s.ListWindow(sys.ctx, actor, "", page.After, page.End, 10)
	if err != nil || tail.More || len(tail.Changes) != 1 || tail.Changes[0].ID != second.ID || tail.Changes[0].State != domain.Submitted {
		t.Fatal("list admitted a future revision/opening", err)
	}
	updates, err := s.StreamPage(sys.ctx, actor, "changes", page.End)
	if err != nil || len(updates.Changes) != 3 || updates.Changes[2].Change.ID != third.ID {
		t.Fatal("list/watch boundary lost updates", err)
	}
	replacement, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := replacement.StreamPage(sys.ctx, actor, "changes", updates.Changes[0].Sequence)
	if err != nil || len(resumed.Changes) != 2 || resumed.Changes[0].Sequence != updates.Changes[1].Sequence {
		t.Fatal("restart/reconnect lost ordering", err)
	}
	investigator := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	plan, err := s.PlanContainment(sys.ctx, investigator, workflow.PlanInput{CommandID: uuid.New(), CorrelationID: uuid.NewString(), Identity: actor.ID, Costs: map[string]int64{"ROLE_REVOKE": 1}})
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.ListIncidents(sys.ctx, investigator, "", 0, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := s.OpenIncident(sys.ctx, investigator, workflow.OpenIncidentInput{CommandID: uuid.New(), CorrelationID: uuid.NewString(), PlanID: plan.Body.ID, PlanDigest: plan.Digest})
	if err != nil {
		t.Fatal(err)
	}
	incidents, err := replacement.StreamPage(sys.ctx, investigator, "incidents", before.End)
	if err != nil || len(incidents.Incidents) != 1 || incidents.Incidents[0].Incident.Incident.ID != opened.Incident.ID {
		t.Fatal("incident stream lost durable opening", err)
	}
	if _, err := s.StreamPage(sys.ctx, actor, "incidents", 0); err == nil {
		t.Fatal("ordinary requester watched investigation details")
	}
}
