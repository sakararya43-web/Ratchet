//go:build integration

package workflow_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestIncidentInvestigationReplaysProposalAndCurrentResidualPaths(t *testing.T) {
	sys := setup(t)
	snapshot, err := sys.store.CurrentGraph(sys.ctx, sys.tenant, sys.key)
	if err != nil {
		t.Fatal(err)
	}
	data := snapshot.Data()
	data.Edges = append(data.Edges, graph.Edge{Source: "user:requester", Target: "role:admin", Kind: "ASSIGNED"})
	replaceGraph(t, sys, data)
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	ordinary := workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}
	proposal, err := service.PlanContainment(sys.ctx, actor, workflow.PlanInput{CommandID: uuid.New(), CorrelationID: uuid.NewString(), Identity: ordinary.ID, Costs: map[string]int64{"ROLE_REVOKE": 1, "RESTRICT_ACCOUNT": 100}})
	if err != nil {
		t.Fatal(err)
	}
	input := workflow.OpenIncidentInput{CommandID: uuid.New(), CorrelationID: uuid.NewString(), PlanID: proposal.Body.ID, PlanDigest: proposal.Digest}
	if _, err := service.OpenIncident(sys.ctx, ordinary, input); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("ordinary user opened incident", err)
	}
	wrong := input
	wrong.PlanDigest = ports.Digest{9}
	if _, err := service.OpenIncident(sys.ctx, actor, wrong); err == nil {
		t.Fatal("wrong plan digest accepted")
	}
	var wg sync.WaitGroup
	results := make(chan workflow.IncidentView, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			view, err := service.OpenIncident(sys.ctx, actor, input)
			if err != nil {
				t.Error(err)
				return
			}
			results <- view
		}()
	}
	wg.Wait()
	close(results)
	var opened workflow.IncidentView
	for view := range results {
		if opened.Incident.ID != "" && opened.Incident.ID != view.Incident.ID {
			t.Fatal("incident retry forked")
		}
		opened = view
	}
	if opened.Incident.Status != "OPEN" || opened.Incident.Revision != 1 || len(opened.Observed.Routes) != 1 || opened.Proposal.Digest != proposal.Digest {
		t.Fatal("incident evidence missing", opened.Incident)
	}
	changed := input
	changed.CorrelationID = uuid.NewString()
	if _, err := service.OpenIncident(sys.ctx, actor, changed); !errors.Is(err, eventstore.ErrIdempotencyConflict) {
		t.Fatal("changed incident retry admitted", err)
	}
	if _, err := service.GetIncident(sys.ctx, ordinary, opened.Incident.ID); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("ordinary user read investigator incident", err)
	}
	input.CommandID = uuid.New()
	if _, err := service.OpenIncident(sys.ctx, actor, input); err != nil {
		t.Fatal(err)
	}
	first, err := service.ListIncidents(sys.ctx, actor, "OPEN", 0, 0, 1)
	if err != nil || len(first.Incidents) != 1 || !first.More {
		t.Fatal("incident first page", err)
	}
	input.CommandID = uuid.New()
	if _, err := service.OpenIncident(sys.ctx, actor, input); err != nil {
		t.Fatal(err)
	}
	second, err := service.ListIncidents(sys.ctx, actor, "OPEN", first.After, first.End, 10)
	if err != nil || len(second.Incidents) != 1 || second.More {
		t.Fatal("incident page admitted later opening", err)
	}
	contained, err := service.ListIncidents(sys.ctx, actor, "CONTAINED", 0, 0, 10)
	if err != nil || len(contained.Incidents) != 0 {
		t.Fatal("planning manufactured containment", err)
	}
	audit, _, err := service.QueryAudit(sys.ctx, actor, eventstore.AuditFilter{Incident: opened.Incident.ID}, 0, 0, 20)
	if err != nil || len(audit) != 1 || audit[0].Event.Type != "IncidentOpened" {
		t.Fatal("incident audit correlation lost", err)
	}
	// Observe a later real graph ingestion independently of the stored proposal.
	data.Edges = data.Edges[:len(data.Edges)-1]
	if _, err := sys.store.IngestGraph(sys.ctx, eventstore.GraphInput{TenantID: sys.tenant, ConnectorID: "source", MessageID: uuid.New(), CorrelationID: uuid.NewString(), WireDigest: (ports.Digest{8}).String(), FromRevision: 11, ToRevision: 12, Complete: true, Snapshot: &data}, sys.key); err != nil {
		t.Fatal(err)
	}
	replacement, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	observed, err := replacement.GetIncident(sys.ctx, actor, opened.Incident.ID)
	if err != nil || len(observed.Observed.Routes) != 0 || observed.Observed.Version <= opened.Observed.Version || observed.Incident.Status != "OPEN" || observed.Proposal.Digest != proposal.Digest {
		t.Fatal("current residual paths or durable incident history lost", err)
	}
	events, err := sys.store.LoadStream(sys.ctx, sys.tenant, "incident:"+opened.Incident.ID)
	if err != nil || len(events) != 1 {
		t.Fatal("incident retry duplicated source evidence", err)
	}
	if _, _, err := sys.store.VerifyTenant(sys.ctx, sys.tenant); err != nil {
		t.Fatal(err)
	}
}
