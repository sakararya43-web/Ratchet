//go:build integration

package workflow_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/telemetry"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestDiagnosticsAndCorrelatedSpansRespectTenantAndInvestigatorBoundary(t *testing.T) {
	sys := setup(t)
	var logs bytes.Buffer
	observer := telemetry.New(slog.New(slog.NewJSONHandler(&logs, nil)))
	graph, err := sys.store.CurrentGraph(sys.ctx, sys.tenant, sys.key)
	if err != nil {
		t.Fatal(err)
	}
	s, err := workflow.NewConfigured(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant}, workflow.Config{Observer: observer, PublishedGraphVersion: func(context.Context, string) (int64, error) { return graph.Version() - 1, nil }})
	if err != nil {
		t.Fatal(err)
	}
	correlation := uuid.NewString()
	c, err := s.Submit(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, workflow.Submit{CommandID: uuid.New(), CorrelationID: correlation, Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:finance"}, Justification: "PRIVATE justification person@example.com must never be logged"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Assess(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: c.Revision, Operation: "assess"}); err != nil {
		t.Fatal(err)
	}
	d, err := s.InvestigatorDiagnostics(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"})
	if err != nil {
		t.Fatal(err)
	}
	if d.OutboxPending < 1 || d.JobsDue < 1 || d.GraphPublicationLagPositions == nil || *d.GraphPublicationLagPositions != 1 || d.PolicyVersion != "1.0.0" || d.Spans["submit"].Spans != 1 || d.Spans["assessment"].Spans != 1 || d.Spans["policy_decision"].Spans != 1 {
		t.Fatal("missing real diagnostics", d)
	}
	if strings.Contains(logs.String(), "PRIVATE") || strings.Contains(logs.String(), "person@example.com") || strings.Contains(logs.String(), "user:requester") || !strings.Contains(logs.String(), correlation) {
		t.Fatal("span lost correlation or leaked private fields")
	}
	if _, err := s.InvestigatorDiagnostics(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("requester read operational metrics", err)
	}
	if _, err := s.Diagnostics(sys.ctx, "other"); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("cross tenant diagnostics", err)
	}
}
