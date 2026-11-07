//go:build integration

package workflow_test

import (
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestEmergencyAccessRetainsIndependentQuorumAndExplicitScope(t *testing.T) {
	sys := setup(t)
	s, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		intent domain.Intent
		state  domain.State
		quorum int
		broad  bool
	}{
		{"minimal", domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:finance", Emergency: true, DurationSeconds: 300, Resources: []string{"reports"}, Permissions: []string{"read"}}, domain.AwaitingApproval, 1, false},
		{"tier-zero", domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:admin", Emergency: true, DurationSeconds: 300, Resources: []string{"wallet"}, Permissions: []string{"sign"}}, domain.AwaitingApproval, 2, false},
		{"excess-permission", domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:finance", Emergency: true, DurationSeconds: 300, Resources: []string{"reports"}, Permissions: []string{"view"}}, domain.Held, 0, true},
		{"excess-resource", domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:finance", Emergency: true, DurationSeconds: 300, Resources: []string{"wallet"}, Permissions: []string{"read"}}, domain.Held, 0, true},
		{"unbounded", domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:finance", Emergency: true, Resources: []string{"reports"}, Permissions: []string{"read"}}, domain.Held, 0, false},
		{"unspecified-scope", domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:finance", DurationSeconds: 300}, domain.Held, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := s.Submit(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, workflow.Submit{CommandID: uuid.New(), Intent: tc.intent, Justification: "Necessary bounded access for the documented incident"})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Assess(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: c.Revision, Operation: "assess"}); err != nil {
				t.Fatal(err)
			}
			c = waitState(t, sys, c.ID, tc.state)
			if c.Decision.Quorum != tc.quorum || c.Scope == nil || c.Scope.OverBroad != tc.broad || len(c.Approvals) != 0 {
				t.Fatal("scope or review bypass", c.Decision, c.Scope)
			}
			if tc.name == "tier-zero" && !slices.Contains(c.Decision.Groups, "role:security-lead") {
				t.Fatal("emergency bypassed independent lead routing")
			}
			if tc.broad && len(c.Scope.Resources)+len(c.Scope.Permissions) == 0 {
				t.Fatal("over-breadth lacks explicit evidence")
			}
		})
	}
}
