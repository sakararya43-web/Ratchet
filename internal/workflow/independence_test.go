package workflow

import (
	"errors"
	"testing"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/graph"
)

func TestBasicApprovalIndependenceUsesBeforeAndProposedControl(t *testing.T) {
	base := graph.Data{Nodes: []graph.Node{{ID: "requester", Type: "Human"}, {ID: "owner", Type: "Human"}, {ID: "service", Type: "ServiceAccount"}, {ID: "group", Type: "Group"}, {ID: "current-role", Type: "Role"}, {ID: "requested-role", Type: "Role"}, {ID: "report", Type: "Resource", Tier: 2}}, Edges: []graph.Edge{{Source: "requested-role", Target: "report", Kind: "GRANTS", Action: "read"}}}
	for _, tc := range []struct {
		name, target, approver string
		extra                  []graph.Edge
		reject                 bool
	}{
		{name: "independent owner", target: "requester", approver: "owner"},
		{name: "self", target: "requester", approver: "requester", reject: true},
		{name: "current inherited takeover", target: "requester", approver: "owner", extra: []graph.Edge{{Source: "requester", Target: "group", Kind: "MEMBER_OF"}, {Source: "group", Target: "owner", Kind: "CAN_ADMINISTER"}}, reject: true},
		{name: "takeover created by requested role", target: "requester", approver: "owner", extra: []graph.Edge{{Source: "requested-role", Target: "owner", Kind: "CAN_ADMINISTER"}}, reject: true},
		{name: "direct beneficiary", target: "owner", approver: "owner", reject: true},
		{name: "controlled beneficiary", target: "service", approver: "owner", extra: []graph.Edge{{Source: "owner", Target: "current-role", Kind: "ASSIGNED"}, {Source: "current-role", Target: "service", Kind: "CAN_ASSUME"}}, reject: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := graph.Data{Nodes: base.Nodes, Edges: append(append([]graph.Edge(nil), base.Edges...), tc.extra...)}
			snapshot, err := graph.Build(1, data)
			if err != nil {
				t.Fatal(err)
			}
			c := domain.Change{Requester: "requester", Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: tc.target, Access: "requested-role"}, Decision: domain.Decision{Groups: []string{"resource-owner"}}}
			result, delta, err := impact(snapshot, c.Intent)
			if err != nil {
				t.Fatal(err)
			}
			err = eligible(snapshot, c, result, delta, tc.approver, []string{tc.approver})
			if tc.reject && !errors.Is(err, ErrPermission) {
				t.Fatal("ineligible approval admitted", err)
			}
			if !tc.reject && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLateReadbackCanProveTimelyApplication(t *testing.T) {
	start := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	command := PreparedCommand{DispatchedAt: start, Deadline: start.Add(time.Minute)}
	result := ExecutionResult{AppliedAt: start.Add(time.Second), ObservedAt: start.Add(2 * time.Minute)}
	if !applicationTimeValid(command, result) {
		t.Fatal("timely application rejected because reconciliation was late")
	}
	result.AppliedAt = start.Add(90 * time.Second)
	if applicationTimeValid(command, result) {
		t.Fatal("late application accepted")
	}
	result.AppliedAt = time.Time{}
	if applicationTimeValid(command, result) {
		t.Fatal("unproved application time accepted")
	}
}
