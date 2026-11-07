package domain_test

import (
	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"testing"
	"time"
)

func TestApprovedChangeRequiresIndependentDistinctHumansAndVerifiedReadback(t *testing.T) {
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	initial := domain.Change{ID: uuid.NewString(), TenantID: "tenant", Requester: "requester", Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: "target", Access: "role"}, PrivateReference: uuid.NewString(), PrivateDigest: ports.Digest{1}}
	history, err := domain.Decide(domain.Change{}, domain.Command{Kind: "SUBMIT", At: now, Submission: &initial})
	if err != nil {
		t.Fatal(err)
	}
	c := history[0].Change
	if _, err := domain.Decide(c, domain.Command{Kind: "VERIFIED", At: now, Verified: true}); err == nil {
		t.Fatal("submitted executed directly")
	}
	envelope := &domain.Envelope{TenantID: c.TenantID, RequestID: c.ID, Requester: c.Requester, ExpiresAt: now.Add(time.Hour)}
	events, err := domain.Decide(c, domain.Command{Kind: "ASSESS", At: now, Decision: domain.Decision{Outcome: "REQUIRE_APPROVAL", Reasons: []string{"sensitive"}, Groups: []string{"security"}, Quorum: 2}, Envelope: envelope, Digest: ports.Digest{2}})
	if err != nil {
		t.Fatal(err)
	}
	history = append(history, events...)
	c = events[len(events)-1].Change
	approve := func(actor string, cred byte) error {
		e, err := domain.Decide(c, domain.Command{Kind: "APPROVE", At: now, Approval: &domain.Approval{ActorID: actor, CredentialID: []byte{cred}, Digest: c.Digest, VerifiedAt: now}})
		if err == nil {
			history = append(history, e...)
			c = e[len(e)-1].Change
		}
		return err
	}
	if approve("requester", 1) == nil {
		t.Fatal("self approval")
	}
	if err := approve("alice", 1); err != nil {
		t.Fatal(err)
	}
	if approve("alice", 2) == nil || approve("bob", 1) == nil {
		t.Fatal("multiple credentials or duplicate credential counted twice")
	}
	if err := approve("bob", 2); err != nil {
		t.Fatal(err)
	}
	if c.State != domain.Approved {
		t.Fatal(c.State)
	}
	e, err := domain.Decide(c, domain.Command{Kind: "CONTEXT_CHANGED", At: now, Reason: "context changed"})
	if err != nil || len(e[0].Change.Approvals) != 0 || e[0].Change.Envelope != nil {
		t.Fatal("stale approvals retained", err)
	}
	e, err = domain.Decide(c, domain.Command{Kind: "DISPATCH", At: now, Digest: c.Digest, ExecutionID: "exec"})
	if err != nil {
		t.Fatal(err)
	}
	history = append(history, e...)
	c = e[0].Change
	if _, err := domain.Decide(c, domain.Command{Kind: "VERIFIED", At: now, ExecutionID: "exec"}); err == nil {
		t.Fatal("write ACK counted as readback")
	}
	e, err = domain.Decide(c, domain.Command{Kind: "VERIFIED", At: now, ExecutionID: "exec", Verified: true})
	if err != nil {
		t.Fatal(err)
	}
	history = append(history, e...)
	replay, err := domain.Replay(history)
	if err != nil || replay.State != domain.Executed {
		t.Fatal(replay.State, err)
	}
	if history[0].Change.State != domain.Submitted || len(history[3].Change.Approvals) != 1 {
		t.Fatal("later commands mutated old evidence")
	}
}
func TestValidationExpiryAndReassessment(t *testing.T) {
	if (domain.Intent{Kind: "UNKNOWN", Target: "a"}).Validate() == nil {
		t.Fatal("unknown kind accepted")
	}
	if (domain.Intent{Kind: "ROLE_ASSIGN", Target: "a", Access: "r", DurationSeconds: -1}).Validate() == nil {
		t.Fatal("negative expiry")
	}
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	c := domain.Change{ID: uuid.NewString(), TenantID: "t", Requester: "a", State: domain.Held, Revision: 3}
	e, err := domain.Decide(c, domain.Command{Kind: "ASSESS", At: now, Decision: domain.Decision{Outcome: "HOLD", Reasons: []string{"missing policy"}}})
	if err != nil || len(e) != 2 || e[1].Change.State != domain.Held {
		t.Fatal(err)
	}
	c.State = domain.AwaitingApproval
	c.Envelope = &domain.Envelope{ExpiresAt: now}
	if _, err := domain.Decide(c, domain.Command{Kind: "APPROVE", At: now, Approval: &domain.Approval{ActorID: "b"}}); err == nil {
		t.Fatal("expired approval accepted")
	}
	e, err = domain.Decide(c, domain.Command{Kind: "EXPIRE", At: now})
	if err != nil || e[0].Change.State != domain.Expired {
		t.Fatal(err)
	}
}
