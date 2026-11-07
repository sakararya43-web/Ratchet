package domain_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"pgregory.net/rapid"
)

func TestRandomApprovalAndContextSequencesNeverReuseStaleAuthorization(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
		c := domain.Change{ID: "6affd352-e70b-4472-92b7-68e6f5ad251b", TenantID: "tenant", Requester: "requester", Revision: 1, State: domain.Submitted, Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: "target", Access: "role"}, PrivateReference: uuid.Nil.String(), PrivateDigest: ports.Digest{1}}
		oldDigests := []ports.Digest{}
		for step := range 40 {
			if c.State == domain.Submitted || c.State == domain.Held {
				digest, err := canon.New().Digest(struct{ Step int }{step})
				if err != nil {
					t.Fatal(err)
				}
				events, err := domain.Decide(c, domain.Command{Kind: "ASSESS", At: now, Decision: domain.Decision{Outcome: "REQUIRE_APPROVAL", Reasons: []string{"sensitive"}, Groups: []string{"security"}, Quorum: 2}, Envelope: &domain.Envelope{TenantID: c.TenantID, RequestID: c.ID, Requester: c.Requester, ExpiresAt: now.Add(time.Hour)}, Digest: digest})
				if err != nil {
					t.Fatal(err)
				}
				c = events[len(events)-1].Change
			}
			if rapid.IntRange(0, 3).Draw(t, fmt.Sprintf("change-%d", step)) == 0 {
				oldDigests = append(oldDigests, c.Digest)
				events, err := domain.Decide(c, domain.Command{Kind: "CONTEXT_CHANGED", At: now, Reason: "context changed"})
				if err != nil {
					t.Fatal(err)
				}
				c = events[0].Change
				if len(c.Approvals) != 0 || c.Envelope != nil {
					t.Fatal("R3: context change retained approval")
				}
				continue
			}
			for _, old := range oldDigests {
				if _, err := domain.Decide(c, domain.Command{Kind: "DISPATCH", At: now, Digest: old, ExecutionID: "execution"}); err == nil {
					t.Fatal("R3: stale digest dispatched changed context")
				}
			}
			actor := fmt.Sprintf("approver:%d", rapid.IntRange(0, 2).Draw(t, fmt.Sprintf("human-%d", step)))
			credential := byte(rapid.IntRange(1, 5).Draw(t, fmt.Sprintf("credential-%d", step)))
			events, err := domain.Decide(c, domain.Command{Kind: "APPROVE", At: now, Approval: &domain.Approval{ActorID: actor, CredentialID: []byte{credential}, Digest: c.Digest, VerifiedAt: now}})
			if err == nil {
				c = events[len(events)-1].Change
			}
			seen := map[string]bool{}
			for _, approval := range c.Approvals {
				if seen[approval.ActorID] {
					t.Fatal("one human counted twice")
				}
				seen[approval.ActorID] = true
			}
		}
	})
}
