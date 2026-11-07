//go:build integration

package workflow_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestInlineDecisionConsumesExactApprovedCommandOnceAcrossConcurrentCallersAndRestart(t *testing.T) {
	sys, s, c, _, replacement := readyExecution(t)
	object, err := canon.New().Digest(c.Intent)
	if err != nil {
		t.Fatal(err)
	}
	input := workflow.InlineInput{Intent: c.Intent, AdmissionID: c.ExecutionID, ObjectDigest: object, TargetRevision: "10", ApprovedRequest: c.ID, MinGraphVersion: c.Envelope.GraphVersion}
	actor := workflow.Actor{TenantID: sys.tenant, ID: c.Requester}
	var wg sync.WaitGroup
	results := make(chan workflow.InlineDecision, 2)
	errorsOut := make(chan error, 2)
	for range 2 {
		wg.Go(func() { result, err := s.DecideInline(sys.ctx, actor, input); results <- result; errorsOut <- err })
	}
	wg.Wait()
	close(results)
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	allows := 0
	for result := range results {
		if result.ExecutionAuthorized {
			allows++
			if result.Decision.Outcome != "ALLOW" || result.ObjectDigest != object || result.ExpiresAt.IsZero() {
				t.Fatal("incomplete authorization binding")
			}
		} else if result.Decision.Outcome != "HOLD" {
			t.Fatal("replay did not fail closed")
		}
	}
	if allows != 1 {
		t.Fatal("concurrent admission consumption", allows)
	}
	next := replacement()
	retry, err := next.DecideInline(sys.ctx, actor, input)
	if err != nil || retry.ExecutionAuthorized || retry.Decision.Outcome != "HOLD" {
		t.Fatal("restart reused allow", err)
	}
	input.ObjectDigest = ports.Digest{9}
	if _, err := next.DecideInline(sys.ctx, actor, input); !errors.Is(err, eventstore.ErrIdempotencyConflict) {
		t.Fatal("admission reused for another object", err)
	}
	var evidence int
	if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		return tx.QueryRow(sys.ctx, `SELECT count(*) FROM ratchet.events WHERE tenant_id=$1 AND event_type='InlineDecisionRecorded'`, sys.tenant).Scan(&evidence)
	}); err != nil || evidence != 1 {
		t.Fatal("enforcement evidence missing/duplicated", evidence, err)
	}
	got, err := sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
	if err != nil || got.State != domain.Executing {
		t.Fatal("inline decision invented target verification", err)
	}
}

func TestInlineDecisionRefusesMismatchedObjectRevisionAndUnapprovedGrants(t *testing.T) {
	for _, mismatch := range []string{"object", "revision"} {
		t.Run(mismatch, func(t *testing.T) {
			sys, s, c, _, _ := readyExecution(t)
			digest, _ := canon.New().Digest(c.Intent)
			input := workflow.InlineInput{Intent: c.Intent, AdmissionID: c.ExecutionID, ObjectDigest: digest, TargetRevision: "10", ApprovedRequest: c.ID}
			if mismatch == "object" {
				input.ObjectDigest = ports.Digest{5}
			} else {
				input.TargetRevision = "11"
			}
			result, err := s.DecideInline(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: c.Requester}, input)
			if err != nil || result.ExecutionAuthorized || result.Decision.Outcome != "HOLD" {
				t.Fatal("mismatched admission allowed", err)
			}
		})
	}
	sys := setup(t)
	s, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	intent := domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:admin"}
	digest, _ := canon.New().Digest(intent)
	result, err := s.DecideInline(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, workflow.InlineInput{Intent: intent, AdmissionID: uuid.NewString(), ObjectDigest: digest, TargetRevision: "10"})
	if err != nil || result.ExecutionAuthorized || result.Decision.Outcome != "REQUIRE_APPROVAL" || result.Decision.Quorum != 2 {
		t.Fatal("unapproved tier-0 grant bypassed policy", err)
	}
}
