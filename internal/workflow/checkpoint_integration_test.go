//go:build integration

package workflow_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/trust"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func signCheckpoint(t *testing.T, sys system, p workflow.CheckpointProposal) trust.AuditCheckpoint {
	t.Helper()
	signed := p.Candidate.Checkpoint
	digest := trust.ComputeCheckpointSigningDigest(sys.tenant, signed.Epoch, signed.CheckpointDigest)
	signature, err := ecdsa.SignASN1(rand.Reader, sys.authorityKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.authority.SignCheckpoint(&signed, trust.MemberSignature{ActorID: "authority-leader", Signature: signature}); err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestCheckpointsPersistVerifiedContinuityAndExcludeTheirOwnReference(t *testing.T) {
	sys := setup(t)
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	ordinary := workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}
	input := workflow.PrepareCheckpointInput{CommandID: uuid.New()}
	if _, err := service.PrepareCheckpoint(sys.ctx, ordinary, input); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("unauthorized checkpoint preparation", err)
	}
	p, err := service.PrepareCheckpoint(sys.ctx, actor, input)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := service.PrepareCheckpoint(sys.ctx, actor, input)
	if err != nil || duplicate.Candidate.Checkpoint.CheckpointDigest != p.Candidate.Checkpoint.CheckpointDigest || !duplicate.CreatedAt.Equal(p.CreatedAt) {
		t.Fatal("candidate retry changed frozen tip", err)
	}
	changed := input
	changed.EndSequence = 1
	if _, err := service.PrepareCheckpoint(sys.ctx, actor, changed); !errors.Is(err, eventstore.ErrIdempotencyConflict) {
		t.Fatal("candidate retry changed input", err)
	}
	competitor, err := service.PrepareCheckpoint(sys.ctx, actor, workflow.PrepareCheckpointInput{CommandID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	signed := signCheckpoint(t, sys, p)
	invalid := signed
	invalid.Signatures = []trust.MemberSignature{{ActorID: "authority-leader", Signature: []byte("forged")}}
	if _, err := service.AcceptCheckpoint(sys.ctx, actor, invalid); !errors.Is(err, domain.ErrInvalid) {
		t.Fatal("forged quorum was accepted", err)
	}
	if _, err := service.AcceptCheckpoint(sys.ctx, ordinary, signed); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("unauthorized checkpoint acceptance", err)
	}
	var wg sync.WaitGroup
	results := make(chan workflow.CheckpointRecord, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := service.AcceptCheckpoint(sys.ctx, actor, signed)
			if err != nil {
				t.Error(err)
				return
			}
			results <- r
		}()
	}
	wg.Wait()
	close(results)
	var first workflow.CheckpointRecord
	for r := range results {
		if first.ReferenceSequence != 0 && first.ReferenceSequence != r.ReferenceSequence {
			t.Fatal("acceptance forked on retry")
		}
		first = r
	}
	if first.ReferenceSequence <= signed.ToSequence {
		t.Fatal("checkpoint included its own acceptance")
	}
	if _, err := service.AcceptCheckpoint(sys.ctx, actor, signCheckpoint(t, sys, competitor)); !errors.Is(err, domain.ErrContextChanged) {
		t.Fatal("competing range accepted after head advanced", err)
	}
	next, err := service.PrepareCheckpoint(sys.ctx, actor, workflow.PrepareCheckpointInput{CommandID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	if next.Candidate.Checkpoint.FromSequence != signed.ToSequence+1 || next.Candidate.Checkpoint.PriorCheckpointDigest != signed.CheckpointDigest || next.Candidate.PreviousEventHash != p.Candidate.LastEventHash || next.Candidate.Checkpoint.ToSequence < first.ReferenceSequence {
		t.Fatal("continuity or subsequent reference coverage lost")
	}
	second, err := service.AcceptCheckpoint(sys.ctx, actor, signCheckpoint(t, sys, next))
	if err != nil {
		t.Fatal(err)
	}
	records, end, err := service.Checkpoints(sys.ctx, actor, 0, 0, 1)
	if err != nil || len(records) != 1 || records[0].ReferenceSequence != first.ReferenceSequence {
		t.Fatal("checkpoint export", err)
	}
	tail, _, err := service.Checkpoints(sys.ctx, actor, first.ReferenceSequence, end, 10)
	if err != nil || len(tail) != 1 || tail[0].ReferenceSequence != second.ReferenceSequence {
		t.Fatal("fixed tip checkpoint continuation", err)
	}
	before, _, err := service.Checkpoints(sys.ctx, actor, 0, first.ReferenceSequence-1, 10)
	if err != nil || len(before) != 0 {
		t.Fatal("checkpoint escaped captured ledger tip", err)
	}
	if _, _, err := service.Checkpoints(sys.ctx, ordinary, 0, 0, 10); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("ordinary user obtained signing evidence", err)
	}
	// A replacement process needs no Authority file to read the frozen proof.
	replacement, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := replacement.AcceptCheckpoint(sys.ctx, actor, signed)
	if err != nil || restored.ReferenceSequence != first.ReferenceSequence {
		t.Fatal("durable acceptance recovery", err)
	}
	for _, table := range []string{"checkpoint_candidates", "accepted_checkpoints"} {
		err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
			_, err := tx.Exec(sys.ctx, `DELETE FROM ratchet.`+table+` WHERE tenant_id=$1`, sys.tenant)
			return err
		})
		if err == nil {
			t.Fatal("runtime could erase checkpoint evidence", table)
		}
	}
	events, err := sys.store.LoadStream(sys.ctx, sys.tenant, "checkpoint:"+signed.CheckpointDigest.String())
	if err != nil || len(events) != 2 {
		t.Fatal("acceptance appended more than once", err)
	}
	raw, err := json.Marshal(first)
	if err != nil || len(raw) == 0 {
		t.Fatal(err)
	}
	if _, _, err := sys.store.VerifyTenant(sys.ctx, sys.tenant); err != nil {
		t.Fatal(err)
	}
}
