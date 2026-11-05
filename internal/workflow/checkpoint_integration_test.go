//go:build integration

package workflow_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestCheckpointDefaultBoundsLargeEventBytesAndContinuesWithoutGaps(t *testing.T) {
	sys := setup(t)
	// This intentionally appends and independently canonicalizes/verifies over
	// 16 MiB several times. Allow race instrumentation's CPU cost without changing
	// production HTTP or workflow deadlines.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	// Keep the same large document volume with bounded evidence fields. A single
	// nearly-megabyte string instead stresses the peer canonicalizer's string
	// handling, independently of checkpoint range selection.
	chunks := make([]string, 3500)
	for i := range chunks {
		chunks[i] = strings.Repeat("x", 256)
	}
	facts, err := json.Marshal(map[string][]string{"evidence": chunks})
	if err != nil {
		t.Fatal(err)
	}
	events := make([]eventstore.Event, 20)
	for i := range events {
		events[i] = eventstore.Event{Type: "LargeCheckpointEvidence", Facts: facts}
	}
	receipt, err := sys.store.Append(ctx, eventstore.Command{TenantID: sys.tenant, ID: uuid.New(), ActorReference: uuid.New(), StreamID: "checkpoint:large-evidence", Events: events})
	if err != nil {
		t.Fatal(err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	if _, err := service.PrepareCheckpoint(ctx, actor, workflow.PrepareCheckpointInput{CommandID: uuid.New(), EndSequence: receipt.LastSequence}); !errors.Is(err, domain.ErrInvalid) {
		t.Fatal("explicit oversized range was silently trimmed or accepted", err)
	}
	p, err := service.PrepareCheckpoint(ctx, actor, workflow.PrepareCheckpointInput{CommandID: uuid.New()})
	if err != nil {
		t.Fatal("automatic range did not fit the byte budget", err)
	}
	to := p.Candidate.Checkpoint.ToSequence
	var total, next int64
	if err := sys.store.WithTenantTx(ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		if err := tx.QueryRow(ctx, `SELECT sum(octet_length(canonical_content)) FROM ratchet.events WHERE tenant_id=$1 AND sequence<=$2`, sys.tenant, to).Scan(&total); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT octet_length(canonical_content) FROM ratchet.events WHERE tenant_id=$1 AND sequence=$2`, sys.tenant, to+1).Scan(&next)
	}); err != nil {
		t.Fatal(err)
	}
	if to >= receipt.LastSequence || total > 16<<20 || total+next <= 16<<20 {
		t.Fatal("default did not select the maximal bounded prefix", to, total, next)
	}
	if _, err := service.AcceptCheckpoint(ctx, actor, signCheckpoint(t, sys, p)); err != nil {
		t.Fatal(err)
	}
	successor, err := service.PrepareCheckpoint(ctx, actor, workflow.PrepareCheckpointInput{CommandID: uuid.New()})
	if err != nil || successor.Candidate.Checkpoint.FromSequence != to+1 || successor.Candidate.Checkpoint.ToSequence < receipt.LastSequence || successor.Candidate.Checkpoint.PriorCheckpointDigest != p.Candidate.Checkpoint.CheckpointDigest {
		t.Fatal("large-event catch-up skipped or stalled the remainder", err)
	}
	if _, err := service.AcceptCheckpoint(ctx, actor, signCheckpoint(t, sys, successor)); err != nil {
		t.Fatal(err)
	}
}

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

func TestCheckpointRotationRejectsPendingOldEpochAndRetainsAcceptedEvidence(t *testing.T) {
	sys := setup(t)
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	first, err := service.PrepareCheckpoint(sys.ctx, actor, workflow.PrepareCheckpointInput{CommandID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AcceptCheckpoint(sys.ctx, actor, signCheckpoint(t, sys, first)); err != nil {
		t.Fatal(err)
	}
	pending, err := service.PrepareCheckpoint(sys.ctx, actor, workflow.PrepareCheckpointInput{CommandID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	oldSigned := signCheckpoint(t, sys, pending)
	genesis, err := sys.authority.GetGenesis()
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := sys.authority.ProposeRegistryChange(sys.tenant, 1, 1, genesis.Members)
	if err != nil {
		t.Fatal(err)
	}
	challenge := trust.ComputeRegistrySigningDigest(sys.tenant, 1, 2, rotation.ProposalDigest)
	signature, err := ecdsa.SignASN1(rand.Reader, sys.authorityKey, challenge[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.authority.SignRegistryProposal(rotation.ProposalID, trust.MemberSignature{ActorID: "authority-leader", Signature: signature}); err != nil {
		t.Fatal(err)
	}
	if _, err := sys.authority.ActivateRegistryProposal(rotation.ProposalID); err != nil {
		t.Fatal(err)
	}
	manager := policy.Manager{Store: sys.store, Engine: sys.engine, Authority: sys.authority, Root: sys.root, Tenant: sys.tenant}
	if err := manager.RefreshRegistry(sys.ctx); err != nil {
		t.Fatal(err)
	}
	modules := map[string]string{}
	for _, name := range []string{"change.rego", "authz.rego"} {
		raw, err := os.ReadFile("../../policies/" + name)
		if err != nil {
			t.Fatal(err)
		}
		modules[name] = string(raw)
	}
	bundle, err := sys.authority.ProposeBundle(sys.tenant, "2.0.0", "checkpoint epoch transition", modules, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	bundleChallenge := trust.ComputePolicySigningDigest(sys.tenant, 2, bundle.BundleDigest)
	bundleSignature, err := ecdsa.SignASN1(rand.Reader, sys.authorityKey, bundleChallenge[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.authority.SignProposal(bundle.ProposalID, trust.MemberSignature{ActorID: "authority-leader", Signature: bundleSignature}); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Activate(sys.ctx, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AcceptCheckpoint(sys.ctx, actor, oldSigned); !errors.Is(err, domain.ErrContextChanged) {
		t.Fatal("old epoch newly accepted after observed rotation", err)
	}
	next, err := service.PrepareCheckpoint(sys.ctx, actor, workflow.PrepareCheckpointInput{CommandID: uuid.New()})
	if err != nil || next.Candidate.Checkpoint.Epoch != 2 {
		t.Fatal("new checkpoint did not bind rotated registry", err)
	}
	if _, err := service.AcceptCheckpoint(sys.ctx, actor, signCheckpoint(t, sys, next)); err != nil {
		t.Fatal(err)
	}
	history, _, err := service.Checkpoints(sys.ctx, actor, 0, 0, 10)
	if err != nil || len(history) != 2 || history[0].Evidence.Signed.Epoch != 1 || history[1].Evidence.Signed.Epoch != 2 {
		t.Fatal("historical signatures lost on rotation", err)
	}
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
	chain, err := service.ExportAudit(sys.ctx, actor, 0, 0, 100, nil, nil)
	if err != nil || chain.After != chain.End {
		t.Fatal("checkpoint history fixture needs the complete chain", err)
	}
	records, _, err = service.Checkpoints(sys.ctx, actor, 0, chain.End, 10)
	if err != nil {
		t.Fatal(err)
	}
	history := workflow.CheckpointHistory{Profile: workflow.CheckpointHistoryProfile, Tenant: sys.tenant, Checkpoints: records}
	for _, event := range chain.Events {
		history.Events = append(history.Events, workflow.CheckpointChainEvent{Canonical: event.Entry.Canonical, Previous: event.Entry.Previous, Hash: event.Entry.Hash})
	}
	verified, err := workflow.VerifyCheckpointHistory(sys.ctx, history, sys.root, chain.EndHash)
	if err != nil || verified.VerifiedEvents != chain.End || verified.CoveredThrough != second.Evidence.Signed.ToSequence {
		t.Fatal("real database export failed independent checkpoint history verification", err)
	}
	// Runtime INSERT privilege cannot turn an alias of genuine signed evidence
	// into a different accepted range or an extra reference in evidence exports.
	if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		alias := ports.Digest{99}
		if _, err := tx.Exec(sys.ctx, `INSERT INTO ratchet.checkpoint_candidates(tenant_id,digest,command_id,input_digest,document,event_position) SELECT tenant_id,$2,$3,input_digest,document,event_position FROM ratchet.checkpoint_candidates WHERE tenant_id=$1 AND digest=$4`, sys.tenant, alias.Bytes(), uuid.New(), signed.CheckpointDigest.Bytes()); err != nil {
			return err
		}
		_, err := tx.Exec(sys.ctx, `INSERT INTO ratchet.accepted_checkpoints(tenant_id,digest,from_sequence,to_sequence,document,event_position) SELECT tenant_id,$2,2,to_sequence+1,document,event_position FROM ratchet.accepted_checkpoints WHERE tenant_id=$1 AND digest=$3`, sys.tenant, alias.Bytes(), signed.CheckpointDigest.Bytes())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Checkpoints(sys.ctx, actor, 0, 0, 10); !errors.Is(err, eventstore.ErrIntegrity) {
		t.Fatal("forged checkpoint ordering metadata was trusted", err)
	}
}
