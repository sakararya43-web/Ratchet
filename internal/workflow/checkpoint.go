package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

// CheckpointProposal freezes the candidate before any request to the Authority.
// Its evidence does not contain keys capable of producing a signature.
type CheckpointProposal struct {
	Candidate      ledger.CheckpointCandidate `json:"candidate"`
	RegistryProof  json.RawMessage            `json:"registry_proof"`
	RegistryDigest ports.Digest               `json:"registry_digest"`
	Root           ports.Digest               `json:"genesis_digest"`
	CreatedAt      time.Time                  `json:"created_at"`
}
type CheckpointEvidence struct {
	Proposal   CheckpointProposal    `json:"proposal"`
	Signed     trust.AuditCheckpoint `json:"signed_checkpoint"`
	AcceptedAt time.Time             `json:"accepted_at"`
}
type CheckpointRecord struct {
	Evidence          CheckpointEvidence `json:"evidence"`
	ReferenceSequence int64              `json:"reference_sequence"`
}
type PrepareCheckpointInput struct {
	CommandID   uuid.UUID
	EndSequence int64
}

// checkpointEntries bounds both event count and bytes. An operator can catch up
// with several consecutive checkpoints rather than allocating an unbounded log.
func (s *Service) checkpointEntries(ctx context.Context, tx pgx.Tx, tenant string, from, to int64, previous ports.Digest) ([]ledger.Entry, error) {
	if from < 1 || to < from || to-from >= 4096 {
		return nil, domain.ErrInvalid
	}
	entries := []ledger.Entry{}
	after, head, size := from-1, previous, 0
	for after < to {
		page, err := s.Store.ExportWithin(ctx, tx, tenant, after, to, 100, &head, nil)
		if err != nil {
			return nil, err
		}
		for _, event := range page.Events {
			size += len(event.Entry.Canonical)
			if size > 16<<20 {
				return nil, domain.ErrInvalid
			}
			entries = append(entries, event.Entry)
		}
		after, head = page.After, page.LastHash
	}
	return entries, nil
}

func checkpointFacts(event eventstore.StoredEvent, expected any) error {
	var content ledger.Content
	var payload struct {
		Facts json.RawMessage `json:"facts"`
	}
	if json.Unmarshal(event.Entry.Canonical, &content) != nil || json.Unmarshal(content.Payload, &payload) != nil {
		return eventstore.ErrIntegrity
	}
	actual, err := canon.New().Canonicalize(payload.Facts)
	if err != nil {
		return eventstore.ErrIntegrity
	}
	wantRaw, err := checkpointEventFacts(expected)
	if err != nil {
		return err
	}
	want, err := canon.New().Canonicalize(json.RawMessage(wantRaw))
	if err != nil || !bytes.Equal(actual, want) {
		return eventstore.ErrIntegrity
	}
	return nil
}

// The Authority proof contains its original member display fields. Preserve
// those signature-bound bytes in the restricted immutable artifact, while the
// public ledger binds the artifact by digest without copying personal fields.
func checkpointEventFacts(document any) ([]byte, error) {
	digest, err := canon.New().Digest(document)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"format_version": 1, "checkpoint_document_digest": digest.String()})
}

func (s *Service) checkpointProposal(ctx context.Context, tx pgx.Tx, tenant string, digest, root ports.Digest) (CheckpointProposal, error) {
	var p CheckpointProposal
	var raw []byte
	var position int64
	if err := tx.QueryRow(ctx, `SELECT document,event_position FROM ratchet.checkpoint_candidates WHERE tenant_id=$1 AND digest=$2`, tenant, digest.Bytes()).Scan(&raw, &position); err != nil {
		return p, err
	}
	if json.Unmarshal(raw, &p) != nil || p.Candidate.Checkpoint.CheckpointDigest != digest || p.Candidate.Checkpoint.TenantID != tenant || p.Root != root {
		return p, eventstore.ErrIntegrity
	}
	r, err := policy.VerifyRegistry(p.RegistryProof, root, tenant)
	if err != nil || r.Digest != p.RegistryDigest || r.Epoch != p.Candidate.Checkpoint.Epoch {
		return p, eventstore.ErrIntegrity
	}
	events, err := s.Store.StreamWithin(ctx, tx, tenant, "checkpoint:"+digest.String())
	if err != nil {
		return p, err
	}
	if len(events) == 0 || events[0].Sequence != position || events[0].Type != "AuditCheckpointPrepared" || position <= p.Candidate.Checkpoint.ToSequence {
		return p, eventstore.ErrIntegrity
	}
	if err := checkpointFacts(events[0], p); err != nil {
		return p, err
	}
	return p, nil
}

func (s *Service) checkpointRecord(ctx context.Context, tx pgx.Tx, tenant string, raw []byte, position int64, root ports.Digest) (CheckpointRecord, error) {
	record := CheckpointRecord{ReferenceSequence: position}
	if json.Unmarshal(raw, &record.Evidence) != nil {
		return record, eventstore.ErrIntegrity
	}
	e := record.Evidence
	// Ordering/filter columns are not proof. Check them against the immutable
	// artifact and reject aliases of one ledger reference under another digest.
	var references int64
	var metadataMatches bool
	if err := tx.QueryRow(ctx, `SELECT count(*),coalesce(bool_and(digest=$3 AND from_sequence=$4 AND to_sequence=$5 AND document=$6),false) FROM ratchet.accepted_checkpoints WHERE tenant_id=$1 AND event_position=$2`, tenant, position, e.Signed.CheckpointDigest.Bytes(), e.Signed.FromSequence, e.Signed.ToSequence, raw).Scan(&references, &metadataMatches); err != nil {
		return record, err
	}
	if references != 1 || !metadataMatches {
		return record, eventstore.ErrIntegrity
	}
	p, err := s.checkpointProposal(ctx, tx, tenant, e.Signed.CheckpointDigest, root)
	if err != nil {
		return record, err
	}
	expected, err := canon.New().Digest(p)
	if err != nil {
		return record, err
	}
	actual, err := canon.New().Digest(e.Proposal)
	if err != nil || actual != expected || position <= e.Signed.ToSequence {
		return record, eventstore.ErrIntegrity
	}
	r, err := policy.VerifyRegistry(p.RegistryProof, root, tenant)
	if err != nil || r.VerifyCheckpoint(p.Candidate, e.Signed) != nil {
		return record, eventstore.ErrIntegrity
	}
	events, err := s.Store.StreamWithin(ctx, tx, tenant, "checkpoint:"+e.Signed.CheckpointDigest.String())
	if err != nil {
		return record, err
	}
	if len(events) != 2 || events[1].Sequence != position || events[1].Type != "AuditCheckpointAccepted" {
		return record, eventstore.ErrIntegrity
	}
	if err := checkpointFacts(events[1], e); err != nil {
		return record, err
	}
	return record, nil
}

func (s *Service) latestCheckpoint(ctx context.Context, tx pgx.Tx, tenant string, end int64, root ports.Digest) (*CheckpointRecord, error) {
	var raw []byte
	var position int64
	err := tx.QueryRow(ctx, `SELECT document,event_position FROM ratchet.accepted_checkpoints WHERE tenant_id=$1 AND ($2::bigint=0 OR event_position<=$2) ORDER BY to_sequence DESC LIMIT 1`, tenant, end).Scan(&raw, &position)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	record, err := s.checkpointRecord(ctx, tx, tenant, raw, position, root)
	return &record, err
}

func (s *Service) PrepareCheckpoint(ctx context.Context, actor Actor, input PrepareCheckpointInput) (CheckpointProposal, error) {
	var proposal CheckpointProposal
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, now time.Time) error {
		var err error
		proposal, err = s.prepareCheckpointWithin(ctx, tx, now, actor, input)
		return err
	})
	return proposal, err
}

func (s *Service) prepareCheckpointWithin(ctx context.Context, tx pgx.Tx, now time.Time, actor Actor, input PrepareCheckpointInput) (CheckpointProposal, error) {
	var proposal CheckpointProposal
	if input.CommandID == uuid.Nil || input.EndSequence < 0 || input.EndSequence > ledger.MaxSafeInteger {
		return proposal, domain.ErrInvalid
	}
	fingerprint, err := canon.New().Digest(struct {
		Actor Actor
		Input PrepareCheckpointInput
	}{actor, input})
	if err != nil {
		return proposal, err
	}
	err = func() error {
		_, active, err := s.context(ctx, tx, actor, "checkpoint_manage", nil)
		if err != nil {
			return err
		}
		var oldInput, oldDigest []byte
		err = tx.QueryRow(ctx, `SELECT input_digest,digest FROM ratchet.checkpoint_candidates WHERE tenant_id=$1 AND command_id=$2`, actor.TenantID, input.CommandID).Scan(&oldInput, &oldDigest)
		if err == nil {
			if !bytes.Equal(oldInput, fingerprint[:]) {
				return eventstore.ErrIdempotencyConflict
			}
			digest, err := ports.DigestFromBytes(oldDigest)
			if err != nil {
				return eventstore.ErrIntegrity
			}
			proposal, err = s.checkpointProposal(ctx, tx, actor.TenantID, digest, active.Root)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		prior, err := s.latestCheckpoint(ctx, tx, actor.TenantID, 0, active.Root)
		if err != nil {
			return err
		}
		from := int64(1)
		var previous, priorDigest ports.Digest
		if prior != nil {
			from = prior.Evidence.Signed.ToSequence + 1
			previous = prior.Evidence.Proposal.Candidate.LastEventHash
			priorDigest = prior.Evidence.Signed.CheckpointDigest
		}
		var head int64
		if err := tx.QueryRow(ctx, `SELECT sequence FROM ratchet.tenant_heads WHERE tenant_id=$1`, actor.TenantID).Scan(&head); err != nil {
			return err
		}
		end := input.EndSequence
		if end == 0 {
			end = min(head, from+4095)
		}
		if end > head {
			return domain.ErrInvalid
		}
		entries, err := s.checkpointEntries(ctx, tx, actor.TenantID, from, end, previous)
		if err != nil {
			return err
		}
		candidate, err := ledger.BuildCheckpoint(actor.TenantID, active.RegistryEpoch, from, end, previous, priorDigest, entries)
		if err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ratchet.checkpoint_candidates WHERE tenant_id=$1 AND digest=$2)`, actor.TenantID, candidate.Checkpoint.CheckpointDigest.Bytes()).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return eventstore.ErrVersionConflict
		}
		proposal = CheckpointProposal{candidate, json.RawMessage(active.TrustProof), active.RegistryDigest, active.Root, now}
		raw, err := json.Marshal(proposal)
		if err != nil {
			return err
		}
		facts, err := checkpointEventFacts(proposal)
		if err != nil {
			return err
		}
		receipt, err := s.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: actor.TenantID, ID: input.CommandID, StreamID: "checkpoint:" + candidate.Checkpoint.CheckpointDigest.String(), ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":"+actor.ID)), Events: []eventstore.Event{{Type: "AuditCheckpointPrepared", Facts: facts}}})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ratchet.checkpoint_candidates(tenant_id,digest,command_id,input_digest,document,event_position) VALUES($1,$2,$3,$4,$5,$6)`, actor.TenantID, candidate.Checkpoint.CheckpointDigest.Bytes(), input.CommandID, fingerprint.Bytes(), raw, receipt.LastSequence)
		return err
	}()
	return proposal, err
}

func (s *Service) AcceptCheckpoint(ctx context.Context, actor Actor, signed trust.AuditCheckpoint) (CheckpointRecord, error) {
	var record CheckpointRecord
	if signed.TenantID != actor.TenantID || signed.CheckpointDigest.IsZero() || len(signed.Signatures) > 256 {
		return record, domain.ErrInvalid
	}
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, now time.Time) error {
		_, active, err := s.context(ctx, tx, actor, "checkpoint_manage", nil)
		if err != nil {
			return err
		}
		p, err := s.checkpointProposal(ctx, tx, actor.TenantID, signed.CheckpointDigest, active.Root)
		if err != nil {
			return err
		}
		registry, err := policy.VerifyRegistry(p.RegistryProof, active.Root, actor.TenantID)
		if err != nil || registry.VerifyCheckpoint(p.Candidate, signed) != nil {
			return domain.ErrInvalid
		}
		var old []byte
		var position int64
		err = tx.QueryRow(ctx, `SELECT document,event_position FROM ratchet.accepted_checkpoints WHERE tenant_id=$1 AND digest=$2`, actor.TenantID, signed.CheckpointDigest.Bytes()).Scan(&old, &position)
		if err == nil {
			record, err = s.checkpointRecord(ctx, tx, actor.TenantID, old, position, active.Root)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		prior, err := s.latestCheckpoint(ctx, tx, actor.TenantID, 0, active.Root)
		if err != nil {
			return err
		}
		from := int64(1)
		var priorDigest, previous ports.Digest
		if prior != nil {
			from = prior.Evidence.Signed.ToSequence + 1
			priorDigest = prior.Evidence.Signed.CheckpointDigest
			previous = prior.Evidence.Proposal.Candidate.LastEventHash
		}
		if signed.FromSequence != from || signed.PriorCheckpointDigest != priorDigest || p.Candidate.PreviousEventHash != previous {
			return domain.ErrContextChanged
		}
		// A rotation invalidates pending candidates. Historical accepted evidence can
		// still be verified using its frozen registry, without trusting retired keys
		// to authorize a new acceptance after the observed rotation.
		if registry.Digest != active.RegistryDigest {
			return domain.ErrContextChanged
		}
		entries, err := s.checkpointEntries(ctx, tx, actor.TenantID, from, signed.ToSequence, previous)
		if err != nil {
			return err
		}
		rebuilt, err := ledger.BuildCheckpoint(actor.TenantID, signed.Epoch, from, signed.ToSequence, previous, priorDigest, entries)
		if err != nil || rebuilt.Checkpoint.CheckpointDigest != signed.CheckpointDigest || rebuilt.LastEventHash != p.Candidate.LastEventHash {
			return eventstore.ErrIntegrity
		}
		evidence := CheckpointEvidence{p, signed, now}
		raw, err := json.Marshal(evidence)
		if err != nil {
			return err
		}
		facts, err := checkpointEventFacts(evidence)
		if err != nil {
			return err
		}
		receipt, err := s.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: actor.TenantID, ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":checkpoint-accept:"+signed.CheckpointDigest.String())), StreamID: "checkpoint:" + signed.CheckpointDigest.String(), ExpectedVersion: 1, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":"+actor.ID)), Events: []eventstore.Event{{Type: "AuditCheckpointAccepted", Facts: facts}}})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ratchet.accepted_checkpoints(tenant_id,digest,from_sequence,to_sequence,document,event_position) VALUES($1,$2,$3,$4,$5,$6)`, actor.TenantID, signed.CheckpointDigest.Bytes(), signed.FromSequence, signed.ToSequence, raw, receipt.LastSequence)
		record = CheckpointRecord{evidence, receipt.LastSequence}
		return err
	})
	return record, err
}

// Checkpoints uses the audit export privilege and a fixed ledger tip. Acceptance
// references lie beyond their covered events, so a checkpoint never hashes itself.
func (s *Service) Checkpoints(ctx context.Context, actor Actor, after, end int64, limit int) ([]CheckpointRecord, int64, error) {
	records := []CheckpointRecord{}
	if after < 0 || end < 0 || end > ledger.MaxSafeInteger || limit < 1 || limit > 51 {
		return nil, 0, domain.ErrInvalid
	}
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, _ time.Time) error {
		_, active, err := s.context(ctx, tx, actor, "audit_export", nil)
		if err != nil {
			return err
		}
		var head int64
		if err := tx.QueryRow(ctx, `SELECT sequence FROM ratchet.tenant_heads WHERE tenant_id=$1`, actor.TenantID).Scan(&head); err != nil {
			return err
		}
		if end == 0 {
			end = head
		}
		if after > end || end > head {
			return domain.ErrInvalid
		}
		rows, err := tx.Query(ctx, `SELECT document,event_position FROM ratchet.accepted_checkpoints WHERE tenant_id=$1 AND event_position>$2 AND event_position<=$3 ORDER BY event_position LIMIT $4`, actor.TenantID, after, end, limit)
		if err != nil {
			return err
		}
		type stored struct {
			raw      []byte
			position int64
		}
		pending := []stored{}
		for rows.Next() {
			var row stored
			if err := rows.Scan(&row.raw, &row.position); err != nil {
				rows.Close()
				return err
			}
			pending = append(pending, row)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, row := range pending {
			record, err := s.checkpointRecord(ctx, tx, actor.TenantID, row.raw, row.position, active.Root)
			if err != nil {
				return err
			}
			records = append(records, record)
		}
		return nil
	})
	return records, end, err
}
