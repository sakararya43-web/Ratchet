package eventstore

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/eventstore/storedb"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

// WithTenantTx serializes authoritative graph, policy and workflow operations on
// the same tenant head. Transaction-local RLS and DB time are established first.
func (s *Store) WithTenantTx(ctx context.Context, tenant string, fn func(pgx.Tx, time.Time) error) error {
	if !token.MatchString(tenant) || fn == nil {
		return ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := storedb.New(tx)
	if err = q.SetTenant(ctx, tenant); err != nil {
		return err
	}
	if err = q.EnsureTenantHead(ctx, tenant); err != nil {
		return err
	}
	if _, err = q.LockTenantHead(ctx, tenant); err != nil {
		return err
	}
	stamp, err := q.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err = fn(tx, stamp.Time.UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) AppendWithin(ctx context.Context, tx pgx.Tx, command Command) (Receipt, error) {
	return s.appendTx(ctx, tx, command)
}
func (s *Store) GraphWithin(ctx context.Context, tx pgx.Tx, tenant string, key []byte) (*graph.Snapshot, error) {
	sources, err := loadSources(ctx, tx, tenant, key)
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, graph.ErrUnavailable
	}
	var version int64
	for _, source := range sources {
		if source.resync {
			return nil, ErrResyncRequired
		}
		version = max(version, source.version)
	}
	merged, err := mergeSources(version, sources)
	if err != nil {
		return nil, err
	}
	return graph.Build(version, publicGraph(merged.Data()))
}

// KubernetesSourceWithin exposes retained exact source facts only to an already
// authorized tenant transaction. GraphWithin deliberately returns public facts.
func (s *Store) KubernetesSourceWithin(ctx context.Context, tx pgx.Tx, tenant, connector, sourceKey string, key []byte) (kube.State, int64, error) {
	sources, err := loadSources(ctx, tx, tenant, key)
	if err != nil {
		return kube.State{}, 0, err
	}
	for _, source := range sources {
		if source.id != connector {
			continue
		}
		if source.resync {
			return kube.State{}, 0, ErrResyncRequired
		}
		state, ok := source.data.Kubernetes[sourceKey]
		if !ok {
			return kube.State{}, 0, graph.ErrUnavailable
		}
		copyState, err := state.Clone()
		return copyState, source.revision, err
	}
	return kube.State{}, 0, graph.ErrUnavailable
}

func (s *Store) PrivateWithin(ctx context.Context, tx pgx.Tx, tenant, reference string, key []byte) ([]byte, error) {
	var record PrivateRecord
	if err := tx.QueryRow(ctx, `SELECT record_id,key_reference,ciphertext FROM ratchet.private_records WHERE tenant_id=$1 AND record_id=$2::uuid`, tenant, reference).Scan(&record.ID, &record.KeyReference, &record.Ciphertext); err != nil {
		return nil, err
	}
	return OpenPrivate(key, tenant, record)
}
func (s *Store) ChangeWithin(ctx context.Context, tx pgx.Tx, tenant, id string) (domain.Change, error) {
	return s.ChangeAtWithin(ctx, tx, tenant, id, 0)
}
func (s *Store) ChangeAtWithin(ctx context.Context, tx pgx.Tx, tenant, id string, end int64) (domain.Change, error) {
	rows, err := storedb.New(tx).LoadStream(ctx, storedb.LoadStreamParams{TenantID: tenant, StreamID: "change:" + id})
	if err != nil {
		return domain.Change{}, err
	}
	events := []domain.Event{}
	for _, row := range rows {
		if end != 0 && row.Sequence > end {
			break
		}
		entry, err := decodeRow(s.digester, row)
		if err != nil {
			return domain.Change{}, err
		}
		var content struct {
			Payload struct {
				Facts json.RawMessage `json:"facts"`
			} `json:"payload"`
		}
		if err = json.Unmarshal(entry.Entry.Canonical, &content); err != nil {
			return domain.Change{}, ErrIntegrity
		}
		var event domain.Event
		if err = json.Unmarshal(content.Payload.Facts, &event); err != nil {
			return domain.Change{}, ErrIntegrity
		}
		if event.Type != entry.Type {
			return domain.Change{}, ErrIntegrity
		}
		events = append(events, event)
	}
	return domain.Replay(events)
}

type ChangeMutation struct {
	TenantID, ActorID, RequestID string
	ID                           uuid.UUID
	ExpectedRevision             int64
	InputDigest                  ports.Digest
	Private                      *PrivateRecord
	Additional                   func(pgx.Tx, Receipt) error
}

// MutateChange's callback writes River jobs or execution outbox rows using this
// exact transaction. The durable command receipt is checked before any callback.
func (s *Store) MutateChange(ctx context.Context, m ChangeMutation, fn func(pgx.Tx, time.Time, domain.Change) ([]domain.Event, error)) (domain.Change, error) {
	var result domain.Change
	err := s.WithTenantTx(ctx, m.TenantID, func(tx pgx.Tx, now time.Time) error {
		var err error
		result, err = s.MutateChangeWithin(ctx, tx, now, m, fn)
		return err
	})
	return result, err
}

// MutateChangeWithin joins an already locked tenant transaction. It preserves
// the same receipts, event validation, private data, projection and outbox rules.
func (s *Store) MutateChangeWithin(ctx context.Context, tx pgx.Tx, now time.Time, m ChangeMutation, fn func(pgx.Tx, time.Time, domain.Change) ([]domain.Event, error)) (domain.Change, error) {
	var result domain.Change
	if _, err := uuid.Parse(m.RequestID); err != nil || m.ID == uuid.Nil || m.ActorID == "" || m.InputDigest.IsZero() {
		return result, ErrInvalid
	}
	err := func() error {
		var prior []byte
		var document []byte
		var request string
		err := tx.QueryRow(ctx, `SELECT input_digest,document,request_id::text FROM ratchet.workflow_receipts WHERE tenant_id=$1 AND command_id=$2`, m.TenantID, m.ID).Scan(&prior, &document, &request)
		if err == nil {
			if string(prior) != string(m.InputDigest[:]) || request != m.RequestID {
				return ErrIdempotencyConflict
			}
			return json.Unmarshal(document, &result)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		current, err := s.ChangeWithin(ctx, tx, m.TenantID, m.RequestID)
		if err != nil {
			return err
		}
		if current.Revision != m.ExpectedRevision {
			return ErrVersionConflict
		}
		events, err := fn(tx, now, current)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return ErrInvalid
		}
		command := Command{TenantID: m.TenantID, ID: m.ID, StreamID: "change:" + m.RequestID, ExpectedVersion: current.Revision, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(m.TenantID+":"+m.ActorID))}
		for i, e := range events {
			raw, err := json.Marshal(e)
			if err != nil {
				return err
			}
			event := Event{Type: e.Type, Facts: raw}
			if i == 0 {
				event.Private = m.Private
			}
			command.Events = append(command.Events, event)
		}
		receipt, err := s.appendTx(ctx, tx, command)
		if err != nil {
			return err
		}
		if m.Additional != nil {
			if err := m.Additional(tx, receipt); err != nil {
				return err
			}
		}
		result = events[len(events)-1].Change
		document, err = json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ratchet.change_projection(tenant_id,request_id,event_position,state,updated_at,document) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,request_id) DO UPDATE SET event_position=excluded.event_position,state=excluded.state,updated_at=excluded.updated_at,document=excluded.document`, m.TenantID, m.RequestID, receipt.LastSequence, string(result.State), now, document)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ratchet.workflow_receipts(tenant_id,command_id,request_id,input_digest,document) VALUES($1,$2,$3,$4,$5)`, m.TenantID, m.ID, m.RequestID, m.InputDigest.Bytes(), document)
		return err
	}()
	return result, err
}
func (s *Store) ReadChange(ctx context.Context, tenant, id string) (domain.Change, error) {
	var c domain.Change
	err := s.WithTenantTx(ctx, tenant, func(tx pgx.Tx, _ time.Time) error {
		var err error
		c, err = s.ChangeWithin(ctx, tx, tenant, id)
		return err
	})
	if err == nil && c.ID == "" {
		err = pgx.ErrNoRows
	}
	return c, err
}
func (s *Store) ReadPrivate(ctx context.Context, tenant, reference string, key []byte) ([]byte, error) {
	var value []byte
	err := s.WithTenantTx(ctx, tenant, func(tx pgx.Tx, _ time.Time) error {
		var record PrivateRecord
		if err := tx.QueryRow(ctx, `SELECT record_id,key_reference,ciphertext FROM ratchet.private_records WHERE tenant_id=$1 AND record_id=$2::uuid`, tenant, reference).Scan(&record.ID, &record.KeyReference, &record.Ciphertext); err != nil {
			return err
		}
		var err error
		value, err = OpenPrivate(key, tenant, record)
		return err
	})
	return value, err
}
