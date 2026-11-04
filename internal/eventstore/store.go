// Package eventstore persists committed, tenant-ordered security evidence.
package eventstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/eventstore/storedb"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

var (
	ErrInvalid             = errors.New("invalid event command")
	ErrVersionConflict     = errors.New("stream version conflict")
	ErrIdempotencyConflict = errors.New("command ID reused for different intent")
	ErrIntegrity           = errors.New("stored evidence integrity failure")
	token                  = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
	streamToken            = regexp.MustCompile(`^[a-zA-Z0-9_:/-]{1,200}$`)
	eventToken             = regexp.MustCompile(`^[A-Z][a-zA-Z0-9_]{0,99}$`)
)

type Event struct {
	Type            string          `json:"type"`
	Action          string          `json:"action"`
	TargetReference string          `json:"target_reference"`
	Facts           json.RawMessage `json:"facts"`
	Private         *PrivateRecord  `json:"private,omitempty"`
}

// Command is an internal boundary. Callers supply server-authenticated references,
// never untrusted requested_by fields. Facts must be non-personal replay inputs.
type Command struct {
	TenantID        string    `json:"tenant_id"`
	ID              uuid.UUID `json:"command_id"`
	StreamID        string    `json:"stream_id"`
	ExpectedVersion int64     `json:"expected_version"`
	ActorReference  uuid.UUID `json:"actor_reference"`
	Events          []Event   `json:"events"`
}

type Receipt struct {
	FirstSequence int64 `json:"first_sequence"`
	LastSequence  int64 `json:"last_sequence"`
	StreamVersion int64 `json:"stream_version"`
	Duplicate     bool  `json:"duplicate"`
}

type StoredEvent struct {
	ID            uuid.UUID
	StreamID      string
	StreamVersion int64
	Sequence      int64
	Type          string
	RecordedAt    time.Time
	Entry         ledger.Entry
}

type Store struct {
	pool     *pgxpool.Pool
	digester ports.Digester
}

func New(pool *pgxpool.Pool, digester ports.Digester) (*Store, error) {
	if pool == nil || digester == nil {
		return nil, errors.New("database and real canonical digester are required")
	}
	return &Store{pool: pool, digester: digester}, nil
}

// Append serializes all streams of one tenant until commit. It never publishes
// directly to the bus; the outbox is inserted in the same transaction.
func (s *Store) Append(ctx context.Context, command Command) (Receipt, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Receipt{}, fmt.Errorf("begin append: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	receipt, err := s.appendTx(ctx, tx, command)
	if err != nil {
		return Receipt{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Receipt{}, fmt.Errorf("commit append (retry same command ID if outcome uncertain): %w", err)
	}
	return receipt, nil
}

func (s *Store) appendTx(ctx context.Context, tx pgx.Tx, command Command) (Receipt, error) {
	if err := validate(command); err != nil {
		return Receipt{}, err
	}
	fingerprint, err := s.digester.Digest(command)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: canonical command: %v", ErrInvalid, err)
	}
	q := storedb.New(tx)
	if err := q.SetTenant(ctx, command.TenantID); err != nil {
		return Receipt{}, err
	}
	if err := q.EnsureTenantHead(ctx, command.TenantID); err != nil {
		return Receipt{}, err
	}
	head, err := q.LockTenantHead(ctx, command.TenantID)
	if err != nil {
		return Receipt{}, err
	}
	id := pgUUID(command.ID)
	prior, err := q.FindCommand(ctx, storedb.FindCommandParams{TenantID: command.TenantID, CommandID: id})
	if err == nil {
		if string(prior.CommandDigest) != string(fingerprint[:]) {
			return Receipt{}, ErrIdempotencyConflict
		}
		return Receipt{FirstSequence: prior.FirstSequence, LastSequence: prior.LastSequence, StreamVersion: prior.StreamVersion, Duplicate: true}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Receipt{}, err
	}
	version, err := q.StreamVersion(ctx, storedb.StreamVersionParams{TenantID: command.TenantID, StreamID: command.StreamID})
	if err != nil {
		return Receipt{}, err
	}
	if version != command.ExpectedVersion {
		return Receipt{}, fmt.Errorf("%w: expected %d, actual %d", ErrVersionConflict, command.ExpectedVersion, version)
	}
	previous, err := ports.DigestFromBytes(head.Hash)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: chain head", ErrIntegrity)
	}
	if head.Sequence > ledger.MaxSafeInteger-int64(len(command.Events)) || version > ledger.MaxSafeInteger-int64(len(command.Events)) {
		return Receipt{}, fmt.Errorf("%w: sequence exceeds canonical integer range", ErrInvalid)
	}
	stamp, err := q.DatabaseTime(ctx)
	if err != nil {
		return Receipt{}, err
	}
	now := stamp.Time.UTC().Truncate(time.Microsecond)
	receipt := Receipt{FirstSequence: head.Sequence + 1, LastSequence: head.Sequence + int64(len(command.Events)), StreamVersion: version + int64(len(command.Events))}
	for i, event := range command.Events {
		seq, streamVersion := head.Sequence+int64(i)+1, version+int64(i)+1
		eventID := uuid.New()
		var privateID pgtype.UUID
		if event.Private != nil {
			privateID = pgUUID(event.Private.ID)
			if err := q.InsertPrivateRecord(ctx, storedb.InsertPrivateRecordParams{TenantID: command.TenantID, RecordID: privateID, KeyReference: event.Private.KeyReference, Ciphertext: event.Private.Ciphertext}); err != nil {
				return Receipt{}, fmt.Errorf("insert private record: %w", err)
			}
		}
		payload, err := json.Marshal(struct {
			FormatVersion    int             `json:"format_version"`
			EventID          string          `json:"event_id"`
			CommandID        string          `json:"command_id"`
			StreamID         string          `json:"stream_id"`
			StreamVersion    int64           `json:"stream_version"`
			Facts            json.RawMessage `json:"facts"`
			PrivateReference string          `json:"private_record_reference"`
		}{1, eventID.String(), command.ID.String(), command.StreamID, streamVersion, event.Facts, privateRef(event.Private)})
		if err != nil {
			return Receipt{}, err
		}
		entry, err := ledger.Build(s.digester, previous, ledger.Content{Action: event.Action, ActorID: command.ActorReference.String(), EventType: event.Type, Payload: payload, Sequence: seq, TargetIdentity: event.TargetReference, TenantID: command.TenantID, Timestamp: now.Format(time.RFC3339Nano)})
		if err != nil {
			return Receipt{}, err
		}
		if err := q.InsertEvent(ctx, storedb.InsertEventParams{TenantID: command.TenantID, Sequence: seq, EventID: pgUUID(eventID), CommandID: id, StreamID: command.StreamID, StreamVersion: streamVersion, EventType: event.Type, ActorReference: pgUUID(command.ActorReference), PrivateRecordID: privateID, CanonicalContent: entry.Canonical, PreviousHash: previous.Bytes(), Hash: entry.Hash.Bytes(), RecordedAt: pgtype.Timestamptz{Time: now, Valid: true}}); err != nil {
			return Receipt{}, fmt.Errorf("insert event: %w", err)
		}
		if err := q.InsertOutbox(ctx, storedb.InsertOutboxParams{TenantID: command.TenantID, EventID: pgUUID(eventID), Sequence: seq, Subject: "ratchet." + command.TenantID + ".changes.events", Payload: entry.Canonical, CreatedAt: pgtype.Timestamptz{Time: now, Valid: true}}); err != nil {
			return Receipt{}, fmt.Errorf("insert outbox: %w", err)
		}
		previous = entry.Hash
	}
	if err := q.SaveCommand(ctx, storedb.SaveCommandParams{TenantID: command.TenantID, CommandID: id, CommandDigest: fingerprint.Bytes(), StreamID: command.StreamID, FirstSequence: receipt.FirstSequence, LastSequence: receipt.LastSequence, StreamVersion: receipt.StreamVersion}); err != nil {
		return Receipt{}, err
	}
	if err := q.AdvanceTenantHead(ctx, storedb.AdvanceTenantHeadParams{TenantID: command.TenantID, Sequence: receipt.LastSequence, Hash: previous.Bytes()}); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func (s *Store) LoadStream(ctx context.Context, tenant, stream string) ([]StoredEvent, error) {
	if !token.MatchString(tenant) || stream == "" {
		return nil, ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := storedb.New(tx)
	if err := q.SetTenant(ctx, tenant); err != nil {
		return nil, err
	}
	rows, err := q.LoadStream(ctx, storedb.LoadStreamParams{TenantID: tenant, StreamID: stream})
	if err != nil {
		return nil, err
	}
	result := make([]StoredEvent, 0, len(rows))
	for i, row := range rows {
		entry, err := decodeRow(s.digester, row)
		if err != nil {
			return nil, err
		}
		if row.StreamVersion != int64(i)+1 {
			return nil, ErrIntegrity
		}
		result = append(result, entry)
	}
	return result, nil
}

// VerifyTenant walks a consistent database snapshot and checks its committed tip.
func (s *Store) VerifyTenant(ctx context.Context, tenant string) (int64, ports.Digest, error) {
	if !token.MatchString(tenant) {
		return 0, ports.Digest{}, ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return 0, ports.Digest{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := storedb.New(tx)
	if err := q.SetTenant(ctx, tenant); err != nil {
		return 0, ports.Digest{}, err
	}
	var sequence int64
	var previous ports.Digest
	for {
		rows, err := q.LoadTenantChain(ctx, storedb.LoadTenantChainParams{TenantID: tenant, Sequence: sequence, Limit: 200})
		if err != nil {
			return 0, ports.Digest{}, err
		}
		for _, row := range rows {
			entry, err := decodeRow(s.digester, row)
			if err != nil || row.Sequence != sequence+1 || entry.Entry.Previous != previous {
				return 0, ports.Digest{}, ErrIntegrity
			}
			sequence, previous = row.Sequence, entry.Entry.Hash
		}
		if len(rows) < 200 {
			break
		}
	}
	var headSeq int64
	var headHash []byte
	err = tx.QueryRow(ctx, "SELECT sequence, hash FROM ratchet.tenant_heads WHERE tenant_id=$1", tenant).Scan(&headSeq, &headHash)
	if errors.Is(err, pgx.ErrNoRows) && sequence == 0 {
		return 0, previous, nil
	}
	if err != nil {
		return 0, ports.Digest{}, err
	}
	if headSeq != sequence || string(headHash) != string(previous[:]) {
		return 0, ports.Digest{}, ErrIntegrity
	}
	return sequence, previous, nil
}

func (s *Store) DeletePrivateRecord(ctx context.Context, tenant string, id uuid.UUID) error {
	if !token.MatchString(tenant) || id == uuid.Nil {
		return ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := storedb.New(tx)
	if err := q.SetTenant(ctx, tenant); err != nil {
		return err
	}
	if err := q.DeletePrivateRecord(ctx, storedb.DeletePrivateRecordParams{TenantID: tenant, RecordID: pgUUID(id)}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func decodeRow(d ports.Digester, row storedb.RatchetEvent) (StoredEvent, error) {
	previous, err := ports.DigestFromBytes(row.PreviousHash)
	if err != nil {
		return StoredEvent{}, ErrIntegrity
	}
	hash, err := ports.DigestFromBytes(row.Hash)
	if err != nil {
		return StoredEvent{}, ErrIntegrity
	}
	entry := ledger.Entry{Canonical: row.CanonicalContent, Previous: previous, Hash: hash}
	content, err := ledger.Verify(d, entry, row.TenantID, row.Sequence, previous)
	if err != nil {
		return StoredEvent{}, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	var payload struct {
		EventID       string `json:"event_id"`
		CommandID     string `json:"command_id"`
		StreamID      string `json:"stream_id"`
		StreamVersion int64  `json:"stream_version"`
		FormatVersion int    `json:"format_version"`
		PrivateRef    string `json:"private_record_reference"`
	}
	if err := json.Unmarshal(content.Payload, &payload); err != nil {
		return StoredEvent{}, ErrIntegrity
	}
	privateReference := ""
	if row.PrivateRecordID.Valid {
		privateReference = uuid.UUID(row.PrivateRecordID.Bytes).String()
	}
	if payload.FormatVersion != 1 || payload.EventID != uuid.UUID(row.EventID.Bytes).String() || payload.CommandID != uuid.UUID(row.CommandID.Bytes).String() || payload.StreamID != row.StreamID || payload.StreamVersion != row.StreamVersion || payload.PrivateRef != privateReference || content.EventType != row.EventType || content.ActorID != uuid.UUID(row.ActorReference.Bytes).String() || content.Timestamp != row.RecordedAt.Time.UTC().Format(time.RFC3339Nano) {
		return StoredEvent{}, ErrIntegrity
	}
	return StoredEvent{ID: uuid.UUID(row.EventID.Bytes), StreamID: row.StreamID, StreamVersion: row.StreamVersion, Sequence: row.Sequence, Type: row.EventType, RecordedAt: row.RecordedAt.Time, Entry: entry}, nil
}

func validate(command Command) error {
	if !token.MatchString(command.TenantID) || command.ID == uuid.Nil || command.ActorReference == uuid.Nil || !streamToken.MatchString(command.StreamID) || command.ExpectedVersion < 0 || command.ExpectedVersion > ledger.MaxSafeInteger || len(command.Events) == 0 || len(command.Events) > 1000 {
		return ErrInvalid
	}
	for _, event := range command.Events {
		if !eventToken.MatchString(event.Type) || (event.Action != "" && !eventToken.MatchString(event.Action)) || (event.TargetReference != "" && !streamToken.MatchString(event.TargetReference)) || !json.Valid(event.Facts) || len(event.Facts) > 1<<20 {
			return ErrInvalid
		}
		var facts any
		decoder := json.NewDecoder(bytes.NewReader(event.Facts))
		decoder.UseNumber()
		if err := decoder.Decode(&facts); err != nil {
			return ErrInvalid
		}
		if _, ok := facts.(map[string]any); !ok {
			return ErrInvalid
		}
		if err := checkPrivateFields(facts); err != nil {
			return err
		}
		if event.Private != nil && (event.Private.ID == uuid.Nil || event.Private.KeyReference == "" || len(event.Private.Ciphertext) < 28 || len(event.Private.Ciphertext) > 1<<20) {
			return ErrInvalid
		}
	}
	return nil
}

// Defense against known accidental copies; callers still own schema-level data minimization.
func checkPrivateFields(v any) error {
	switch value := v.(type) {
	case map[string]any:
		for key, child := range value {
			switch strings.ToLower(key) {
			case "justification", "display_name", "email", "password", "private_key", "name":
				return fmt.Errorf("%w: personal field must use encrypted private record", ErrInvalid)
			}
			if err := checkPrivateFields(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := checkPrivateFields(child); err != nil {
				return err
			}
		}
	case json.Number:
		if !strings.ContainsAny(value.String(), ".eE") {
			n, err := strconv.ParseInt(value.String(), 10, 64)
			if err != nil || n > ledger.MaxSafeInteger || n < -ledger.MaxSafeInteger {
				return fmt.Errorf("%w: encode large integers as decimal strings", ErrInvalid)
			}
		} else {
			n, err := strconv.ParseFloat(value.String(), 64)
			if err != nil || n > float64(ledger.MaxSafeInteger) || n < -float64(ledger.MaxSafeInteger) {
				return fmt.Errorf("%w: fact number exceeds canonical range", ErrInvalid)
			}
		}
	}
	return nil
}

func pgUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }
func privateRef(record *PrivateRecord) string {
	if record == nil {
		return ""
	}
	return record.ID.String()
}
