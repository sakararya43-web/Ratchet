package eventstore

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/eventstore/storedb"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

type ChainPage struct {
	Events                      []StoredEvent
	After, End                  int64
	Previous, LastHash, EndHash ports.Digest
	AcceptedCheckpointDigest    ports.Digest
}

func (s *Store) hashAt(ctx context.Context, tx pgx.Tx, tenant string, sequence int64) (ports.Digest, error) {
	if sequence == 0 {
		return ports.Digest{}, nil
	}
	rows, err := storedb.New(tx).LoadTenantChain(ctx, storedb.LoadTenantChainParams{TenantID: tenant, Sequence: sequence - 1, Limit: 1})
	if err != nil {
		return ports.Digest{}, err
	}
	if len(rows) != 1 || rows[0].Sequence != sequence {
		return ports.Digest{}, ErrIntegrity
	}
	e, err := decodeRow(s.digester, rows[0])
	return e.Entry.Hash, err
}

// ExportWithin returns a bounded verified contiguous page. Callers authenticate
// the tenant and bind the captured range/anchors in their continuation cursor.
func (s *Store) ExportWithin(ctx context.Context, tx pgx.Tx, tenant string, after, end int64, limit int, expectedPrevious, expectedEnd *ports.Digest) (ChainPage, error) {
	var page ChainPage
	if after < 0 || end < 0 || after > ledger.MaxSafeInteger || end > ledger.MaxSafeInteger || limit < 1 || limit > 100 {
		return page, ErrInvalid
	}
	var head int64
	if err := tx.QueryRow(ctx, `SELECT sequence FROM ratchet.tenant_heads WHERE tenant_id=$1`, tenant).Scan(&head); err != nil {
		return page, err
	}
	if end == 0 {
		end = head
	}
	if end > head || after > end {
		return page, ErrInvalid
	}
	previous, err := s.hashAt(ctx, tx, tenant, after)
	if err != nil {
		return page, err
	}
	tip, err := s.hashAt(ctx, tx, tenant, end)
	if err != nil {
		return page, err
	}
	if (expectedPrevious != nil && *expectedPrevious != previous) || (expectedEnd != nil && *expectedEnd != tip) {
		return page, ErrIntegrity
	}
	page = ChainPage{Events: []StoredEvent{}, After: after, End: end, Previous: previous, LastHash: previous, EndHash: tip}
	if after == end {
		return page, nil
	}
	rows, err := storedb.New(tx).LoadTenantChain(ctx, storedb.LoadTenantChainParams{TenantID: tenant, Sequence: after, Limit: int32(limit)})
	if err != nil {
		return page, err
	}
	bytes := 0
	for _, row := range rows {
		if row.Sequence > end {
			break
		}
		entry, err := decodeRow(s.digester, row)
		if err != nil {
			return page, err
		}
		if bytes+len(entry.Entry.Canonical) > 4<<20 {
			break
		}
		if _, err := ledger.Verify(s.digester, entry.Entry, tenant, page.After+1, page.LastHash); err != nil {
			return page, ErrIntegrity
		}
		page.Events = append(page.Events, entry)
		page.After = entry.Sequence
		page.LastHash = entry.Entry.Hash
		bytes += len(entry.Entry.Canonical)
	}
	if len(page.Events) == 0 {
		return page, ErrIntegrity
	}
	if page.After == end && page.LastHash != tip {
		return page, ErrIntegrity
	}
	return page, nil
}
