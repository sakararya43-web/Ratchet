package eventstore

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/eventstore/storedb"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

// ReplayGraph reconstructs authority facts from verified immutable events,
// without trusting the mutable graph-source projection or retained personal data.
func (s *Store) ReplayGraph(ctx context.Context, tenant string) (*graph.Snapshot, error) {
	if !token.MatchString(tenant) {
		return nil, ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := storedb.New(tx)
	if err := q.SetTenant(ctx, tenant); err != nil {
		return nil, err
	}
	sources := map[string]sourceGraph{}
	var position, version int64
	var previous ports.Digest
	for {
		rows, err := q.LoadTenantChain(ctx, storedb.LoadTenantChainParams{TenantID: tenant, Sequence: position, Limit: 200})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			event, err := decodeRow(s.digester, row)
			if err != nil {
				return nil, err
			}
			if event.Sequence != position+1 || event.Entry.Previous != previous {
				return nil, ErrIntegrity
			}
			position, previous = event.Sequence, event.Entry.Hash
			if event.Type != "SyncCompleted" && event.Type != "GraphResyncRequired" {
				continue
			}
			var content struct {
				Payload struct {
					Facts struct {
						ConnectorID string     `json:"connector_id"`
						Revision    int64      `json:"source_revision"`
						Data        graph.Data `json:"graph"`
					} `json:"facts"`
				} `json:"payload"`
			}
			if err := json.Unmarshal(event.Entry.Canonical, &content); err != nil {
				return nil, ErrIntegrity
			}
			facts := content.Payload.Facts
			if !token.MatchString(facts.ConnectorID) {
				return nil, ErrIntegrity
			}
			if event.Type == "SyncCompleted" {
				sources[facts.ConnectorID] = sourceGraph{id: facts.ConnectorID, revision: facts.Revision, version: position, data: facts.Data}
			} else {
				source := sources[facts.ConnectorID]
				source.id = facts.ConnectorID
				source.resync = true
				sources[facts.ConnectorID] = source
			}
			version = position
		}
		if len(rows) < 200 {
			break
		}
	}
	if version == 0 {
		return nil, graph.ErrUnavailable
	}
	all := []sourceGraph{}
	for _, source := range sources {
		if source.resync {
			return nil, ErrResyncRequired
		}
		all = append(all, source)
	}
	return mergeSources(version, all)
}
