package eventstore

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/eventstore/storedb"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func (s *Store) StreamWithin(ctx context.Context, tx pgx.Tx, tenant, stream string) ([]StoredEvent, error) {
	rows, err := storedb.New(tx).LoadStream(ctx, storedb.LoadStreamParams{TenantID: tenant, StreamID: stream})
	if err != nil {
		return nil, err
	}
	events := make([]StoredEvent, 0, len(rows))
	for _, row := range rows {
		event, err := decodeRow(s.digester, row)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

// GraphAtWithin reconstructs public authority from a verified contiguous ledger
// prefix. Current mutable source rows and erased display data are not consulted.
func (s *Store) GraphAtWithin(ctx context.Context, tx pgx.Tx, tenant string, version int64) (*graph.Snapshot, error) {
	if version < 1 || version > ledger.MaxSafeInteger {
		return nil, ErrInvalid
	}
	sources := map[string]sourceGraph{}
	var sequence int64
	var previous ports.Digest
	var graphVersion int64
	for sequence < version {
		rows, err := storedb.New(tx).LoadTenantChain(ctx, storedb.LoadTenantChainParams{TenantID: tenant, Sequence: sequence, Limit: 200})
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			return nil, ErrIntegrity
		}
		for _, row := range rows {
			if row.Sequence > version {
				if sequence != version {
					return nil, ErrIntegrity
				}
				break
			}
			entry, err := decodeRow(s.digester, row)
			if err != nil {
				return nil, err
			}
			content, err := ledger.Verify(s.digester, entry.Entry, tenant, sequence+1, previous)
			if err != nil {
				return nil, ErrIntegrity
			}
			sequence = entry.Sequence
			previous = entry.Entry.Hash
			if entry.Type != "SyncCompleted" && entry.Type != "GraphResyncRequired" {
				continue
			}
			var payload struct {
				Facts struct {
					Connector string     `json:"connector_id"`
					Revision  int64      `json:"source_revision"`
					Graph     graph.Data `json:"graph"`
					Compact   []byte     `json:"graph_compact"`
				} `json:"facts"`
			}
			if json.Unmarshal(content.Payload, &payload) != nil || entry.StreamID != "graph:"+payload.Facts.Connector {
				return nil, ErrIntegrity
			}
			data, err := graphFromFacts(payload.Facts.Graph, payload.Facts.Compact)
			if err != nil {
				return nil, err
			}
			sources[payload.Facts.Connector] = sourceGraph{id: payload.Facts.Connector, revision: payload.Facts.Revision, version: entry.Sequence, data: data, resync: entry.Type == "GraphResyncRequired"}
			graphVersion = entry.Sequence
		}
	}
	if graphVersion != version {
		return nil, graph.ErrUnavailable
	}
	keys := []string{}
	for key, source := range sources {
		if source.resync {
			return nil, ErrResyncRequired
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ordered := []sourceGraph{}
	for _, key := range keys {
		ordered = append(ordered, sources[key])
	}
	return mergeSources(version, ordered)
}
