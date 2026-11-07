package eventstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/eventstore/storedb"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

var ErrResyncRequired = errors.New("connector full resync required")

type GraphInput struct {
	TenantID      string       `json:"tenant_id"`
	ConnectorID   string       `json:"connector_id"`
	MessageID     uuid.UUID    `json:"message_id"`
	CorrelationID string       `json:"correlation_id"`
	WireDigest    string       `json:"wire_digest"`
	FromRevision  int64        `json:"from_revision"`
	ToRevision    int64        `json:"to_revision"`
	Complete      bool         `json:"complete"`
	Snapshot      *graph.Data  `json:"snapshot,omitempty"`
	Delta         *graph.Delta `json:"delta,omitempty"`
}
type GraphReceipt struct {
	Version     int64
	Duplicate   bool
	NeedsResync bool
}
type sourceGraph struct {
	id                string
	revision, version int64
	data              graph.Data
	resync            bool
}

func (s *Store) IngestGraph(ctx context.Context, input GraphInput, key []byte) (GraphReceipt, error) {
	if _, err := ports.DigestFromHex(input.WireDigest); err != nil {
		return GraphReceipt{}, ErrInvalid
	}
	if _, err := uuid.Parse(input.CorrelationID); err != nil {
		return GraphReceipt{}, ErrInvalid
	}
	if !token.MatchString(input.TenantID) || !token.MatchString(input.ConnectorID) || input.MessageID == uuid.Nil || input.ToRevision < 1 || input.ToRevision > 1<<53-1 || input.FromRevision < 0 || input.FromRevision > 1<<53-1 || len(key) != 32 || (input.Snapshot == nil) == (input.Delta == nil) || (input.Snapshot != nil && !input.Complete) {
		return GraphReceipt{}, ErrInvalid
	}
	digest, err := s.digester.Digest(input)
	if err != nil {
		return GraphReceipt{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return GraphReceipt{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := storedb.New(tx)
	if err := q.SetTenant(ctx, input.TenantID); err != nil {
		return GraphReceipt{}, err
	}
	if err := q.EnsureTenantHead(ctx, input.TenantID); err != nil {
		return GraphReceipt{}, err
	}
	if _, err := q.LockTenantHead(ctx, input.TenantID); err != nil {
		return GraphReceipt{}, err
	}
	var priorDigest []byte
	var priorVersion int64
	var outcome string
	err = tx.QueryRow(ctx, `SELECT input_digest,graph_version,outcome FROM ratchet.ingest_receipts WHERE tenant_id=$1 AND message_id=$2`, input.TenantID, input.MessageID).Scan(&priorDigest, &priorVersion, &outcome)
	if err == nil {
		if string(priorDigest) != string(digest[:]) {
			return GraphReceipt{}, ErrIdempotencyConflict
		}
		return GraphReceipt{Version: priorVersion, Duplicate: true, NeedsResync: outcome == "resync_required"}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return GraphReceipt{}, err
	}
	sources, err := loadSources(ctx, tx, input.TenantID, key)
	if err != nil {
		return GraphReceipt{}, err
	}
	idx := -1
	for i, source := range sources {
		if source.id == input.ConnectorID {
			idx = i
		}
	}
	current := sourceGraph{id: input.ConnectorID}
	if idx >= 0 {
		current = sources[idx]
	}
	gap := input.Delta != nil && (current.revision == 0 || current.resync || input.FromRevision != current.revision || input.ToRevision <= input.FromRevision)
	// Selected native sources publish complete normalized cuts. A generic edge
	// delta cannot leave an apparently current but stale RBAC preimage behind.
	if input.Delta != nil && len(current.data.KubernetesDigests) > 0 {
		gap = true
	}
	if input.ToRevision < current.revision {
		gap = true
	}
	var next *graph.Snapshot
	if !gap {
		if input.Snapshot != nil {
			next, err = graph.Build(0, *input.Snapshot)
		} else {
			var base *graph.Snapshot
			base, err = graph.Build(0, current.data)
			if err == nil {
				next, err = base.Overlay(0, *input.Delta)
			}
		}
		if err != nil {
			return GraphReceipt{}, err
		}
		if input.ToRevision == current.revision {
			oldHash, err := s.digester.Digest(publicGraph(current.data))
			if err != nil {
				return GraphReceipt{}, err
			}
			newHash, err := s.digester.Digest(publicGraph(next.Data()))
			if err != nil {
				return GraphReceipt{}, err
			}
			if oldHash != newHash {
				return GraphReceipt{}, ErrIdempotencyConflict
			}
			if !current.resync {
				if _, err := tx.Exec(ctx, `INSERT INTO ratchet.ingest_receipts(tenant_id,message_id,connector_id,input_digest,graph_version,outcome) VALUES($1,$2,$3,$4,$5,'applied')`, input.TenantID, input.MessageID, input.ConnectorID, digest.Bytes(), current.version); err != nil {
					return GraphReceipt{}, err
				}
				if err := tx.Commit(ctx); err != nil {
					return GraphReceipt{}, err
				}
				return GraphReceipt{Version: current.version, Duplicate: true}, nil
			}
		}
		candidate := sourceGraph{id: input.ConnectorID, revision: input.ToRevision, data: next.Data()}
		merged := slices.Clone(sources)
		if idx < 0 {
			merged = append(merged, candidate)
		} else {
			merged[idx] = candidate
		}
		if _, err := mergeSources(0, merged); err != nil {
			return GraphReceipt{}, err
		}
	}
	version, err := q.StreamVersion(ctx, storedb.StreamVersionParams{TenantID: input.TenantID, StreamID: "graph:" + input.ConnectorID})
	if err != nil {
		return GraphReceipt{}, err
	}
	facts := map[string]any{"connector_id": input.ConnectorID, "source_revision": input.ToRevision, "input_digest": digest.String(), "correlation_id": input.CorrelationID, "wire_digest": input.WireDigest}
	typ := "SyncCompleted"
	outcome = "applied"
	var private *PrivateRecord
	if gap {
		typ = "GraphResyncRequired"
		outcome = "resync_required"
		facts["expected_source_revision"] = current.revision
	} else {
		public := publicGraph(next.Data())
		if len(public.KubernetesDigests) > 0 {
			compact, err := encodeCompactGraph(public)
			if err != nil {
				return GraphReceipt{}, err
			}
			facts["graph_compact"] = compact
		} else {
			facts["graph"] = public
		}
		raw, err := encodePrivateGraph(next.Data())
		if err != nil {
			return GraphReceipt{}, err
		}
		sealed, err := SealPrivate(key, input.TenantID, uuid.New(), "graph-v1", raw)
		if err != nil {
			return GraphReceipt{}, err
		}
		private = &sealed
	}
	rawFacts, err := json.Marshal(facts)
	if err != nil {
		return GraphReceipt{}, err
	}
	r, err := s.appendTx(ctx, tx, Command{TenantID: input.TenantID, ID: input.MessageID, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(input.TenantID+":"+input.ConnectorID)), StreamID: "graph:" + input.ConnectorID, ExpectedVersion: version, Events: []Event{{Type: typ, Facts: rawFacts, Private: private}}})
	if err != nil {
		return GraphReceipt{}, fmt.Errorf("append native/source cut (%d fact bytes): %w", len(rawFacts), err)
	}
	if gap {
		// A pending source is a durable quarantine marker, never a ready empty graph.
		if _, err := tx.Exec(ctx, `INSERT INTO ratchet.graph_sources(tenant_id,connector_id,source_revision,graph_version,public_graph,needs_resync) VALUES($1,$2,0,$3,'{"nodes":[],"edges":[]}',true) ON CONFLICT(tenant_id,connector_id) DO UPDATE SET needs_resync=true,graph_version=excluded.graph_version`, input.TenantID, input.ConnectorID, r.LastSequence); err != nil {
			return GraphReceipt{}, err
		}
	} else {
		public, err := json.Marshal(publicGraph(next.Data()))
		if err != nil {
			return GraphReceipt{}, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ratchet.graph_sources(tenant_id,connector_id,source_revision,graph_version,public_graph,private_record_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,connector_id) DO UPDATE SET source_revision=excluded.source_revision,graph_version=excluded.graph_version,public_graph=excluded.public_graph,private_record_id=excluded.private_record_id,needs_resync=false`, input.TenantID, input.ConnectorID, input.ToRevision, r.LastSequence, public, private.ID)
		if err != nil {
			return GraphReceipt{}, err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO ratchet.ingest_receipts(tenant_id,message_id,connector_id,input_digest,graph_version,outcome) VALUES($1,$2,$3,$4,$5,$6)`, input.TenantID, input.MessageID, input.ConnectorID, digest.Bytes(), r.LastSequence, outcome); err != nil {
		return GraphReceipt{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return GraphReceipt{}, err
	}
	return GraphReceipt{Version: r.LastSequence, NeedsResync: gap}, nil
}

// CurrentGraph reads a consistent projection. Missing/deleted private display
// data does not remove the public authority facts needed for replay.
func (s *Store) CurrentGraph(ctx context.Context, tenant string, key []byte) (*graph.Snapshot, error) {
	if !token.MatchString(tenant) || len(key) != 32 {
		return nil, ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := storedb.New(tx).SetTenant(ctx, tenant); err != nil {
		return nil, err
	}
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
	return mergeSources(version, sources)
}

func loadSources(ctx context.Context, tx pgx.Tx, tenant string, key []byte) ([]sourceGraph, error) {
	// Authenticated private snapshots already contain the complete projection.
	// Avoid transferring and decoding the large redundant public JSON alongside
	// them; the public fallback is needed only after private-record erasure.
	rows, err := tx.Query(ctx, `SELECT s.connector_id,s.source_revision,s.graph_version,CASE WHEN p.record_id IS NULL THEN s.public_graph ELSE NULL::jsonb END,s.needs_resync,p.record_id,p.key_reference,p.ciphertext FROM ratchet.graph_sources s LEFT JOIN ratchet.private_records p ON p.tenant_id=s.tenant_id AND p.record_id=s.private_record_id WHERE s.tenant_id=$1 ORDER BY s.connector_id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []sourceGraph{}
	for rows.Next() {
		var source sourceGraph
		var raw []byte
		var id *uuid.UUID
		var keyRef *string
		var cipher []byte
		if err := rows.Scan(&source.id, &source.revision, &source.version, &raw, &source.resync, &id, &keyRef, &cipher); err != nil {
			return nil, err
		}
		if id != nil && keyRef != nil {
			raw, err = OpenPrivate(key, tenant, PrivateRecord{ID: *id, KeyReference: *keyRef, Ciphertext: cipher})
			if err != nil {
				return nil, fmt.Errorf("%w: graph private data authentication", ErrIntegrity)
			}
		}
		source.data, err = decodePrivateGraph(raw)
		if err != nil {
			return nil, ErrIntegrity
		}
		result = append(result, source)
	}
	return result, rows.Err()
}

func mergeSources(version int64, sources []sourceGraph) (*graph.Snapshot, error) {
	d := graph.Data{Nodes: []graph.Node{}, Edges: []graph.Edge{}}
	nodes := map[string]graph.Node{}
	edges := map[string]graph.Edge{}
	for _, source := range sources {
		for key, digest := range source.data.KubernetesDigests {
			if d.KubernetesDigests == nil {
				d.KubernetesDigests = map[string]string{}
			}
			if _, exists := d.KubernetesDigests[key]; exists {
				return nil, fmt.Errorf("%w: native cluster source ownership conflicts", graph.ErrInvalid)
			}
			d.KubernetesDigests[key] = digest
		}
		for key, state := range source.data.Kubernetes {
			if d.Kubernetes == nil {
				d.Kubernetes = map[string]kube.State{}
			}
			d.Kubernetes[key] = state
		}
		for _, n := range source.data.Nodes {
			if old, ok := nodes[n.ID]; ok {
				a, _ := json.Marshal(old)
				b, _ := json.Marshal(n)
				if string(a) != string(b) {
					return nil, fmt.Errorf("%w: conflicting node ownership", graph.ErrInvalid)
				}
			} else {
				nodes[n.ID] = n
				d.Nodes = append(d.Nodes, n)
			}
		}
		for _, e := range source.data.Edges {
			e.ID = graph.EdgeID(e)
			if old, ok := edges[e.ID]; ok {
				a, _ := json.Marshal(old)
				b, _ := json.Marshal(e)
				if string(a) != string(b) {
					return nil, fmt.Errorf("%w: conflicting edge ownership", graph.ErrInvalid)
				}
			} else {
				edges[e.ID] = e
				d.Edges = append(d.Edges, e)
			}
		}
	}
	return graph.Build(version, d)
}

func publicGraph(data graph.Data) graph.Data {
	out := graph.Data{Nodes: make([]graph.Node, len(data.Nodes)), Edges: make([]graph.Edge, len(data.Edges))}
	out.KubernetesDigests = maps.Clone(data.KubernetesDigests)
	for i, n := range data.Nodes {
		out.Nodes[i] = graph.Node{ID: n.ID, Type: n.Type, Tier: n.Tier}
		if disabled := n.Properties["disabled"]; disabled != "" {
			out.Nodes[i].Properties = map[string]string{"disabled": disabled}
		}
		if n.Type == "Safeguard" {
			for _, key := range []string{"guard_kind", "required_checks", "threshold_usd"} {
				if value, exists := n.Properties[key]; exists {
					if out.Nodes[i].Properties == nil {
						out.Nodes[i].Properties = map[string]string{}
					}
					out.Nodes[i].Properties[key] = value
				}
			}
		}
	}
	for i, e := range data.Edges {
		out.Edges[i] = graph.Edge{ID: graph.EdgeID(e), Source: e.Source, Target: e.Target, Kind: e.Kind, Action: e.Action}
		if by := e.Properties["granted_by"]; by != "" {
			out.Edges[i].Properties = map[string]string{"granted_by": by}
		}
	}
	return out
}
