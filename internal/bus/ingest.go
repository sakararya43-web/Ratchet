package bus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/google/uuid"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var ErrAuthentication = errors.New("connector authentication failed")

type ConnectorKey struct {
	TenantID, ConnectorID string
	PublicKey             ed25519.PublicKey
}
type Ingestor struct {
	store    *eventstore.Store
	registry *graph.Registry
	digester ports.Digester
	key      []byte
	pins     map[string]ed25519.PublicKey
	mu       sync.Mutex
}

func NewIngestor(store *eventstore.Store, registry *graph.Registry, d ports.Digester, key []byte, pins []ConnectorKey) (*Ingestor, error) {
	if store == nil || registry == nil || d == nil || len(key) != 32 || len(pins) == 0 {
		return nil, eventstore.ErrInvalid
	}
	i := &Ingestor{store: store, registry: registry, digester: d, key: append([]byte(nil), key...), pins: map[string]ed25519.PublicKey{}}
	for _, pin := range pins {
		if !tenantToken.MatchString(pin.TenantID) || !tenantToken.MatchString(pin.ConnectorID) || len(pin.PublicKey) != ed25519.PublicKeySize {
			return nil, eventstore.ErrInvalid
		}
		id := pin.TenantID + ":" + pin.ConnectorID
		if _, exists := i.pins[id]; exists {
			return nil, eventstore.ErrInvalid
		}
		i.pins[id] = append(ed25519.PublicKey(nil), pin.PublicKey...)
	}
	return i, nil
}

// SyncSigningDigest domain-separates connector authentication from approvals.
// Canonicalization always comes from the real shared Digester.
func SyncSigningDigest(d ports.Digester, message *v1.SignedGraphSync) (ports.Digest, error) {
	if d == nil || message == nil {
		return ports.Digest{}, eventstore.ErrInvalid
	}
	copyMessage := proto.Clone(message).(*v1.SignedGraphSync)
	copyMessage.Signature = nil
	raw, err := (protojson.MarshalOptions{UseProtoNames: true, EmitDefaultValues: true}).Marshal(copyMessage)
	if err != nil {
		return ports.Digest{}, err
	}
	canonical, err := d.Canonicalize(raw)
	if err != nil {
		return ports.Digest{}, err
	}
	return d.Digest(struct {
		Domain string `json:"domain"`
		Body   []byte `json:"canonical_proto_json"`
	}{"RATCHET_GRAPH_SYNC_V1", canonical})
}

func (i *Ingestor) Handle(ctx context.Context, tenant string, raw []byte) error {
	if len(raw) > 1<<20 {
		return eventstore.ErrInvalid
	}
	message := new(v1.SignedGraphSync)
	if err := protojson.Unmarshal(raw, message); err != nil {
		return fmt.Errorf("%w: malformed sync", eventstore.ErrInvalid)
	}
	e := message.GetEnvelope()
	if e == nil || e.SchemaVersion != 1 || e.TenantId != tenant {
		return ErrAuthentication
	}
	key, known := i.pins[tenant+":"+e.ConnectorId]
	if !known {
		return ErrAuthentication
	}
	digest, err := SyncSigningDigest(i.digester, message)
	if err != nil || !ed25519.Verify(key, digest[:], message.Signature) {
		return ErrAuthentication
	}
	id, err := uuid.Parse(e.MessageId)
	if err != nil {
		return eventstore.ErrInvalid
	}
	if _, err := uuid.Parse(e.CorrelationId); err != nil {
		return eventstore.ErrInvalid
	}
	input := eventstore.GraphInput{TenantID: tenant, ConnectorID: e.ConnectorId, MessageID: id, CorrelationID: e.CorrelationId, WireDigest: digest.String()}
	if native := message.GetKubernetes(); native != nil {
		if native.TenantId != tenant || native.ConnectorId != e.ConnectorId || native.SourceRevision != e.SourceRevision || len(native.NormalizedStateJson) == 0 {
			return eventstore.ErrInvalid
		}
		var state kube.State
		decoder := json.NewDecoder(bytes.NewReader(native.NormalizedStateJson))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&state) != nil {
			return eventstore.ErrInvalid
		}
		if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
			return eventstore.ErrInvalid
		}
		compiled, err := graph.KubernetesSource(0, state)
		if err != nil {
			return err
		}
		data := compiled.Data()
		input.Snapshot = &data
		input.Complete = true
		input.ToRevision = native.SourceRevision
	} else if snapshot := message.GetSnapshot(); snapshot != nil {
		if snapshot.TenantId != tenant || snapshot.ConnectorId != e.ConnectorId || snapshot.SourceRevision != e.SourceRevision || !snapshot.Complete {
			return eventstore.ErrInvalid
		}
		if snapshot.Envelope != nil && !proto.Equal(snapshot.Envelope, e) {
			return ErrAuthentication
		}
		data := graph.Data{Nodes: []graph.Node{}, Edges: []graph.Edge{}}
		for _, n := range snapshot.Nodes {
			if n == nil {
				return eventstore.ErrInvalid
			}
			data.Nodes = append(data.Nodes, graphNode(n))
		}
		for _, edge := range snapshot.Edges {
			if edge == nil {
				return eventstore.ErrInvalid
			}
			data.Edges = append(data.Edges, graphEdge(edge))
		}
		input.Snapshot = &data
		input.Complete = true
		input.ToRevision = snapshot.SourceRevision
	} else if delta := message.GetDelta(); delta != nil {
		if delta.TenantId != tenant || delta.ConnectorId != e.ConnectorId || delta.ToRevision != e.SourceRevision {
			return ErrAuthentication
		}
		if delta.Envelope != nil && !proto.Equal(delta.Envelope, e) {
			return ErrAuthentication
		}
		d := graph.Delta{NodesRemoved: delta.NodesRemoved}
		for _, n := range delta.NodesAdded {
			if n == nil {
				return eventstore.ErrInvalid
			}
			d.NodesAdded = append(d.NodesAdded, graphNode(n))
		}
		for _, edge := range delta.EdgesAdded {
			if edge == nil {
				return eventstore.ErrInvalid
			}
			d.EdgesAdded = append(d.EdgesAdded, graphEdge(edge))
		}
		for _, edge := range delta.EdgesRemoved {
			if edge == nil {
				return eventstore.ErrInvalid
			}
			d.EdgesRemoved = append(d.EdgesRemoved, graph.EdgeID(graphEdge(edge)))
		}
		input.Delta = &d
		input.FromRevision = delta.FromRevision
		input.ToRevision = delta.ToRevision
	} else {
		return eventstore.ErrInvalid
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	_, err = i.store.IngestGraph(ctx, input, i.key)
	if err != nil {
		return err
	}
	err = i.refresh(ctx, tenant)
	if errors.Is(err, eventstore.ErrResyncRequired) || errors.Is(err, graph.ErrUnavailable) {
		return nil
	}
	return err
}

func (i *Ingestor) Refresh(ctx context.Context, tenant string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.refresh(ctx, tenant)
}
func (i *Ingestor) refresh(ctx context.Context, tenant string) error {
	s, err := i.store.CurrentGraph(ctx, tenant, i.key)
	if err != nil {
		i.registry.Invalidate(tenant)
		return err
	}
	if err := i.registry.Publish(tenant, s); err != nil {
		if errors.Is(err, graph.ErrInvalid) {
			return nil
		}
		return err
	}
	return nil
}
func graphNode(n *v1.GraphNode) graph.Node {
	return graph.Node{ID: n.Id, Type: n.Type, Tier: int(n.Tier), DisplayName: n.DisplayName, Properties: n.Properties}
}
func graphEdge(e *v1.GraphEdge) graph.Edge {
	return graph.Edge{Source: e.Source, Target: e.Target, Kind: e.Kind, Action: e.Action, Properties: e.Properties}
}
