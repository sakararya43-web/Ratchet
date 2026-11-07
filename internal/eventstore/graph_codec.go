package eventstore

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/graph"
)

// Compact graphs retain every authority fact. Endpoint dictionaries and derived
// edge identities avoid repeating long anonymous hashes thousands of times.
// Bounds apply both before compression and while decompressing untrusted input.
const (
	maxGraphPlain      = 64 << 20
	maxGraphCompressed = 700 << 10 // leaves room for base64 and ledger framing
)

type compactEdge struct {
	Source     uint32            `json:"s"`
	Target     uint32            `json:"t"`
	Kind       string            `json:"k"`
	Action     string            `json:"a,omitempty"`
	ID         string            `json:"id,omitempty"`
	Native     bool              `json:"n,omitempty"`
	Properties map[string]string `json:"p,omitempty"`
}

type compactGraph struct {
	Version    int                   `json:"version"`
	Nodes      []graph.Node          `json:"nodes"`
	Edges      []compactEdge         `json:"edges"`
	Kubernetes map[string]kube.State `json:"kubernetes,omitempty"`
	Digests    map[string]string     `json:"kubernetes_digests,omitempty"`
}

func encodeCompactGraph(data graph.Data) ([]byte, error) {
	c := compactGraph{Version: 1, Nodes: data.Nodes, Digests: data.KubernetesDigests, Kubernetes: data.Kubernetes, Edges: make([]compactEdge, len(data.Edges))}
	index := make(map[string]uint32, len(data.Nodes))
	for i, node := range data.Nodes {
		if _, exists := index[node.ID]; exists {
			return nil, ErrInvalid
		}
		index[node.ID] = uint32(i)
	}
	for i, edge := range data.Edges {
		s, sok := index[edge.Source]
		t, tok := index[edge.Target]
		if !sok || !tok {
			return nil, ErrInvalid
		}
		e := compactEdge{Source: s, Target: t, Kind: edge.Kind, Action: edge.Action, Properties: edge.Properties}
		actual := graph.EdgeID(edge)
		if actual == graph.NativeEdgeID(edge) {
			e.Native = true
		} else {
			derived := edge
			derived.ID = ""
			if actual != graph.EdgeID(derived) {
				e.ID = actual
			}
		}
		c.Edges[i] = e
	}
	// Storage order follows adjacency rather than hashed edge IDs, improving
	// compression without changing any edge. Decode restores graph's canonical
	// ID order before hashing or replaying projections.
	slices.SortFunc(c.Edges, func(a, b compactEdge) int {
		if n := cmp.Compare(a.Source, b.Source); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Target, b.Target); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Kind, b.Kind); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Action, b.Action); n != 0 {
			return n
		}
		if n := cmp.Compare(a.ID, b.ID); n != 0 {
			return n
		}
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return bytes.Compare(x, y)
	})
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxGraphPlain {
		return nil, fmt.Errorf("%w: native graph plaintext exceeds %d bytes", ErrInvalid, maxGraphPlain)
	}
	var buffer bytes.Buffer
	w := gzip.NewWriter(&buffer)
	if _, err := w.Write(raw); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if buffer.Len() > maxGraphCompressed {
		return nil, fmt.Errorf("%w: compact graph is %d bytes, limit %d", ErrInvalid, buffer.Len(), maxGraphCompressed)
	}
	return buffer.Bytes(), nil
}

func decodeCompactGraph(raw []byte) (graph.Data, error) {
	if len(raw) == 0 || len(raw) > maxGraphCompressed {
		return graph.Data{}, ErrIntegrity
	}
	reader := bytes.NewReader(raw)
	r, err := gzip.NewReader(reader)
	if err != nil {
		return graph.Data{}, ErrIntegrity
	}
	r.Multistream(false)
	plain, err := io.ReadAll(io.LimitReader(r, maxGraphPlain+1))
	closeErr := r.Close()
	if err != nil || closeErr != nil || len(plain) > maxGraphPlain || reader.Len() != 0 {
		return graph.Data{}, ErrIntegrity
	}
	var c compactGraph
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF || c.Version != 1 || len(c.Nodes) > 2_000_000 || len(c.Edges) > 20_000_000 {
		return graph.Data{}, ErrIntegrity
	}
	out := graph.Data{Nodes: c.Nodes, Edges: make([]graph.Edge, len(c.Edges)), Kubernetes: c.Kubernetes, KubernetesDigests: c.Digests}
	for i, e := range c.Edges {
		if uint64(e.Source) >= uint64(len(c.Nodes)) || uint64(e.Target) >= uint64(len(c.Nodes)) || e.Native && e.ID != "" {
			return graph.Data{}, ErrIntegrity
		}
		edge := graph.Edge{ID: e.ID, Source: c.Nodes[e.Source].ID, Target: c.Nodes[e.Target].ID, Kind: e.Kind, Action: e.Action, Properties: e.Properties}
		if e.Native {
			edge.ID = graph.NativeEdgeID(edge)
		} else {
			edge.ID = graph.EdgeID(edge)
		}
		out.Edges[i] = edge
	}
	snapshot, err := graph.Build(0, out)
	if err != nil {
		return graph.Data{}, ErrIntegrity
	}
	return snapshot.Data(), nil
}

func encodePrivateGraph(data graph.Data) ([]byte, error) {
	if len(data.KubernetesDigests) == 0 {
		return json.Marshal(data)
	}
	raw, err := encodeCompactGraph(data)
	if err != nil {
		return nil, err
	}
	return append([]byte("RGZ1"), raw...), nil
}

func decodePrivateGraph(raw []byte) (graph.Data, error) {
	if bytes.HasPrefix(raw, []byte("RGZ1")) {
		return decodeCompactGraph(raw[4:])
	}
	var data graph.Data
	if err := json.Unmarshal(raw, &data); err != nil {
		return graph.Data{}, ErrIntegrity
	}
	return data, nil
}

func graphFromFacts(legacy graph.Data, compact []byte) (graph.Data, error) {
	if compact == nil {
		return legacy, nil
	}
	if len(legacy.Nodes) != 0 || len(legacy.Edges) != 0 || len(legacy.KubernetesDigests) != 0 || len(legacy.Kubernetes) != 0 {
		return graph.Data{}, ErrIntegrity
	}
	data, err := decodeCompactGraph(compact)
	// Private source material must never be accepted in immutable public facts.
	if err != nil || len(data.Kubernetes) != 0 {
		return graph.Data{}, ErrIntegrity
	}
	return data, nil
}

// Native admission needs the authenticated complete source state, not another
// reconstruction of its already-compiled authority graph. Ignore graph arrays
// while decoding, but verify the exact normalized state commitment and bounds.
func nativeSourceState(raw []byte, sourceKey string) (kube.State, error) {
	compact := bytes.HasPrefix(raw, []byte("RGZ1"))
	if compact {
		if len(raw)-4 > maxGraphCompressed {
			return kube.State{}, ErrIntegrity
		}
		input := bytes.NewReader(raw[4:])
		r, err := gzip.NewReader(input)
		if err != nil {
			return kube.State{}, ErrIntegrity
		}
		r.Multistream(false)
		plain, err := io.ReadAll(io.LimitReader(r, maxGraphPlain+1))
		closeErr := r.Close()
		if err != nil || closeErr != nil || len(plain) > maxGraphPlain || input.Len() != 0 {
			return kube.State{}, ErrIntegrity
		}
		raw = plain
	}
	if len(raw) > maxGraphPlain {
		return kube.State{}, ErrIntegrity
	}
	var wire struct {
		Version int                   `json:"version"`
		States  map[string]kube.State `json:"kubernetes"`
		Digests map[string]string     `json:"kubernetes_digests"`
	}
	if json.Unmarshal(raw, &wire) != nil || compact && wire.Version != 1 {
		return kube.State{}, ErrIntegrity
	}
	state, ok := wire.States[sourceKey]
	if !ok {
		return kube.State{}, graph.ErrUnavailable
	}
	digest, err := graph.KubernetesStateDigest(state)
	if err != nil || sourceKey != graph.KubernetesSourceKey(state.Cluster) || wire.Digests[sourceKey] != digest {
		return kube.State{}, ErrIntegrity
	}
	return state, nil
}
