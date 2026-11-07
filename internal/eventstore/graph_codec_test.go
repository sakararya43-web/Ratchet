package eventstore

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"reflect"
	"testing"

	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/graph"
)

func TestCompactGraphRoundTripAndLegacy(t *testing.T) {
	data := graph.Data{Nodes: []graph.Node{{ID: "a", Type: "Human"}, {ID: "b", Type: "Role"}, {ID: "c", Type: "Resource", Tier: 0}}, Edges: []graph.Edge{
		{Source: "a", Target: "b", Kind: "ASSIGNED"},
		{ID: "custom", Source: "b", Target: "c", Kind: "GRANTS", Action: "read", Properties: map[string]string{"granted_by": "opaque"}},
		{Source: "b", Target: "c", Kind: "GRANTS", Action: "write"},
	}}
	data.Edges[2].ID = graph.NativeEdgeID(data.Edges[2])
	snapshot, err := graph.Build(0, data)
	if err != nil {
		t.Fatal(err)
	}
	data = snapshot.Data()
	raw, err := encodeCompactGraph(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeCompactGraph(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(data, got) {
		t.Fatalf("authority facts changed: %#v", got)
	}
	second, err := encodeCompactGraph(data)
	if err != nil || !bytes.Equal(raw, second) {
		t.Fatal("compact encoding is not deterministic", err)
	}
	legacy, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err = decodePrivateGraph(legacy)
	if err != nil || !reflect.DeepEqual(data, got) {
		t.Fatal("legacy source incompatible", err)
	}
	if _, err := graphFromFacts(data, raw); err == nil {
		t.Fatal("ambiguous dual graph accepted")
	}
}

func TestNativeSourceStateChecksPrivateCommitmentAndLegacyEncoding(t *testing.T) {
	state := kube.State{Cluster: "cluster", ResourceVersion: "opaque-cut", Complete: true}
	key := graph.KubernetesSourceKey(state.Cluster)
	digest, err := graph.KubernetesStateDigest(state)
	if err != nil {
		t.Fatal(err)
	}
	data := graph.Data{Kubernetes: map[string]kube.State{key: state}, KubernetesDigests: map[string]string{key: digest}}
	compact, err := encodePrivateGraph(data)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{legacy, compact} {
		got, err := nativeSourceState(raw, key)
		if err != nil || !reflect.DeepEqual(state, got) {
			t.Fatal("private source state changed", err)
		}
		if _, err := nativeSourceState(raw, graph.KubernetesSourceKey("other")); err == nil {
			t.Fatal("source state crossed cluster boundary")
		}
	}
	data.KubernetesDigests[key] = "forged"
	for _, encode := range []func(graph.Data) ([]byte, error){encodePrivateGraph, func(d graph.Data) ([]byte, error) { return json.Marshal(d) }} {
		raw, err := encode(data)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nativeSourceState(raw, key); err == nil {
			t.Fatal("forged normalized source commitment accepted")
		}
	}
	for _, raw := range [][]byte{compact[:len(compact)-1], append(bytes.Clone(compact), 1), append(bytes.Clone(compact), compact[4:]...)} {
		if _, err := nativeSourceState(raw, key); err == nil {
			t.Fatal("truncated or concatenated private source accepted")
		}
	}
}

func TestCompactGraphRejectsCorruptionAndBounds(t *testing.T) {
	zip := func(s string) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		if _, err := w.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	valid := zip(`{"version":1,"nodes":[],"edges":[]}`)
	for _, raw := range [][]byte{nil, []byte("invalid"), valid[:len(valid)-1], append(bytes.Clone(valid), 1), append(bytes.Clone(valid), valid...), zip(`{"version":2,"nodes":[],"edges":[]}`), zip(`{"version":1,"nodes":[],"edges":[{"s":0,"t":0,"k":"ASSIGNED"}]}`), zip(`{"version":1,"nodes":[],"edges":[],"extra":true}`), bytes.Repeat([]byte{'x'}, maxGraphCompressed+1)} {
		if _, err := decodeCompactGraph(raw); err == nil {
			t.Fatal("malformed compact graph accepted")
		}
	}
	// A tiny compressed bomb must stop at the decompressed bound.
	if _, err := decodeCompactGraph(zip(string(bytes.Repeat([]byte{' '}, maxGraphPlain+1)))); err == nil {
		t.Fatal("decompression bound bypassed")
	}
}
