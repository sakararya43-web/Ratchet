package workflow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
)

func TestLargeNativePlanPreservesExactGraphsAndHistoricalSigningBytes(t *testing.T) {
	data := graph.Data{Nodes: []graph.Node{{ID: "actor", Type: "Human"}}}
	for i := 0; i < 1800; i++ {
		role, resource := fmt.Sprintf("role:%d", i), fmt.Sprintf("resource:%d", i)
		data.Nodes = append(data.Nodes, graph.Node{ID: role, Type: "Role"}, graph.Node{ID: resource, Type: "Resource", Tier: 2})
		data.Edges = append(data.Edges, graph.Edge{Source: "actor", Target: role, Kind: "ASSIGNED"}, graph.Edge{Source: role, Target: resource, Kind: "GRANTS", Action: "read"})
	}
	base, err := graph.Build(0, data)
	if err != nil {
		t.Fatal(err)
	}
	after, err := base.Overlay(0, graph.Delta{EdgesAdded: []graph.Edge{{ID: "additional-grant", Source: "role:0", Target: "resource:1", Kind: "GRANTS", Action: "write"}}})
	if err != nil {
		t.Fatal(err)
	}
	plan := KubernetesPlan{Version: 1, Tenant: "tenant", Current: base.Data(), Before: base.Data(), After: after.Data()}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"projection_bundle"`)) || len(raw) > 1<<20 {
		t.Fatal("large comparison graphs not compacted", len(raw))
	}
	var got KubernetesPlan
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.Current, got.Current) || !reflect.DeepEqual(plan.Before, got.Before) || !reflect.DeepEqual(plan.After, got.After) {
		t.Fatal("compact plan changed authority")
	}
	wantDigest, err := canon.New().Digest(plan)
	if err != nil {
		t.Fatal(err)
	}
	gotDigest, err := canon.New().Digest(got)
	if err != nil || wantDigest != gotDigest {
		t.Fatal("compact plan digest unstable after reload", err)
	}
	legacy, err := json.Marshal(nativePlanJSON(plan))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(legacy, &got); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.Marshal(got)
	if err != nil || !bytes.Equal(legacy, reencoded) {
		t.Fatal("historical native plan signing bytes changed", err)
	}
	var malformed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &malformed); err != nil {
		t.Fatal(err)
	}
	malformed["current_projection"], err = json.Marshal(plan.Current)
	if err != nil {
		t.Fatal(err)
	}
	mixed, err := json.Marshal(malformed)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(mixed, &got) == nil {
		t.Fatal("ambiguous compact and full projections accepted")
	}
	bundle, err := eventstore.EncodePublicGraphBundle([]graph.Data{plan.Current, plan.After})
	if err != nil {
		t.Fatal(err)
	}
	bundle[len(bundle)/2] ^= 1
	if _, err := eventstore.DecodePublicGraphBundle(bundle); err == nil {
		t.Fatal("corrupt compact authority accepted")
	}
}
