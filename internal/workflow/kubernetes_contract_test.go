package workflow_test

import (
	"encoding/json"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestNativeExtensionPreservesLegacyDriftSigningBytes(t *testing.T) {
	report := &v1.DriftReport{TenantId: "tenant", ConnectorId: "source", DriftId: "drift", Envelope: &v1.ConnectorEnvelope{SchemaVersion: 1, TenantId: "tenant", ConnectorId: "source"}}
	inner, err := (protojson.MarshalOptions{UseProtoNames: true, EmitDefaultValues: true}).Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	// The legacy signed envelope has exactly these two fields. Constructing it
	// explicitly catches accidental new default-valued fields in its signing bytes.
	legacy, err := canon.New().Canonicalize(map[string]any{"report": json.RawMessage(inner), "signature": ""})
	if err != nil {
		t.Fatal(err)
	}
	want, err := canon.New().Digest(struct {
		Domain string `json:"domain"`
		Body   []byte `json:"canonical_proto_json"`
	}{"RATCHET_DRIFT_REPORT_V1", legacy})
	if err != nil {
		t.Fatal(err)
	}
	got, err := workflow.DriftSigningDigest(&v1.SignedDriftReport{Report: report, Signature: []byte("signature excluded")})
	if err != nil || got != want {
		t.Fatal("native extension changed existing simulator signature", got, want, err)
	}
}
