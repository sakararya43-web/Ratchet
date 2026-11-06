package k8s

import (
	"context"
	"crypto/ed25519"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func (a *K8sAdapter) SignedSnapshot(ctx context.Context, key ed25519.PrivateKey) (*v1.SignedGraphSync, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, kube.ErrInvalid
	}
	state, revision, err := a.NativeSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(a.config.Tenant+":"+a.config.Connector+":"+state.ResourceVersion)).String()
	message := &v1.SignedGraphSync{Envelope: &v1.ConnectorEnvelope{SchemaVersion: 1, TenantId: a.config.Tenant, ConnectorId: a.config.Connector, MessageId: id, CorrelationId: id, SourceRevision: revision}, Payload: &v1.SignedGraphSync_Kubernetes{Kubernetes: &v1.NormalizedKubernetesSnapshot{TenantId: a.config.Tenant, ConnectorId: a.config.Connector, SourceRevision: revision, NormalizedStateJson: raw}}}
	digest, err := bus.SyncSigningDigest(canon.New(), message)
	if err != nil {
		return nil, err
	}
	message.Signature = ed25519.Sign(key, digest[:])
	return message, nil
}

// PublishDrift authenticates a real watch/read-back observation against the
// connector's configured scope. Core verifies its committed baseline, complete
// current cut and exact transition; this publication never authorizes a write.
func (a *K8sAdapter) PublishDrift(ctx context.Context, report workflow.SignedKubernetesDrift, key ed25519.PrivateKey, publish func(context.Context, string, string, []byte) error) error {
	if len(key) != ed25519.PrivateKeySize || publish == nil || report.Tenant != a.config.Tenant || report.Connector != a.config.Connector || report.Cluster != a.config.Cluster || report.Before.ValidateObserved() != nil || report.Mutation.Validate() != nil || report.BaselineGraphVersion < 1 || report.SourceRevision < 1 {
		return kube.ErrInvalid
	}
	report.Signature = nil
	digest, err := workflow.KubernetesDriftSigningDigest(report)
	if err != nil {
		return err
	}
	report.Signature = ed25519.Sign(key, digest[:])
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	wrapped, err := protojson.Marshal(&v1.SignedKubernetesDriftReport{SignedKubernetesDriftJson: raw})
	if err != nil {
		return err
	}
	return publish(ctx, "ratchet."+a.config.Tenant+".drift.reports", report.DriftID, wrapped)
}

func (a *K8sAdapter) PublishSnapshot(ctx context.Context, key ed25519.PrivateKey, publish func(context.Context, string, string, []byte) error) error {
	message, err := a.SignedSnapshot(ctx, key)
	if err != nil {
		return err
	}
	raw, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(message)
	if err != nil {
		return err
	}
	return publish(ctx, "ratchet."+a.config.Tenant+".ingest.sync", message.Envelope.MessageId, raw)
}
