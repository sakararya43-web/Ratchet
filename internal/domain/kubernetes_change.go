package domain

import (
	"encoding/hex"
	"strings"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

// KubernetesChange contains commitments and opaque references only. Actual API
// object names, subjects and userInfo belong in separately encrypted records.
type KubernetesChange struct {
	PlanID           string       `json:"plan_id"`
	PlanDigest       ports.Digest `json:"plan_digest"`
	MutationDigest   ports.Digest `json:"mutation_digest"`
	SourceDigest     ports.Digest `json:"source_digest"`
	SourceKey        string       `json:"source_key"`
	Connector        string       `json:"connector_id"`
	Operation        string       `json:"operation"`
	PrivateReference string       `json:"private_record_reference"`
	PrivateDigest    ports.Digest `json:"private_content_digest"`
}

func opaqueKubernetesKey(value, kind string) bool {
	prefix := "k8s:" + kind + ":"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == strings.TrimPrefix(value, prefix)
}

func (n KubernetesChange) Validate() error {
	id, err := uuid.Parse(n.PlanID)
	if err != nil || id == uuid.Nil || id.String() != n.PlanID || n.PlanDigest.IsZero() || n.MutationDigest.IsZero() || n.SourceDigest.IsZero() || !opaqueKubernetesKey(n.SourceKey, "source") || n.Connector == "" || len(n.Connector) > 128 || strings.ContainsAny(n.Connector, " \r\n\t\x00") {
		return ErrInvalid
	}
	ref, err := uuid.Parse(n.PrivateReference)
	if err != nil || ref == uuid.Nil || ref.String() != n.PrivateReference || n.PrivateDigest.IsZero() {
		return ErrInvalid
	}
	switch n.Operation {
	case "CREATE", "UPDATE", "DELETE":
		return nil
	default:
		return ErrInvalid
	}
}
